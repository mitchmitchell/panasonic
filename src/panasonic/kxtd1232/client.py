"""Blocking client over a Transport (prototype PA option (a))."""

from __future__ import annotations

import time
from collections.abc import Callable

from .frame import (
    Encoder,
    FrameError,
    Reply,
    ReplyKind,
    ReplyMismatchError,
    classify,
    frame_length,
)
from .session import Login, LoginError, State
from .transport import Transport

DEFAULT_TIMEOUT = 5.0
READ_BLOCK_BYTES = 150  # DSHSOMT reads 0x24 in 150-byte blocks
# Observed busy run: ~128 ms cadence for ~7 s (live-capture §6). 12 s = 7 s plus margin.
BUSY_LIMIT_S = 12.0
MAX_STALE_FRAMES = 4
QUIET_S = 0.05  # after a reply, any further frame inside this window is an error
MAX_DRAIN_READS = 64


class ProtocolError(RuntimeError):
    def __init__(self, msg: str, reply: Reply | None = None) -> None:
        super().__init__(msg)
        self.reply = reply


class LinkTimeoutError(ProtocolError, TimeoutError):
    """No bytes arrived from the transport within the timeout."""


class RecordDecodeError(ProtocolError):
    """A record read from the PBX did not decode with the expected field layout."""


class WriteRejectedError(ProtocolError):
    """The PBX answered a write with a NAK or refusal: nothing was applied (per spec)."""


class BusyTimeoutError(ProtocolError):
    """The busy run outlasted the bound: treat as a link failure."""


class UnackedWriteError(ProtocolError):
    """A write got no valid ack (timeout, busy past the bound, garbled or mismatched ack).
    Never resend: re-read and use :meth:`Client.verify_block` to decide continue / rollback /
    LOCKED."""

    def __init__(self, msg: str, table: int, record: int, word: int, payload: bytes) -> None:
        super().__init__(msg)
        self.table, self.record, self.word, self.payload = table, record, word, payload


class Client:
    def __init__(
        self,
        transport: Transport,
        encoder: Encoder | None = None,
        busy_limit: float = BUSY_LIMIT_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.t = transport
        self.enc = encoder or Encoder()
        self.busy_limit = busy_limit
        self.clock = clock
        self._rx = b""

    # -- login ----------------------------------------------------------------
    def login(self, password: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        sm = Login(password)
        while sm.state not in (State.BINARY, State.FAILED):
            out = sm.feed(self._recv(timeout))
            if out:
                self.t.send(out)
        if sm.state is State.FAILED:
            raise LoginError(sm.failure or "login failed")
        self._rx = sm.leftover

    def _recv(self, timeout: float) -> bytes:
        try:
            return self.t.recv(timeout)
        except TimeoutError as e:
            raise LinkTimeoutError(f"no data within {timeout} s") from e

    # -- frames ---------------------------------------------------------------
    def _recv_frame(self, timeout: float) -> bytes:
        while True:
            n = frame_length(self._rx)
            if n is not None and len(self._rx) >= n:
                raw, self._rx = self._rx[:n], self._rx[n:]
                return raw
            self._rx += self._recv(timeout)

    def request(self, raw: bytes, timeout: float = DEFAULT_TIMEOUT) -> Reply:
        """Send once and return the reply. Busy frames are waited out, never answered with a
        resend (design §3), for at most ``busy_limit`` seconds (BusyTimeoutError)."""
        self._drain()
        self.t.send(raw)
        try:
            reply = self._await_reply(raw[1], timeout)
            self._expect_quiet()
            return reply
        except (TimeoutError, ProtocolError):
            # Drop leftover busy or partial bytes so a following re-read (verify_block)
            # starts on a clean frame boundary.
            self._rx = b""
            raise

    def _drain(self) -> None:
        """Discard anything already waiting, so a stale frame is never read as this reply."""
        self._rx = b""
        for _ in range(MAX_DRAIN_READS):
            try:
                if not self.t.recv(0):
                    return
            except TimeoutError:
                return
        raise ProtocolError("link will not go quiet before send")

    def _expect_quiet(self) -> None:
        """A second frame right after the reply means we may have taken a stale frame with
        the same command as the answer, so the reply cannot be trusted."""
        extra = self._rx
        if not extra:
            try:
                extra = self.t.recv(QUIET_S)
            except TimeoutError:
                return
        if extra:
            raise ProtocolError(f"unexpected extra bytes after reply: {extra[:8].hex()}")

    def _await_reply(self, request_cmd: int, timeout: float) -> Reply:
        busy_since: float | None = None
        stale = 0
        while True:
            try:
                reply = classify(self._recv_frame(timeout), request_cmd)
            except ReplyMismatchError as e:
                # A stale/out-of-order frame is skipped, never taken as the answer.
                stale += 1
                if stale > MAX_STALE_FRAMES:
                    raise ProtocolError(f"too many mismatched replies: {e}") from e
                continue
            except FrameError as e:
                raise ProtocolError(f"bad reply: {e}") from e
            if reply.kind != ReplyKind.BUSY:
                return reply
            now = self.clock()
            busy_since = now if busy_since is None else busy_since
            if now - busy_since > self.busy_limit:
                raise BusyTimeoutError(f"busy run longer than {self.busy_limit} s")

    def version(self) -> str:
        r = self.request(self.enc.version_probe())
        if r.kind != ReplyKind.DATA or len(r.data) != 16:
            raise ProtocolError("unexpected version reply", r)
        return r.data.decode("ascii", "replace")

    def read(self, table: int, record: int, word: int, nwords: int) -> bytes:
        r = self.request(self.enc.read(table, record, word, nwords))
        if r.kind != ReplyKind.DATA or len(r.data) != 2 * nwords:
            raise ProtocolError(f"read failed ({r.kind})", r)
        return r.data

    def read_records(self, table: int, record_size: int, first: int, count: int) -> bytes:
        if record_size % 2:
            raise ValueError("record size must be whole words")
        per_block = max(1, READ_BLOCK_BYTES // record_size)
        out = bytearray()
        rec = first
        while rec < first + count:
            n = min(per_block, first + count - rec)
            out += self.read(table, rec, 0, n * record_size // 2)
            rec += n
        return bytes(out)

    def write(self, table: int, record: int, word: int, payload: bytes) -> Reply:
        """One write frame, never resent. Returns the ack. Raises UnackedWriteError when no
        valid ack arrived (re-read with verify_block) and WriteRejectedError on a NAK."""
        raw = self.enc.write(table, record, word, payload)
        try:
            r = self.request(raw)
        except (TimeoutError, ProtocolError) as e:
            raise UnackedWriteError(f"write not acked: {e}", table, record, word, payload) from e
        if r.kind != ReplyKind.ACK:
            raise WriteRejectedError(f"write rejected ({r.kind}, code {r.code})", r)
        return r

    def verify_block(self, table: int, record: int, word: int, new: bytes, base: bytes) -> str:
        """Re-read a block after an unacked write: "applied", "not_applied" or "neither"."""
        got = self.read(table, record, word, len(new) // 2)
        if got == new:
            return "applied"
        return "not_applied" if got == base else "neither"

    def end_binary(self) -> None:
        r = self.request(self.enc.end_binary())
        if r.kind != ReplyKind.ACK:
            raise ProtocolError("end-binary not acked", r)
