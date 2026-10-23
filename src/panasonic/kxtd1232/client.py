"""Blocking client over a Transport (prototype PA option (a))."""

from __future__ import annotations

from .frame import Encoder, FrameError, Reply, classify, frame_length
from .session import Login, LoginError, State
from .transport import Transport

DEFAULT_TIMEOUT = 5.0
READ_BLOCK_BYTES = 150  # DSHSOMT reads 0x24 in 150-byte blocks


class ProtocolError(RuntimeError):
    def __init__(self, msg: str, reply: Reply | None = None) -> None:
        super().__init__(msg)
        self.reply = reply


class Client:
    def __init__(self, transport: Transport, encoder: Encoder | None = None) -> None:
        self.t = transport
        self.enc = encoder or Encoder()
        self._rx = b""

    # -- login ----------------------------------------------------------------
    def login(self, password: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        sm = Login(password)
        while sm.state not in (State.BINARY, State.FAILED):
            out = sm.feed(self.t.recv(timeout))
            if out:
                self.t.send(out)
        if sm.state is State.FAILED:
            raise LoginError(sm.failure or "login failed")

    # -- frames ---------------------------------------------------------------
    def _recv_frame(self, timeout: float) -> bytes:
        while True:
            n = frame_length(self._rx)
            if n is not None and len(self._rx) >= n:
                raw, self._rx = self._rx[:n], self._rx[n:]
                return raw
            self._rx += self.t.recv(timeout)

    def request(self, raw: bytes, timeout: float = DEFAULT_TIMEOUT) -> Reply:
        """Send once and return the reply. Busy frames are waited out, never answered with a
        resend (design §3); bounding the busy run is A2."""
        self.t.send(raw)
        while True:
            try:
                reply = classify(self._recv_frame(timeout), raw[1])
            except FrameError as e:
                raise ProtocolError(f"bad reply: {e}") from e
            if reply.kind != "busy":
                return reply

    def version(self) -> str:
        r = self.request(self.enc.version_probe())
        if r.kind != "data" or len(r.data) != 16:
            raise ProtocolError("unexpected version reply", r)
        return r.data.decode("ascii", "replace")

    def read(self, table: int, record: int, word: int, nwords: int) -> bytes:
        r = self.request(self.enc.read(table, record, word, nwords))
        if r.kind != "data" or len(r.data) != 2 * nwords:
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
        """One write frame. Never resent here; callers verify by re-reading."""
        return self.request(self.enc.write(table, record, word, payload))

    def end_binary(self) -> None:
        r = self.request(self.enc.end_binary())
        if r.kind != "ack":
            raise ProtocolError("end-binary not acked", r)
