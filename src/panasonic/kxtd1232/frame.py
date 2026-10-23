"""Binary frame codec: ``[LEN][CMD][...][SUM]``.

LEN counts itself and every byte up to (not including) SUM. SUM is the 8-bit sum of all
preceding bytes. No escaping; one reply per request; same rule in both directions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

MAX_WRITE_PAYLOAD = 200


class Cmd(IntEnum):
    WRITE = 0x00
    READ = 0x01
    CLOCK = 0x03
    PROBE = 0x08
    END_UPLOAD_A = 0x0A  # meaning UNKNOWN (G3); full upload only
    END_BINARY = 0x0B
    END_UPLOAD_B = 0x10  # meaning UNKNOWN (G3); full upload only


READ_ONLY_COMMANDS = frozenset({Cmd.READ, Cmd.CLOCK, Cmd.PROBE, Cmd.END_BINARY})
WRITE_COMMANDS = frozenset({Cmd.WRITE})
# 0x0A/0x10 are never allowed until G3 is closed.


class FrameError(ValueError):
    pass


class NotAllowedError(PermissionError):
    pass


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def encode(cmd: int, body: bytes = b"") -> bytes:
    length = 2 + len(body)
    if length > 0xFF:
        raise FrameError(f"frame too long: {length}")
    head = bytes([length, cmd]) + body
    return head + bytes([checksum(head)])


@dataclass(frozen=True)
class Frame:
    cmd: int
    body: bytes

    @property
    def raw(self) -> bytes:
        return encode(self.cmd, self.body)


def frame_length(buf: bytes) -> int | None:
    """Total length of the frame at the start of ``buf`` (LEN + 1), or None if empty."""
    if not buf:
        return None
    if buf[0] < 2:
        raise FrameError(f"invalid LEN byte {buf[0]:#04x}")
    return buf[0] + 1


def decode(raw: bytes) -> Frame:
    n = frame_length(raw)
    if n is None or len(raw) != n:
        raise FrameError(f"length mismatch: LEN says {n}, got {len(raw)}")
    if checksum(raw[:-1]) != raw[-1]:
        raise FrameError("bad checksum")
    return Frame(raw[1], bytes(raw[2:-1]))


class Encoder:
    """Builds request frames, enforcing a command allow-list (read-only by default)."""

    def __init__(self, allowed: frozenset[int] = READ_ONLY_COMMANDS) -> None:
        self.allowed = allowed

    def _check(self, cmd: int) -> None:
        if cmd not in self.allowed:
            raise NotAllowedError(f"command {cmd:#04x} not in allow-list")

    def version_probe(self) -> bytes:
        self._check(Cmd.PROBE)
        return encode(Cmd.PROBE, b"\x00")

    def status_probe(self) -> bytes:
        self._check(Cmd.PROBE)
        return encode(Cmd.PROBE, b"\x01")

    def clock(self) -> bytes:
        self._check(Cmd.CLOCK)
        return encode(Cmd.CLOCK)

    def end_binary(self) -> bytes:
        self._check(Cmd.END_BINARY)
        return encode(Cmd.END_BINARY)

    def read(self, table: int, record: int, word: int, nwords: int) -> bytes:
        self._check(Cmd.READ)
        if not (0 <= table <= 0xFF and 0 <= record <= 0xFFFF and 0 <= word <= 0xFFFF):
            raise FrameError("read address out of range")
        if not 1 <= nwords <= 0xFF:
            raise FrameError("nwords must be 1..255")
        body = bytes([table]) + record.to_bytes(2, "big") + word.to_bytes(2, "big")
        return encode(Cmd.READ, body + bytes([nwords]))

    def write(self, table: int, record: int, word: int, payload: bytes) -> bytes:
        self._check(Cmd.WRITE)
        from .tables import check_writable

        check_writable(table)
        if not 0 < len(payload) <= MAX_WRITE_PAYLOAD:
            raise FrameError("payload must be 1..200 bytes")
        body = bytes([table]) + record.to_bytes(2, "big") + word.to_bytes(2, "big") + b"\x00"
        return encode(Cmd.WRITE, body + payload)


# --- replies -----------------------------------------------------------------

BUSY_FRAME = bytes.fromhex("04FF010004")


@dataclass(frozen=True)
class Reply:
    kind: str  # ack | data | nak | refused | busy | status | other
    cmd: int
    data: bytes = b""
    code: int | None = None


def classify(raw: bytes, request_cmd: int) -> Reply:
    f = decode(raw)
    if raw == BUSY_FRAME:
        return Reply("busy", 0xFF)
    if f.cmd == Cmd.PROBE and f.body[:1] == b"\x01":
        return Reply("status", f.cmd, data=f.body[1:])  # meaning of the value: UNKNOWN
    if len(f.body) == 2 and f.body[0] == 0x01:
        code = f.body[1]
        kind = "refused" if code == 0x03 and f.cmd == Cmd.READ else "nak"
        return Reply(kind, f.cmd, code=code)
    if f.body[:1] == b"\x00":
        data = f.body[1:]
        return Reply("data" if data else "ack", f.cmd, data=data)
    return Reply("other", f.cmd, data=f.body)
