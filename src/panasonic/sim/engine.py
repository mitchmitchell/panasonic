"""Sans-I/O PBX simulator built from the behavior spec. All data is synthetic.

Faults are queued with :meth:`SimPBX.inject`. A0/A1 support ``nak`` (next request gets a
bad-checksum NAK) and ``silent_write`` (next write is acked but not stored). The rest of
design §6 (busy run, unacked write, timeout, link drop, ...) lands in A2.
"""

from __future__ import annotations

from collections import deque

from panasonic.kxtd1232.fields import encode_cid_name, encode_cid_number, encode_ext_name
from panasonic.kxtd1232.frame import BUSY_FRAME, Cmd, checksum, encode

PLACEHOLDER_PASSWORD = "0000"
PLACEHOLDER_ROM_ID = "-----PXXXXXXXXXX"
BANNER = b"Welcome To KX-TD1232  Ver 2.0 Panasonic CO.,LTD.\r\nEnter Password\r\n"


def synthetic_db(cid_records: int = 50, ext_records: int = 32) -> dict[int, bytearray]:
    """A small fake database: a few caller-ID entries and extension names."""
    nums = bytearray(encode_cid_number("") * cid_records)
    names = bytearray(encode_cid_name("") * cid_records)
    nums[0:6] = encode_cid_number("123")
    names[0:16] = encode_cid_name("TEST ONE")
    exts = bytearray()
    for i in range(ext_records):
        exts += encode_ext_name(f"EXT {i + 100}")
    return {0x24: nums, 0x25: names, 0x05: exts}


class SimPBX:
    def __init__(
        self,
        db: dict[int, bytearray] | None = None,
        password: str = PLACEHOLDER_PASSWORD,
        rom_id: str = PLACEHOLDER_ROM_ID,
    ) -> None:
        self.db = db if db is not None else synthetic_db()
        self._password = password.encode("ascii")
        self.rom_id = rom_id.encode("ascii").ljust(16)[:16]
        self.mode = "idle"
        self._buf = b""
        self.faults: deque[str] = deque()
        self.writes: list[tuple[int, int, int, bytes]] = []
        self.requests = 0

    def inject(self, fault: str) -> None:
        if fault not in _FAULTS:
            raise ValueError(f"unknown fault {fault}")
        self.faults.append(fault)

    # -- line events ----------------------------------------------------------
    def dtr_up(self) -> bytes:
        self.mode = "await_crlf"
        self._buf = b""
        return bytes([0x13, 0x11])

    def dtr_down(self) -> bytes:
        self.mode = "idle"
        return b"\x00"

    def feed(self, data: bytes) -> bytes:
        self._buf += data
        out = b""
        while True:
            if self.mode == "binary":
                if not self._buf or len(self._buf) < self._buf[0] + 1:
                    return out
                n = self._buf[0] + 1
                raw, self._buf = self._buf[:n], self._buf[n:]
                out += self._frame(raw)
            else:
                if b"\r" not in self._buf:
                    return out
                line, self._buf = self._buf.split(b"\r", 1)
                self._buf = self._buf.removeprefix(b"\n")
                out += self._text(line.strip())

    def _text(self, line: bytes) -> bytes:
        m = self.mode
        if m == "await_crlf":
            self.mode = "await_password"
            return BANNER
        if m == "await_password":
            if line == self._password:
                self.mode = "await_ecs"
                return b"EIA Mode Start\r\n"
            return b"Enter Password\r\n"  # guess, like the RE simulator (G5)
        if m == "await_ecs" and line == b"ECS OF":
            self.mode = "await_prg"
            return b"ECS OF\r\nOK\r\n"
        if m == "await_prg" and line == b"PRG":
            self.mode = "binary"
            return b"OK\r\n"
        if m == "await_password_again" and line == b"BYE":
            self.mode = "await_password"
            return b"OK\r\n" + BANNER
        return b"NG\r\n"

    # -- binary ---------------------------------------------------------------
    def _frame(self, raw: bytes) -> bytes:
        self.requests += 1
        cmd = raw[1] if len(raw) > 1 else 0xFF
        if len(raw) < 3 or checksum(raw[:-1]) != raw[-1]:
            return encode(cmd, b"\x01\x02")
        fault = None
        if self.faults and (cmd == Cmd.WRITE or self.faults[0] not in _WRITE_FAULTS):
            fault = self.faults.popleft()
        if fault == "nak":
            return encode(cmd, b"\x01\x02")
        busy = BUSY_FRAME * 3 if fault == "busy" else b""
        if fault == "busy_forever":
            return BUSY_FRAME * 200  # longer than any bound the client is given in tests
        if fault in ("no_ack_applied", "no_ack_dropped"):
            if fault == "no_ack_applied":
                self._write(raw[2:-1], silent=False)
            return b""
        body = raw[2:-1]
        if cmd == Cmd.PROBE and body == b"\x00":
            return busy + encode(cmd, b"\x00" + self.rom_id)
        if cmd == Cmd.PROBE and body == b"\x01":
            return busy + encode(cmd, b"\x01\x03")
        if cmd == Cmd.READ and len(body) == 6:
            return busy + self._read(body)
        if cmd == Cmd.WRITE and len(body) > 6:
            return busy + self._write(body, silent=fault == "silent_write")
        if cmd == Cmd.CLOCK:
            return busy + encode(cmd, b"\x00" + bytes([0x1A, 1, 2, 0, 3, 4, 5, 0]))
        if cmd == Cmd.END_BINARY:
            self.mode = "await_password_again"
            return encode(cmd, b"\x00")
        return encode(cmd, b"\x00")  # guess, like the RE simulator

    def _read(self, body: bytes) -> bytes:
        table = body[0]
        rec, word = int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big")
        nwords = body[5]
        img = self.db.get(table)
        size = _RECORD_SIZES.get(table, 2)
        start = rec * size + 2 * word
        if img is None or start + 2 * nwords > len(img):
            return encode(Cmd.READ, b"\x01\x03")
        return encode(Cmd.READ, b"\x00" + bytes(img[start : start + 2 * nwords]))

    def _write(self, body: bytes, silent: bool) -> bytes:
        table = body[0]
        rec, word = int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big")
        payload = body[6:]
        img = self.db.get(table)
        size = _RECORD_SIZES.get(table, 2)
        start = rec * size + 2 * word
        if img is None or start + len(payload) > len(img):
            return encode(Cmd.WRITE, b"\x01\x03")  # guess (G4)
        self.writes.append((table, rec, word, bytes(payload)))
        if not silent:
            img[start : start + len(payload)] = payload
        return encode(Cmd.WRITE, b"\x00")


_WRITE_FAULTS = {"silent_write", "no_ack_applied", "no_ack_dropped"}
_FAULTS = {"nak", "busy", "busy_forever"} | _WRITE_FAULTS
_RECORD_SIZES = {0x24: 6, 0x25: 16, 0x05: 10}
