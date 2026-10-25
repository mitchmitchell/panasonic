"""Field codecs. Layouts are HYPOTHESIS unless noted (handoff §2.6)."""

from __future__ import annotations

CID_NUMBER_SIZE = 6  # 12 nibbles: digit count + up to 11 digits
CID_NAME_SIZE = 16  # 15 ASCII bytes + 0xFF
EXT_NAME_SIZE = 10
MAX_CID_DIGITS = 11


def encode_cid_number(number: str) -> bytes:
    """Nibble 0 = digit count, 0xA = digit 0, 0xF pad."""
    if any(d not in "0123456789" for d in number):  # ASCII only; str.isdigit allows Unicode
        raise ValueError("caller-ID number must be digits only")
    if len(number) > MAX_CID_DIGITS:
        raise ValueError(f"at most {MAX_CID_DIGITS} digits")
    nibbles = [len(number)] + [0xA if d == "0" else int(d) for d in number]
    nibbles += [0xF] * (2 * CID_NUMBER_SIZE - len(nibbles))
    return bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))


def decode_cid_number(raw: bytes) -> str:
    if len(raw) != CID_NUMBER_SIZE:
        raise ValueError("bad record size")
    nibbles = [n for b in raw for n in (b >> 4, b & 0xF)]
    count = nibbles[0]
    if count > MAX_CID_DIGITS:
        raise ValueError("bad digit count")
    digits = nibbles[1 : 1 + count]
    if any(d == 0 or d > 0xA for d in digits):
        raise ValueError("bad digit nibble")
    return "".join("0" if d == 0xA else str(d) for d in digits)


def _encode_ascii(text: str, room: int) -> bytes:
    """ASCII padded with 0x00 (RE table spec); an empty field is all 0x00."""
    if len(text) > room or not text.isascii() or not text.isprintable():
        raise ValueError(f"name must be printable ASCII, at most {room} chars")
    return text.encode("ascii").ljust(room, b"\x00")


def _decode_ascii(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii")


# Caller-ID names: bytes 0-14 ASCII, 0x00-padded; byte 15 is always 0xFF, even when empty.
# A full 15-character name (no 0x00 before the 0xFF) has never been tested on hardware,
# so the encoder refuses it and allows at most 14 characters until RE confirms it.
MAX_CID_NAME_CHARS = CID_NAME_SIZE - 2


def encode_cid_name(name: str) -> bytes:
    return _encode_ascii(name, MAX_CID_NAME_CHARS).ljust(CID_NAME_SIZE - 1, b"\x00") + b"\xff"


def decode_cid_name(raw: bytes) -> str:
    if len(raw) != CID_NAME_SIZE or raw[-1] != 0xFF:
        raise ValueError("caller-ID name record must be 16 bytes ending in 0xFF")
    return _decode_ascii(raw[: CID_NAME_SIZE - 1])


def encode_ext_name(name: str) -> bytes:
    """Extension names (table 0x05): 10 bytes, ASCII, 0x00-padded."""
    return _encode_ascii(name, EXT_NAME_SIZE)


def decode_ext_name(raw: bytes) -> str:
    if len(raw) != EXT_NAME_SIZE:
        raise ValueError("extension name record must be 10 bytes")
    return _decode_ascii(raw)


# record size and codec per editable field kind
FIELDS = {
    "cid_number": (0x24, CID_NUMBER_SIZE, encode_cid_number, decode_cid_number),
    "cid_name": (0x25, CID_NAME_SIZE, encode_cid_name, decode_cid_name),
    "ext_name": (0x05, EXT_NAME_SIZE, encode_ext_name, decode_ext_name),
}
