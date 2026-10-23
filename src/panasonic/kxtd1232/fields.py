"""Field codecs. Layouts are HYPOTHESIS unless noted (handoff §2.6)."""

from __future__ import annotations

CID_NUMBER_SIZE = 6  # 12 nibbles: digit count + up to 11 digits
CID_NAME_SIZE = 16  # 15 ASCII bytes + 0xFF
EXT_NAME_SIZE = 10
MAX_CID_DIGITS = 11


def encode_cid_number(number: str) -> bytes:
    """Nibble 0 = digit count, 0xA = digit 0, 0xF pad."""
    if not number.isdigit() and number != "":
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


def _encode_ascii(text: str, size: int, terminator: bool) -> bytes:
    room = size - (1 if terminator else 0)
    if len(text) > room or not text.isascii() or not text.isprintable():
        raise ValueError(f"name must be printable ASCII, at most {room} chars")
    raw = text.encode("ascii").ljust(room, b" ")
    return raw + (b"\xff" if terminator else b"")


def encode_cid_name(name: str) -> bytes:
    return _encode_ascii(name, CID_NAME_SIZE, terminator=True)


def decode_cid_name(raw: bytes) -> str:
    return raw[: CID_NAME_SIZE - 1].decode("ascii").rstrip(" ")


def encode_ext_name(name: str) -> bytes:
    return _encode_ascii(name, EXT_NAME_SIZE, terminator=False)


def decode_ext_name(raw: bytes) -> str:
    return raw.decode("ascii").rstrip(" ")


# record size and codec per editable field kind
FIELDS = {
    "cid_number": (0x24, CID_NUMBER_SIZE, encode_cid_number, decode_cid_number),
    "cid_name": (0x25, CID_NAME_SIZE, encode_cid_name, decode_cid_name),
    "ext_name": (0x05, EXT_NAME_SIZE, encode_ext_name, decode_ext_name),
}
