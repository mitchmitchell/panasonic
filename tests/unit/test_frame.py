import pytest

from panasonic.kxtd1232.frame import (
    READ_ONLY_COMMANDS,
    WRITE_COMMANDS,
    Cmd,
    Encoder,
    FrameError,
    NotAllowedError,
    checksum,
    classify,
    decode,
    encode,
)

H = bytes.fromhex
RW = Encoder(READ_ONLY_COMMANDS | WRITE_COMMANDS)


def test_checksum_and_encode_probe():
    assert encode(Cmd.PROBE, b"\x00") == H("0308000B")
    assert Encoder().status_probe() == H("0308010C")
    assert checksum(H("0308")) == 0x0B


# Synthetic exchanges from the RE handoff §4.2 (spec-derived contract fixtures).
@pytest.mark.parametrize(
    "build,expected",
    [
        (lambda: Encoder().read(0x24, 0, 0, 9), "080124000000000936"),
        (lambda: Encoder().read(0x24, 0, 0, 0x4B), "080124000000004B78"),
        (lambda: Encoder().read(0xC3, 800, 0, 100), "0801C303200000 6453"),
        (lambda: Encoder().clock(), "020305"),
        (lambda: Encoder().end_binary(), "020B0D"),
    ],
)
def test_requests_match_spec(build, expected):
    assert build() == H(expected.replace(" ", ""))


def test_write_frame_matches_spec():
    payload = H("3123FFFFFFFF0FFFFFFFFFFF0FFFFFFFFFFF")
    raw = RW.write(0x24, 0, 0, payload)
    assert raw == H("1A0024000000000031 23FFFFFFFF0FFFFFFFFFFF0FFFFFFFFFFFA2".replace(" ", ""))
    assert raw[0] == 8 + len(payload)


def test_read_only_encoder_blocks_writes():
    with pytest.raises(NotAllowedError):
        Encoder().write(0x24, 0, 0, b"\x00\x00")


@pytest.mark.parametrize("table", [0x0B, 0x17, 0x4B, 0x10, 0x03])
def test_write_blocked_tables(table):
    with pytest.raises(NotAllowedError):
        RW.write(table, 0, 0, b"\x00\x00")


def test_write_payload_bounds():
    with pytest.raises(FrameError):
        RW.write(0x24, 0, 0, b"\x00" * 201)
    assert RW.write(0x24, 0, 0, b"\x00" * 200)[0] == 0xD0


@pytest.mark.parametrize(
    "raw,kind,code",
    [
        ("03000003", "ack", None),
        ("0401010208", "nak", 2),
        ("0400010207", "nak", 2),
        ("0401010309", "refused", 3),
        ("04FF010004", "busy", None),
        ("0408010310", "status", None),
        ("030A000D", "ack", None),
        ("0310 0013", "ack", None),
        ("030B000E", "ack", None),
    ],
)
def test_classify_replies(raw, kind, code):
    b = H(raw.replace(" ", ""))
    r = classify(b, b[1])
    assert r.kind == kind and r.code == code


def test_read_word_limit_fits_one_frame():
    assert Encoder().read(0x24, 0, 0, 126)
    with pytest.raises(FrameError):
        Encoder().read(0x24, 0, 0, 127)


def test_probe_nak_is_not_status():
    r = classify(H("040801020F"), Cmd.PROBE)
    assert r.kind == "nak" and r.code == 2


def test_read_reply_data():
    raw = H("15010031 23FFFFFFFF0FFFFFFFFFFF0FFFFFFFFFFF7A".replace(" ", ""))
    r = classify(raw, Cmd.READ)
    assert r.kind == "data" and len(r.data) == 18


def test_decode_rejects_bad_checksum_and_length():
    with pytest.raises(FrameError):
        decode(H("0308000C"))
    with pytest.raises(FrameError):
        decode(H("030800"))
