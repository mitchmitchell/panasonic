import pytest

from panasonic.kxtd1232 import fields as f


def test_cid_number_spec_example():
    assert f.encode_cid_number("123") == bytes.fromhex("3123FFFFFFFF")
    assert f.encode_cid_number("") == bytes.fromhex("0FFFFFFFFFFF")


@pytest.mark.parametrize("n", ["0", "10", "5551234", "01234567890", ""])
def test_cid_number_roundtrip(n):
    assert f.decode_cid_number(f.encode_cid_number(n)) == n


def test_zero_digit_is_A():
    assert f.encode_cid_number("10")[:2] == bytes.fromhex("21A F".replace(" ", ""))[:2]


@pytest.mark.parametrize("bad", ["12a", "1" * 12, "+1"])
def test_cid_number_rejects(bad):
    with pytest.raises(ValueError):
        f.encode_cid_number(bad)


def test_cid_name_layout():
    raw = f.encode_cid_name("TEST")
    assert raw == b"TEST" + b"\x00" * 11 + b"\xff"
    assert f.decode_cid_name(raw) == "TEST"


def test_empty_records_are_zero():
    assert f.encode_cid_name("") == b"\x00" * 15 + b"\xff"
    assert f.decode_cid_name(b"\x00" * 15 + b"\xff") == ""
    assert f.encode_ext_name("") == b"\x00" * 10
    assert f.decode_ext_name(b"\x00" * 10) == ""


def test_cid_name_15_chars_untested_so_refused():
    assert f.decode_cid_name(f.encode_cid_name("N" * 14)) == "N" * 14
    with pytest.raises(ValueError):
        f.encode_cid_name("N" * 15)


def test_cid_name_requires_ff_terminator():
    with pytest.raises(ValueError):
        f.decode_cid_name(b"\x00" * 16)


def test_ext_name_layout():
    assert f.encode_ext_name("EXT 101") == b"EXT 101\x00\x00\x00"
    assert f.decode_ext_name(f.encode_ext_name("X" * 10)) == "X" * 10
    with pytest.raises(ValueError):
        f.encode_ext_name("X" * 11)
    with pytest.raises(ValueError):
        f.encode_cid_name("caf\u00e9")
