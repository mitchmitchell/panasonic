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


def test_names():
    raw = f.encode_cid_name("TEST")
    assert len(raw) == 16 and raw[-1] == 0xFF
    assert f.decode_cid_name(raw) == "TEST"
    assert f.decode_ext_name(f.encode_ext_name("EXT 101")) == "EXT 101"
    with pytest.raises(ValueError):
        f.encode_ext_name("X" * 11)
    with pytest.raises(ValueError):
        f.encode_cid_name("caf\u00e9")
