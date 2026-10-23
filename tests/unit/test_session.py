import pytest

from panasonic.kxtd1232.session import Login, State

BANNER = b"Welcome To KX-TD1232  Ver 2.0 Panasonic CO.,LTD.\r\nEnter Password\r\n"


def test_happy_path():
    s = Login("pw")
    assert s.feed(b"\x13") == b""
    assert s.feed(b"\x11") == b"\r\n"
    assert s.feed(BANNER) == b"pw\r"
    assert s.feed(b"EIA Mode Start\r\n") == b"ECS OF\r\n"
    assert s.feed(b"ECS OF\r\nOK\r\n") == b"PRG\r\n"
    s.feed(b"OK\r\n")
    assert s.state is State.BINARY


def test_crlf_only_after_xon():
    s = Login("pw")
    assert s.feed(b"\x13") == b""
    assert s.state is State.WAIT_XON


@pytest.mark.parametrize("reply", [b"Enter Password\r\n", b"NG 01\r\n",
                                   b"Another Terminal Connected\r\n"])  # fmt: skip
def test_failures(reply):
    s = Login("pw")
    s.feed(b"\x11" + BANNER)
    s.feed(reply)
    assert s.state is State.FAILED


def test_repr_hides_password():
    assert "secretpw" not in repr(Login("secretpw"))
