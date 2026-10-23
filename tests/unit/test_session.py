import pytest

from panasonic.kxtd1232.session import Login, State
from panasonic.sim.engine import BANNER  # synthetic placeholder sign-on


def test_happy_path():
    s = Login("pw")
    assert s.feed(b"\x13") == b""
    assert s.feed(b"\x11") == b"\r\n"
    assert s.feed(BANNER) == b"pw\r"
    assert s.feed(b"<MODE_START>\r\n") == b"ECS OF\r\n"
    assert s.feed(b"ECS OF\r\nOK\r\n") == b"PRG\r\n"
    s.feed(b"OK\r\n")
    assert s.state is State.BINARY


def test_crlf_only_after_xon():
    s = Login("pw")
    assert s.feed(b"\x13") == b""
    assert s.state is State.WAIT_XON


@pytest.mark.parametrize("reply", [b"Password:\r\n", b"NG 01\r\n",
                                   b"<TERMINAL_IN_USE>\r\n"])  # fmt: skip
def test_failures(reply):
    s = Login("pw")
    s.feed(b"\x11" + BANNER)
    s.feed(reply)
    assert s.state is State.FAILED


def test_repr_hides_password():
    assert "secretpw" not in repr(Login("secretpw"))
