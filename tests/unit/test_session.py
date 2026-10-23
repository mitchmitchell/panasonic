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


def test_terminated_overlong_line_fails():
    # Claude PRRT_kwDOVUJjDM6vdZ4H: a long line ending in LF inside one feed is capped too.
    from panasonic.kxtd1232.session import MAX_LINE, XON, Login, State

    s = Login("0000")
    s.feed(bytes([XON]) + b"A" * (MAX_LINE + 1) + b"\r\n")
    assert s.state is State.FAILED and "longer than" in (s.failure or "")


def test_max_length_line_with_crlf_is_accepted():
    # Tester low: a MAX_LINE-byte line plus CRLF is within the cap; the CR is a terminator.
    from panasonic.kxtd1232.session import MAX_LINE, XON, Login, State

    s = Login("0000")
    s.feed(bytes([XON]) + b"A" * MAX_LINE + b"\r\n")
    assert s.state is not State.FAILED


def _signed_on():
    from panasonic.kxtd1232.session import XON, Login

    s = Login("0000")
    s.feed(bytes([XON]))
    return s


def test_max_line_cr_and_lf_in_separate_reads_is_accepted():
    from panasonic.kxtd1232.session import MAX_LINE, State

    s = _signed_on()
    s.feed(b"A" * MAX_LINE + b"\r")
    s.feed(b"\n")
    assert s.state is not State.FAILED


def test_max_line_lone_cr_then_lf_later_is_accepted():
    from panasonic.kxtd1232.session import MAX_LINE, State

    s = _signed_on()
    s.feed(b"A" * MAX_LINE)
    s.feed(b"\r")
    assert s.state is not State.FAILED
    s.feed(b"\n")
    assert s.state is not State.FAILED


def test_max_line_crlf_fed_byte_by_byte_is_accepted():
    from panasonic.kxtd1232.session import MAX_LINE, State

    s = _signed_on()
    for b in b"A" * MAX_LINE + b"\r\n":
        s.feed(bytes([b]))
        assert s.state is not State.FAILED


def test_line_over_max_with_crlf_is_rejected():
    from panasonic.kxtd1232.session import MAX_LINE, State

    s = _signed_on()
    s.feed(b"A" * (MAX_LINE + 1) + b"\r\n")
    assert s.state is State.FAILED and "longer than" in (s.failure or "")
