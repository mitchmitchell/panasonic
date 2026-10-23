"""Mitch's Claude review @ 12ed3f9e7265: correlation, write ranges, session limits, plan."""

import pytest

from panasonic.kxtd1232.frame import (
    READ_ONLY_COMMANDS,
    WRITE_COMMANDS,
    Cmd,
    Encoder,
    FrameError,
    NotAllowedError,
    ReplyKind,
    ReplyMismatchError,
    classify,
)
from panasonic.kxtd1232.session import MAX_LINE, Login, State
from panasonic.kxtd1232.writeplan import Granularity, build_plan, field_patch
from panasonic.sim import synthetic_db

RW = Encoder(READ_ONLY_COMMANDS | WRITE_COMMANDS)
H = bytes.fromhex


def test_classify_rejects_mismatched_cmd():
    with pytest.raises(ReplyMismatchError):
        classify(H("03000003"), Cmd.READ)  # write ack while waiting on a read
    assert classify(H("04FF010004"), Cmd.WRITE).kind is ReplyKind.BUSY


@pytest.mark.parametrize("cmds", [{Cmd.END_UPLOAD_A}, {Cmd.END_UPLOAD_B}])
def test_end_upload_commands_structurally_rejected(cmds):
    with pytest.raises(NotAllowedError):
        Encoder(READ_ONLY_COMMANDS | frozenset(cmds))


def test_not_allowed_is_plain_exception():
    assert not issubclass(NotAllowedError, PermissionError)


@pytest.mark.parametrize(
    "args", [(0x24, -1, 0, b"\0\0"), (0x24, 0x10000, 0, b"\0\0"), (0x24, 0, -1, b"\0\0"),
             (0x24, 0, 0x10000, b"\0\0"), (0x24, 0, 0, b"\0\0\0")],
)  # fmt: skip
def test_write_range_and_even_payload(args):
    with pytest.raises(FrameError):
        RW.write(*args)


BANNER = b"Welcome To KX-TD1232  Ver 2.0 Panasonic CO.,LTD.\r\nEnter Password\r\n"


def test_session_line_cap():
    s = Login("pw")
    s.feed(b"\x11")
    s.feed(b"x" * (MAX_LINE + 1))
    assert s.state is State.FAILED


def test_session_hands_over_binary_leftover():
    s = Login("pw")
    s.feed(b"\x11" + BANNER + b"EIA Mode Start\r\nECS OF\r\nOK\r\n")
    s.feed(b"OK\r\n\x03\x08\x00\x0b")
    assert s.state is State.BINARY and s.leftover == H("0308000B")


def test_granularity_enum_and_chunk_limit():
    base = bytes(synthetic_db()[0x25])
    p = field_patch("cid_name", 0, "A")
    assert build_plan(0x25, 16, base, [p], granularity=Granularity.TABLE).writes
    with pytest.raises(ValueError):
        build_plan(0x25, 16, base, [p], granularity="whole")
    with pytest.raises(ValueError):
        build_plan(0x25, 16, base, [p], records_per_chunk=13)  # 208 bytes > 200


def test_session_caps_total_login_lines():
    from panasonic.kxtd1232.session import MAX_LOGIN_LINES, Login, State

    sm = Login("0000")
    sm.feed(b"\x11" + b"x\n" * (MAX_LOGIN_LINES + 5))
    assert sm.state is State.FAILED
