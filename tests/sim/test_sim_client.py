import pytest

from panasonic.kxtd1232.client import Client, ProtocolError
from panasonic.kxtd1232.frame import READ_ONLY_COMMANDS, WRITE_COMMANDS, Encoder
from panasonic.kxtd1232.session import LoginError
from panasonic.kxtd1232.writeplan import build_plan, field_patch
from panasonic.sim import LoopbackTransport, SimPBX
from panasonic.sim.engine import PLACEHOLDER_ROM_ID


def connect(sim=None, rw=False):
    sim = sim or SimPBX()
    enc = Encoder(READ_ONLY_COMMANDS | WRITE_COMMANDS) if rw else None
    c = Client(LoopbackTransport(sim), enc)
    c.login("0000")
    return sim, c


def test_login_and_version():
    _, c = connect()
    assert c.version() == PLACEHOLDER_ROM_ID


def test_login_sends_crlf_once_after_xon():
    sim = SimPBX()
    t = LoopbackTransport(sim)
    Client(t).login("0000")
    assert bytes(t.sent).startswith(b"\r\n0000\r")


def test_wrong_password():
    with pytest.raises(LoginError):
        Client(LoopbackTransport(SimPBX())).login("9999")


def test_read_records_blocks_match_db():
    sim, c = connect()
    data = c.read_records(0x24, 6, 0, 50)
    assert data == bytes(sim.db[0x24])
    assert sim.requests == 2  # 25-record blocks


def test_refusal_past_end():
    _, c = connect()
    with pytest.raises(ProtocolError) as e:
        c.read(0x24, 49, 0, 6)
    assert e.value.reply.kind == "refused"


def test_nak_fault_surfaces():
    sim, c = connect()
    sim.inject("nak")
    with pytest.raises(ProtocolError) as e:
        c.read(0x24, 0, 0, 3)
    assert e.value.reply.code == 2


def test_busy_run_waited_out_without_resend():
    sim, c = connect()
    sim.inject("busy")
    before = sim.requests
    assert c.version() == PLACEHOLDER_ROM_ID
    assert sim.requests == before + 1


def test_plan_apply_readback_in_sim():
    sim, c = connect(rw=True)
    base = c.read_records(0x25, 16, 0, 50)
    plan = build_plan(0x25, 16, base, [field_patch("cid_name", 2, "HELLO")])
    for w in plan.writes:
        assert c.write(w.table, w.record, w.word, w.new).kind == "ack"
        assert c.read(w.table, w.record, w.word, len(w.new) // 2) == w.new


def test_silent_write_detected_by_readback():
    sim, c = connect(rw=True)
    base = c.read_records(0x24, 6, 0, 50)
    w = build_plan(0x24, 6, base, [field_patch("cid_number", 1, "42")]).writes[0]
    sim.inject("silent_write")
    assert c.write(w.table, w.record, w.word, w.new).kind == "ack"
    assert c.read(w.table, w.record, w.word, len(w.new) // 2) == w.base


def test_end_binary_then_bye():
    sim, c = connect()
    c.end_binary()
    assert sim.mode == "await_password_again"
