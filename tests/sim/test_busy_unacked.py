import itertools

import pytest

from panasonic.kxtd1232.client import (
    BusyTimeoutError,
    Client,
    UnackedWriteError,
    WriteRejectedError,
)
from panasonic.kxtd1232.frame import READ_ONLY_COMMANDS, WRITE_COMMANDS, Encoder
from panasonic.kxtd1232.writeplan import build_plan, field_patch
from panasonic.sim import LoopbackTransport, SimPBX


class FakeClock:
    """Advances 128 ms per call, the observed busy cadence."""

    def __init__(self):
        self._t = itertools.count()

    def __call__(self):
        return next(self._t) * 0.128


def connect():
    sim = SimPBX()
    c = Client(
        LoopbackTransport(sim), Encoder(READ_ONLY_COMMANDS | WRITE_COMMANDS), clock=FakeClock()
    )
    c.login("0000")
    return sim, c


def one_write(c):
    base = c.read_records(0x24, 6, 0, 50)
    return build_plan(0x24, 6, base, [field_patch("cid_number", 1, "42")]).writes[0]


def test_busy_past_bound_raises():
    sim, c = connect()
    sim.inject("busy_forever")
    with pytest.raises(BusyTimeoutError):
        c.version()


def test_short_busy_ok():
    sim, c = connect()
    sim.inject("busy")
    assert c.version()


def test_busy_past_bound_on_write_is_unacked_then_verify():
    sim, c = connect()
    w = one_write(c)
    sim.inject("busy_forever")
    with pytest.raises(UnackedWriteError):
        c.write(w.table, w.record, w.word, w.new)


@pytest.mark.parametrize(
    "fault,outcome", [("no_ack_applied", "applied"), ("no_ack_dropped", "not_applied")]
)
def test_unacked_write_verified_by_reread_not_resent(fault, outcome):
    sim, c = connect()
    w = one_write(c)
    sim.inject(fault)
    with pytest.raises(UnackedWriteError) as e:
        c.write(w.table, w.record, w.word, w.new)
    assert e.value.payload == w.new
    writes_before = len(sim.writes)
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == outcome
    assert len(sim.writes) == writes_before  # verify never resends


def test_write_fault_survives_intervening_reads():
    sim, c = connect()
    sim.inject("silent_write")
    w = one_write(c)  # reads happen first
    c.write(w.table, w.record, w.word, w.new)
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == "not_applied"


def test_busy_forever_then_verify_block_starts_clean():
    sim, c = connect()
    w = one_write(c)
    sim.inject("busy_forever")
    with pytest.raises(UnackedWriteError):
        c.write(w.table, w.record, w.word, w.new)
    # busy_forever drops the write, so the re-read must say exactly not_applied
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == "not_applied"


def test_garbled_ack_is_unacked_write():
    sim, c = connect()
    w = one_write(c)
    sim.inject("garbled_ack")
    with pytest.raises(UnackedWriteError):
        c.write(w.table, w.record, w.word, w.new)
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == "applied"


def test_stale_read_reply_during_write_ack_is_skipped():
    sim, c = connect()
    w = one_write(c)
    sim.inject("stale_read")
    assert c.write(w.table, w.record, w.word, w.new).kind == "ack"
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == "applied"


def test_stale_ack_during_verify_block_is_skipped():
    sim, c = connect()
    w = one_write(c)
    sim.inject("no_ack_dropped")
    with pytest.raises(UnackedWriteError):
        c.write(w.table, w.record, w.word, w.new)
    sim.inject("stale_ack")
    assert c.verify_block(w.table, w.record, w.word, w.new, w.base) == "not_applied"


def test_write_nak_raises_rejected():
    sim, c = connect()
    w = one_write(c)
    sim.inject("nak")
    with pytest.raises(WriteRejectedError) as e:
        c.write(w.table, w.record, w.word, w.new)
    assert e.value.reply.code == 2
