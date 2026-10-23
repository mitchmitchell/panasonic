"""Timed transport tests (virtual clock) for pre-send quiet and the post-send guard."""

import pytest

from panasonic.kxtd1232.client import Client, PreSendError, UnackedWriteError
from panasonic.kxtd1232.frame import BUSY_FRAME, READ_ONLY_COMMANDS, Cmd, Encoder, encode

ACK = encode(Cmd.WRITE, b"\x00")
P = b"\x11" * 16


class Timed:
    """Each send schedules (delay, bytes) events relative to the virtual send time."""

    def __init__(self, script):
        self.t, self.ev, self.script, self.sends = 0.0, [], list(script), 0

    def send(self, data):
        self.sends += 1
        for dt, b in self.script.pop(0) if self.script else []:
            self.ev.append((self.t + dt, b))
        self.ev.sort(key=lambda e: e[0])

    def recv(self, timeout):
        if self.ev and self.ev[0][0] <= self.t + timeout:
            at, b = self.ev.pop(0)
            self.t = max(self.t, at)
            return b
        self.t += timeout
        raise TimeoutError

    def close(self):
        pass


def _client(t):
    return Client(t, encoder=Encoder(READ_ONLY_COMMANDS | {Cmd.WRITE}))


def test_stale_ack_at_10ms_with_dropped_write_is_not_success():
    t = Timed([[(0.010, ACK)]])
    with pytest.raises(UnackedWriteError):
        _client(t).write(0x25, 1, 0, P)


def test_real_ack_after_stale_ack_is_accepted():
    t = Timed([[(0.010, ACK), (0.2, ACK)]])
    assert _client(t).write(0x25, 1, 0, P).kind == "ack"


def test_noisy_line_raises_presend_and_sends_nothing():
    class Noisy(Timed):
        def recv(self, timeout):
            self.t += 0.01
            return BUSY_FRAME

    t = Noisy([])
    with pytest.raises(PreSendError) as ei:
        _client(t).write(0x25, 1, 0, P)
    assert not isinstance(ei.value, UnackedWriteError) and t.sends == 0


def test_longer_quiet_after_unacked_write():
    t = Timed([[], [(0.01, ACK)]])
    c = _client(t)
    with pytest.raises(TimeoutError):
        c.request(c.enc.write(0x25, 1, 0, P), timeout=0.1)
    # a late frame 0.3 s later would slip past a 50 ms quiet wait but not the recovery wait
    t.ev.append((t.t + 0.3, ACK))
    t0 = t.t
    assert c._dirty
    with pytest.raises(UnackedWriteError):
        c.write(0x25, 2, 0, P)  # stale ack drained, guard drops the 10 ms ack -> unacked
    assert t.t - t0 >= 0.5
