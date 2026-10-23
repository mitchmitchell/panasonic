"""Synchronous loopback transport binding a Client to an in-process SimPBX."""

from __future__ import annotations

from .engine import SimPBX


class LoopbackTransport:
    instant = True  # replies appear synchronously; no timing to guard

    def __init__(self, sim: SimPBX) -> None:
        self.sim = sim
        self.sent = bytearray()
        self._rx = bytearray(sim.dtr_up())  # opening the port raises DTR

    def send(self, data: bytes) -> None:
        self.sent += data
        self._rx += self.sim.feed(data)

    def recv(self, timeout: float) -> bytes:
        if not self._rx:
            raise TimeoutError("no data from simulator")
        data, self._rx = bytes(self._rx), bytearray()
        return data

    def close(self) -> None:
        self.sim.dtr_down()
