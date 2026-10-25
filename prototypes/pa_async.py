"""PA option (b): the same sans-I/O Login core driven by asyncio.

Shows that an asyncio transport is a thin wrapper over the sans-I/O core.
"""

from __future__ import annotations

import asyncio

from panasonic.kxtd1232.frame import Encoder, classify, frame_length
from panasonic.kxtd1232.session import Login, LoginError, State
from panasonic.sim import SimPBX


class AsyncSimTransport:
    def __init__(self, sim: SimPBX) -> None:
        self.sim = sim
        self.q: asyncio.Queue[bytes] = asyncio.Queue()
        self.q.put_nowait(sim.dtr_up())

    async def send(self, data: bytes) -> None:
        out = self.sim.feed(data)
        if out:
            await self.q.put(out)

    async def recv(self, timeout: float) -> bytes:
        return await asyncio.wait_for(self.q.get(), timeout)


async def download(sim: SimPBX, table: int, record_size: int, count: int) -> bytes:
    t = AsyncSimTransport(sim)
    sm = Login("0000")
    while sm.state not in (State.BINARY, State.FAILED):
        out = sm.feed(await t.recv(1.0))
        if out:
            await t.send(out)
    if sm.state is State.FAILED:
        raise LoginError(sm.failure)
    enc, rx, data = Encoder(), b"", bytearray()
    per = 150 // record_size
    for rec in range(0, count, per):
        n = min(per, count - rec)
        await t.send(enc.read(table, rec, 0, n * record_size // 2))
        while (fl := frame_length(rx)) is None or len(rx) < fl:
            rx += await t.recv(1.0)
        raw, rx = rx[:fl], rx[fl:]
        data += classify(raw, 1).data
    return bytes(data)
