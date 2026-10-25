import asyncio
import time

from panasonic.kxtd1232.client import Client
from panasonic.sim import LoopbackTransport, SimPBX
from prototypes.pa_async import download
from prototypes.queue_models import AsyncQueue, ThreadQueue


def test_pa_sync_and_async_agree():
    c = Client(LoopbackTransport(SimPBX()))
    c.login("0000")
    assert asyncio.run(download(SimPBX(), 0x24, 6, 50)) == c.read_records(0x24, 6, 0, 50)


def _jobs(order):
    def mk(i):
        def fn():
            time.sleep(0.002)
            order.append(i)
            if i == 3:
                raise RuntimeError("boom")
            return i

        return fn

    return [mk(i) for i in range(6)]


def test_thread_queue_serializes():
    q, order = ThreadQueue(), []
    jobs = [q.submit(f) for f in _jobs(order)]
    q.drain()
    q.stop()
    assert order == list(range(6)) and q.max_running == 1
    assert jobs[3].state == "failed" and jobs[5].state == "done"


def test_async_queue_serializes():
    async def run():
        q, order = AsyncQueue(), []
        jobs = [q.submit(f) for f in _jobs(order)]
        w = asyncio.create_task(q.worker())
        await q._q.join()
        w.cancel()
        return q, order, jobs

    q, order, jobs = asyncio.run(run())
    assert order == list(range(6)) and q.max_running == 1
    assert jobs[3].state == "failed"
