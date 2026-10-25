"""Daemon queue model prototypes: one worker thread vs one asyncio worker task.

Both must run jobs strictly one at a time, in submit order, with a state per job.
"""

from __future__ import annotations

import asyncio
import itertools
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Job:
    id: int
    fn: Callable[[], object]
    state: str = "queued"  # queued | running | done | failed
    result: object = None
    log: list[str] = field(default_factory=list)


class ThreadQueue:
    def __init__(self) -> None:
        self._q: queue.Queue[Job | None] = queue.Queue()
        self._ids = itertools.count(1)
        self.running = 0
        self.max_running = 0
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def submit(self, fn: Callable[[], object]) -> Job:
        job = Job(next(self._ids), fn)
        self._q.put(job)
        return job

    def _run(self) -> None:
        while (job := self._q.get()) is not None:
            self.running += 1
            self.max_running = max(self.max_running, self.running)
            job.state = "running"
            try:
                job.result, job.state = job.fn(), "done"
            except Exception as e:  # noqa: BLE001 - job failures are recorded, not raised
                job.state, job.result = "failed", repr(e)
            self.running -= 1
            self._q.task_done()

    def drain(self) -> None:
        self._q.join()

    def stop(self) -> None:
        self._q.put(None)
        self._t.join()


class AsyncQueue:
    def __init__(self) -> None:
        self._q: asyncio.Queue[Job] = asyncio.Queue()
        self._ids = itertools.count(1)
        self.running = 0
        self.max_running = 0

    def submit(self, fn: Callable[[], object]) -> Job:
        job = Job(next(self._ids), fn)
        self._q.put_nowait(job)
        return job

    async def worker(self) -> None:
        while True:
            job = await self._q.get()
            self.running += 1
            self.max_running = max(self.max_running, self.running)
            job.state = "running"
            try:
                # blocking serial I/O must leave the event loop
                job.result = await asyncio.to_thread(job.fn)
                job.state = "done"
            except Exception as e:  # noqa: BLE001
                job.state, job.result = "failed", repr(e)
            self.running -= 1
            self._q.task_done()
