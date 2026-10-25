"""Print A0 prototype measurements (PB/PC frame and byte counts, PA parity)."""

from __future__ import annotations

import asyncio

from panasonic.kxtd1232.client import Client
from panasonic.kxtd1232.writeplan import build_plan, field_patch
from panasonic.sim import LoopbackTransport, SimPBX, synthetic_db
from prototypes.pa_async import download

BAUD_BYTES_PER_S = 960  # 9600 8N1


def main() -> None:
    db = synthetic_db()
    base = bytes(db[0x25])
    p = field_patch("cid_name", 7, "NEW NAME")
    for g in ("chunk", "table"):
        plan = build_plan(0x25, 16, base, [p], granularity=g)
        nbytes = sum(len(w.new) + 9 for w in plan.writes)
        print(f"PC {g}: frames={len(plan.writes)} wire_bytes={nbytes} "
              f"wire_s={nbytes / BAUD_BYTES_PER_S:.2f} + ack_median=0.28s/frame "
              f"changed={plan.changed_bytes()}")  # fmt: skip
    sync = Client(LoopbackTransport(SimPBX()))
    sync.login("0000")
    a = sync.read_records(0x24, 6, 0, 50)
    b = asyncio.run(download(SimPBX(), 0x24, 6, 50))
    print(f"PA parity sync==async: {a == b}")


if __name__ == "__main__":
    main()
