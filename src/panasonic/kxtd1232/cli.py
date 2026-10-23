"""``kxtd1232`` CLI. Phase A: simulator only, read-only and dry-run."""

from __future__ import annotations

import argparse
import json
import sys

from panasonic.sim import LoopbackTransport, SimPBX

from .client import Client
from .fields import FIELDS
from .frame import NotAllowedError
from .writeplan import build_plan, field_patch


def _connect() -> Client:
    sim = SimPBX()
    c = Client(LoopbackTransport(sim))
    c.login("0000")
    return c


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kxtd1232", description=__doc__)
    ap.add_argument("--transport", choices=["sim"], default="sim")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version", help="version probe")
    r = sub.add_parser("read", help="read typed fields")
    r.add_argument("kind", choices=sorted(FIELDS))
    r.add_argument("--first", type=int, default=0)
    r.add_argument("--count", type=int, default=5)
    p = sub.add_parser("plan", help="dry-run a typed field edit")
    p.add_argument("kind", choices=sorted(FIELDS))
    p.add_argument("index", type=int)
    p.add_argument("value")
    a = ap.parse_args(argv)

    c = _connect()
    if a.cmd == "version":
        print(c.version())
    elif a.cmd == "read":
        table, size, _enc, dec = FIELDS[a.kind]
        raw = c.read_records(table, size, a.first, a.count)
        for i in range(a.count):
            print(f"{a.first + i}\t{dec(raw[i * size : (i + 1) * size])}")
    elif a.cmd == "plan":
        table, size, _enc, _dec = FIELDS[a.kind]
        n = a.index + 1
        base = c.read_records(table, size, 0, n)
        try:
            patch = field_patch(a.kind, a.index, a.value)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        try:
            plan = build_plan(table, size, base, [patch])
        except NotAllowedError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(json.dumps({"table": table, "writes": len(plan.writes), "diff": plan.diff()}))
    c.end_binary()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
