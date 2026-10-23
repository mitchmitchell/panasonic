"""``kxtd1232`` CLI. Phase A: simulator only, read-only and dry-run.

Exit codes: 0 success; 1 runtime error, including a refused write or plan (for example a
table outside the editable list) and protocol, frame or login failures; 2 usage error
(bad arguments, out-of-range records, invalid field values). Errors print one line,
``kxtd1232: error: ...``, with no traceback.
"""

from __future__ import annotations

import argparse
import json
import sys

from panasonic.sim import LoopbackTransport, SimPBX

from .client import Client, ProtocolError, RecordDecodeError
from .fields import FIELDS
from .frame import FrameError, NotAllowedError
from .session import LoginError
from .writeplan import build_plan, field_patch

# Record counts per table from the RE table spec (single-cabinet KX-TD1232).
FIELD_RECORDS = {"cid_number": 500, "cid_name": 500, "ext_name": 128}


def _nonneg(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if v < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0: {v}")
    return v


def _positive(text: str) -> int:
    v = _nonneg(text)
    if v == 0:
        raise argparse.ArgumentTypeError("must be >= 1")
    return v


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
    r.add_argument("--first", type=_nonneg, default=0)
    r.add_argument("--count", type=_positive, default=5)
    p = sub.add_parser("plan", help="dry-run a typed field edit")
    p.add_argument("kind", choices=sorted(FIELDS))
    p.add_argument("index", type=_nonneg)
    p.add_argument("value")
    a = ap.parse_args(argv)
    limit = FIELD_RECORDS[a.kind] if a.cmd in ("read", "plan") else 0
    if a.cmd == "read" and a.first + a.count > limit:
        ap.error(f"records {a.first}..{a.first + a.count - 1} out of range 0..{limit - 1}")
    if a.cmd == "plan" and a.index >= limit:
        ap.error(f"record {a.index} out of range 0..{limit - 1}")
    try:
        return _run(a)
    except (ProtocolError, FrameError, LoginError, NotAllowedError) as e:
        print(f"kxtd1232: error: {e}", file=sys.stderr)
        return 1


def _run(a: argparse.Namespace) -> int:
    c = _connect()
    ok = False
    try:
        rc = _command(c, a)
        ok = True
        return rc
    finally:
        try:
            c.end_binary()
        except (ProtocolError, FrameError, TimeoutError):
            if ok:
                raise


def _command(c: Client, a: argparse.Namespace) -> int:
    if a.cmd == "version":
        print(c.version())
    elif a.cmd == "read":
        table, size, _enc, dec = FIELDS[a.kind]
        raw = c.read_records(table, size, a.first, a.count)
        for i in range(a.count):
            rec = raw[i * size : (i + 1) * size]
            try:
                value = dec(rec)
            except ValueError as e:
                raise RecordDecodeError(f"record {a.first + i} does not decode: {e}") from e
            print(f"{a.first + i}\t{value}")
    elif a.cmd == "plan":
        table, size, _enc, _dec = FIELDS[a.kind]
        n = a.index + 1
        base = c.read_records(table, size, 0, n)
        try:
            patch = field_patch(a.kind, a.index, a.value)
        except ValueError as e:
            print(f"kxtd1232: error: {e}", file=sys.stderr)
            return 2
        plan = build_plan(table, size, base, [patch])
        print(json.dumps({"table": table, "writes": len(plan.writes), "diff": plan.diff()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
