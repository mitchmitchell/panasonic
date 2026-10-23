import random

import pytest

from panasonic.kxtd1232.fields import CID_NAME_SIZE
from panasonic.kxtd1232.frame import NotAllowedError
from panasonic.kxtd1232.writeplan import Patch, build_plan, field_patch
from panasonic.sim import synthetic_db


def test_single_field_edit_one_chunk():
    base = bytes(synthetic_db()[0x25])
    plan = build_plan(0x25, CID_NAME_SIZE, base, [field_patch("cid_name", 3, "NEW")])
    assert len(plan.writes) == 1
    w = plan.writes[0]
    assert len(w.new) <= 200 and w.record == 0


def test_table_granularity_writes_everything():
    base = bytes(synthetic_db()[0x25])
    plan = build_plan(0x25, 16, base, [field_patch("cid_name", 3, "NEW")], granularity="table")
    assert sum(len(w.new) for w in plan.writes) == len(base)


def test_fuzz_no_bytes_outside_span():
    rng = random.Random(74)
    base = bytes(synthetic_db()[0x24])
    for _ in range(200):
        idx = rng.randrange(len(base) // 6)
        num = "".join(rng.choice("0123456789") for _ in range(rng.randint(0, 11)))
        p = field_patch("cid_number", idx, num)
        plan = build_plan(0x24, 6, base, [p])
        for w in plan.writes:
            start = w.record * 6
            for i, (a, b) in enumerate(zip(w.base, w.new, strict=True)):
                if a != b:
                    assert p.offset <= start + i < p.offset + 6


def test_no_change_no_writes():
    base = bytes(synthetic_db()[0x24])
    assert build_plan(0x24, 6, base, [Patch(0x24, 0, base[:6])]).writes == []


def test_rejects_bad_tables_and_ranges():
    with pytest.raises(NotAllowedError):
        build_plan(0x0B, 2, b"\x00" * 4, [])
    with pytest.raises(ValueError):
        build_plan(0x24, 6, b"\x00" * 6, [Patch(0x24, 4, b"\x00\x00\x00")])
