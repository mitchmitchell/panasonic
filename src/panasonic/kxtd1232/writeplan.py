"""WritePlan: a dry-run list of chunk writes computed from a base image and edits.

Unchanged bytes inside a chunk are re-sent exactly as read (design §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .fields import FIELDS
from .frame import MAX_WRITE_PAYLOAD
from .tables import check_writable


@dataclass(frozen=True)
class Patch:
    """Raw edit: bytes at ``offset`` within a table image (expert / debug escape hatch)."""

    table: int
    offset: int
    data: bytes


def field_patch(kind: str, index: int, value: str) -> Patch:
    """Typed edit (PB option (b)) compiled to a raw Patch."""
    table, size, enc, _dec = FIELDS[kind]
    return Patch(table, index * size, enc(value))


@dataclass(frozen=True)
class ChunkWrite:
    table: int
    record: int
    word: int
    base: bytes
    new: bytes


@dataclass
class WritePlan:
    table: int
    record_size: int
    writes: list[ChunkWrite] = field(default_factory=list)

    def changed_bytes(self) -> int:
        return sum(a != b for w in self.writes for a, b in zip(w.base, w.new, strict=True))

    def diff(self) -> list[str]:
        lines = []
        for w in self.writes:
            for i, (a, b) in enumerate(zip(w.base, w.new, strict=True)):
                if a != b:
                    off = w.record * self.record_size + 2 * w.word + i
                    lines.append(f"T{self.table:02X} +{off:#06x}: {a:02X} -> {b:02X}")
        return lines


def build_plan(
    table: int,
    record_size: int,
    base: bytes,
    patches: list[Patch],
    granularity: str = "chunk",
    records_per_chunk: int | None = None,
) -> WritePlan:
    """``granularity``: "chunk" (only changed record groups, PC (a)) or "table" (PC (b))."""
    check_writable(table)
    new = bytearray(base)
    for p in patches:
        if p.table != table:
            raise ValueError("patch for another table")
        if p.offset < 0 or p.offset + len(p.data) > len(base):
            raise ValueError("patch outside table image")
        new[p.offset : p.offset + len(p.data)] = p.data
    per = records_per_chunk or max(1, MAX_WRITE_PAYLOAD // record_size)
    chunk = per * record_size
    plan = WritePlan(table, record_size)
    for start in range(0, len(base), chunk):
        b, n = base[start : start + chunk], bytes(new[start : start + chunk])
        if granularity == "table" or b != n:
            plan.writes.append(ChunkWrite(table, start // record_size, 0, b, n))
    return plan
