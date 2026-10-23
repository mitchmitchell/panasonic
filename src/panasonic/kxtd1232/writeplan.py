"""WritePlan: a dry-run list of chunk writes computed from a base image and edits.

Unchanged bytes inside a chunk are re-sent exactly as read (design §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .fields import FIELDS
from .frame import MAX_WRITE_PAYLOAD
from .tables import check_writable


class PlanError(ValueError):
    """A write plan cannot be built. Distinct from field-decode ``ValueError``s; carries
    the table and, for size failures, the chunk size in bytes."""

    def __init__(self, msg: str, table: int, chunk: int | None = None) -> None:
        super().__init__(msg)
        self.table, self.chunk = table, chunk


class Granularity(StrEnum):
    CHUNK = "chunk"  # only changed record groups (PC (a))
    TABLE = "table"  # the whole table (PC (b))


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
    granularity: Granularity | str = Granularity.CHUNK,
    records_per_chunk: int | None = None,
) -> WritePlan:
    """Build a dry-run plan. Raises PlanError for an unknown granularity, a bad record
    size, a patch that does not fit, or a chunk that would not fit one write frame."""
    try:
        granularity = Granularity(granularity)
    except ValueError as e:
        raise PlanError(f"unknown granularity {granularity!r}", table) from e
    if record_size <= 0 or record_size % 2:
        raise PlanError("record size must be a positive whole number of words", table)
    check_writable(table)
    new = bytearray(base)
    for p in patches:
        if p.table != table:
            raise PlanError("patch for another table", table)
        if p.offset < 0 or p.offset + len(p.data) > len(base):
            raise PlanError("patch outside table image", table)
        new[p.offset : p.offset + len(p.data)] = p.data
    per = records_per_chunk or max(1, MAX_WRITE_PAYLOAD // record_size)
    chunk = per * record_size
    if per <= 0 or chunk > MAX_WRITE_PAYLOAD:
        raise PlanError(
            f"chunk of {chunk} bytes exceeds {MAX_WRITE_PAYLOAD}-byte write limit", table, chunk
        )
    plan = WritePlan(table, record_size)
    for start in range(0, len(base), chunk):
        b, n = base[start : start + chunk], bytes(new[start : start + chunk])
        if granularity is Granularity.TABLE or b != n:
            plan.writes.append(ChunkWrite(table, start // record_size, 0, b, n))
    return plan
