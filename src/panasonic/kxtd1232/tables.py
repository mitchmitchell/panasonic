"""Table constants from the behavior spec (handoff §1.13, §5)."""

from __future__ import annotations

from .frame import NotAllowedError

# Table IDs DSHSOMT never writes during a full upload. The encoder refuses them.
NEVER_WRITTEN = frozenset({0x0B, 0x17, 0x32, 0x33, 0x3C, 0x42, 0x48, 0x4A, 0x4B})


def _ranges(*spans: tuple[int, int]) -> tuple[int, ...]:
    out: list[int] = []
    for a, b in spans:
        out.extend(range(a, b + 1))
    return tuple(out)


# The 75 tables of a full upload, in strictly ascending order.
UPLOAD_TABLES = _ranges(
    (0x01, 0x0A), (0x0C, 0x16), (0x18, 0x31), (0x34, 0x3B), (0x3D, 0x41),
    (0x43, 0x47), (0x49, 0x49), (0x4C, 0x52), (0xA7, 0xA7), (0xC3, 0xC3),
)  # fmt: skip

# Tables >= 0x40 exist only in their first half on a single-cabinet unit.
HALF_TABLE_THRESHOLD = 0x40

# Writes are allowed only to the caller-ID tables, the only ones written standalone on
# real hardware. Widening this (tag 5 extension names first) needs gate G6 closed by
# hardware test H8 (design §3a, handoff §3). Reads and decodes of every table stay allowed.
EDITABLE_TABLES = frozenset({0x24, 0x25})

CID_NUMBERS = 0x24
CID_NAMES = 0x25
EXT_NAMES = 0x05


def check_writable(table: int) -> None:
    if table in NEVER_WRITTEN:
        raise NotAllowedError(f"table {table:#04x} is never written")
    if table >= HALF_TABLE_THRESHOLD:
        # Only the first half of tables >= 0x40 exists on a single-cabinet unit; the
        # second half must never be written. Neither half is editable before G6.
        raise NotAllowedError(f"table {table:#04x} >= 0x40 is not writable (half-table rule)")
    if table not in EDITABLE_TABLES:
        raise NotAllowedError(f"table {table:#04x} is not on the editable list")
