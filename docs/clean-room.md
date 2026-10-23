# Clean-room rules for this repo

- Never commit real captures, `EMPTY.DBH` or any unit backup. Fixtures are synthetic (see
  `crates/kxtd1232/tests/fixtures/README.md`).
- **DBH header block 0x1E-0xFF** (design v2.4 §15): never embed these bytes in code or
  fixtures. A DBH writer (later phase; A1 has none) must copy the header from the unit's
  pre-write backup at runtime. If there is no backup, it refuses to write and gives a
  clear error. Tests use a synthetic placeholder header.
- `crates/kxtd1232/tests/no_vendor_header.rs` enforces the rule. It fails on binary files,
  DBH images, runs of 64 or more varying byte literals, or hex strings of 128 or more digits.
