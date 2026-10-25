# kxtd1232-sim fixtures

**All data is synthetic**, derived from the KX-TD1232 **behavior spec** and design v2.2 §6/§9b.
Nothing is copied from live captures or a real unit.

| File | Role | Provenance |
|---|---|---|
| `fault-timing.jsonl` | Simulator fault parameters used in tests | Design defaults + mandatory test timings |

Exchange steps and full-upload **headers** live under `crates/kxtd1232/tests/fixtures/` (shared
with the core contract tests). This crate references those paths in `tests/fixtures.rs` only.

Do not add duplicate copies of the core fixtures here.
