# kxtd1232-sim fixtures

**All bytes are synthetic**, derived from the KX-TD1232 **behavior spec** and design v2.2 §6/§9b.
No byte is copied from live captures or a real unit. The `sessions/` files keep only the frame
order, direction, type, length and relative timing of two read-only captures (see below).

| File | Role | Provenance |
|---|---|---|
| `fault-timing.jsonl` | Simulator fault parameters used in tests | Design defaults + mandatory test timings |
| `read-plan-headers.json` | The full 75-table read plan: 305 requests in send order (288 data frames + 17 end-of-table probes for tables >= 0x40), plus the 9 skipped ids. `{table, record, offset (word), length (payload bytes), expect}`. No payloads | Generated from `kxtd1232::tables::TABLES`; read chunking = write chunking (write-path §6, library-handoff rows 1.13/1.17, read-path spec §5). Matches the request order of both captures below, retries removed |
| `sessions/read-live-full-backup.jsonl` | Timing session of a full read-only backup: 760 frames, about 160 s | Derived from a 2026-10-18 read-only capture on the real unit |
| `sessions/read-fullbridge-download.jsonl` | Timing session of the download half of a full-database session: 770 frames, about 172 s | Derived from the 2026-10-18 bridge capture, cut at the first write |

### How `sessions/` was scrubbed

- Binary phase of the read path only. Sign-on text (banner, prompt, password), `BYE`, every write
  and upload frame and the `0A`/`10` end-of-upload frames are dropped entirely.
- Kept per frame: `t_ms` (ms since the first binary frame), `dir` (`host`/`pbx`), `type`, `len`.
- `frame` is synthetic. Host frames are the read-plan and probe headers from the spec. Every pbx
  frame is what `SimPbx` (`synthetic_db()`, `PLACEHOLDER_ROM_ID`) answers to that host frame, with
  the checksum computed over the synthetic bytes, so no checksum carries information about the
  original payload. Each synthetic reply was checked to have the same length and type as the
  observed one (all 1,530 frames match; the 85 end-of-table refusals land on the same requests).
- The repeated end-of-table probes (5 per table) are kept as they were sent, for timing.
- The empty caller-ID slots in tables 0x24/0x25 encode the same way in the synthetic database as
  the spec's empty encoding, so those frames are identical by construction, not by copying.

Exchange steps and full-upload **headers** live under `crates/kxtd1232/tests/fixtures/` (shared
with the core contract tests). This crate references those paths in `tests/fixtures.rs` only.

Do not add duplicate copies of the core fixtures here.
