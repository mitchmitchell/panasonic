# kxtd1232-sim fixtures (synthetic / scrubbed)

Clean-room only: addresses, timing, and frame headers. No real PBX payloads, passwords,
ROM ids, or capture bytes from the unit.

| File | Contents |
|---|---|
| `exchanges.jsonl` | Login and binary-mode exchange steps (hex/text placeholders) |
| `full-upload-headers.jsonl` | 288 write-frame headers + ack timing (no payload bytes) |
| `fault-timing.jsonl` | Simulator fault parameters (busy cadence, ack bounds) |

Copied from Reverse Engineer's vault set; same rules as `crates/kxtd1232/tests/fixtures/`.
