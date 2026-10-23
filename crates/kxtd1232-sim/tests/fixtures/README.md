# kxtd1232-sim fixtures

**All data here is synthetic**, derived from the KX-TD1232 **behavior spec** and table layout
(RE handoff / design v2.2). Nothing is copied from live serial captures, `.DBH` dumps, or a
real unit. Payload bytes are omitted or invented; passwords and ROM ids are placeholders.

| File | Role | Provenance |
|---|---|---|
| `exchanges.jsonl` | Login and binary-mode exchange **shape** (steps, frame hex, placeholders) | Behavior spec login and frame rules; hex patterns from the contract suite, not capture replay |
| `full-upload-headers.jsonl` | 288 write-frame **addresses** (`header_hex`) plus synthetic schedule fields | `kxtd1232::tables` read/write plan (table spec §1); monotonic synthetic `t_send_s` / `ack_latency_s` |
| `fault-timing.jsonl` | Simulator fault parameters for tests | Design v2.2 §6 / §9b defaults wired in `kxtd1232` / `kxtd1232-sim` |

Do not paste real sign-on banner text, site config, or capture timing into these files.
