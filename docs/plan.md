# Phase A plan (simulator only, on the box)

Source: Architect's design v2.1 §10 and Reverse Engineer's library handoff. No PBX, Scarlet
or serial contact. Every PR goes through the usual gates.

- **A0 (this PR):** prototypes PA/PB/PC and the queue model; results in `docs/prototypes.md`.
- **A1 (started in this PR):** frame codec with command allow-list (read-only by default;
  0x0A/0x10 never allowed), never-written/editable table guards, sans-I/O login, blocking
  client, caller-ID/extension-name codecs (layouts HYPOTHESIS), `WritePlan` dry-run, CLI
  (`version`, `read`, `plan`) on the sim. Remaining A1: full read plan of all 75 tables,
  half-table refusal and 5x retry handling, `.DBH` model from the behavior spec (needs the
  write-path §6 chunk table and a corrected tag layout as a spec, not code), headers-only
  upload fixture from RE as a contract test, clock decode, `backup` CLI to a synthetic image.
- **Done in PR #1 review round:** writes/plans limited to 0x24/0x25 until G6/H8; tables >= 0x40 refused for writes (half-table rule); bounded busy wait (12 s) raising `BusyTimeoutError`; `UnackedWriteError` + `verify_block` re-read (never resend), sim faults `busy_forever`, `no_ack_applied`, `no_ack_dropped`. Still to do: read-side second-half guard needs per-table first-half record counts from RE (A1); real-time busy cadence in a paced sim (A2); journal-driven continue/rollback/LOCKED decision after verify (A5).
- **A2:** simulator faults: bounded busy run (128 ms cadence, 7 s default, past-bound),
  unacked write (applied / not applied, plus busy), timeout, link drop, wrong password,
  Another Terminal Connected, refusal; paced timing mode; RE's scrubbed fixtures.
- **A3:** `kxprovd`: single worker queue, lock file + flock/TIOCEXCL, backups (0600,
  round-trip parse), write-ahead journal, modes and gate flags (`live_writes_approved`
  default false), audit log, Unix-socket API, Goliath copy to a local target.
- **A4:** web UI (server-rendered, session login, CSRF, re-auth) and MCP (streamable HTTP,
  hashed scoped tokens: Tester read+plan, Communications read+plan+write), one process,
  shared API contract and scope tests.
- **A5:** sim write path: apply, per-block verify, auto-rollback, BUSY/unacked handling,
  crash recovery and journal replay, full fault suite, mutation check on guards; deploy
  files (systemd, udev, nftables, tailscale serve example), arm64 install check, memory/CPU
  budget test.
