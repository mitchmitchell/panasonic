# The Python prototype (A0)

The Python package in PR #1 (branch `a0-a1-library-sim`) was the **A0 prototype**. It was used to
check the protocol model, the write guards and the simulator against the clean-room table spec.
It will not ship.

The production app is all Rust (decision 2026-10-22, design-DRAFT v2.2). Phase A1 starts with
this cargo workspace. The Rust tests port the applicable #1 tests, plus fixes from the #1 review:

- a garbled write ack counts as unacked
- replies must match the request cmd
- range checks
- a line-length cap on login text
- typed errors

Not ported: `test_prototypes.py`, because it only covers Python prototype scaffolding.

All fixtures are synthetic: headers and timing only, copied from the RE vault's synthetic set.
No real captures and no EMPTY.DBH content are ever committed.
