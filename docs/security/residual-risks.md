# kx-provision — residual security risks

## Whole-`PROVISION_ROOT` restore (P4-R10, pending Architect)

Per-profile rollback detection uses monotonic epoch counters stored under
`/var/lib/kx-provision/.epoch/<profile>.counter`, separate from each profile’s
`mode.json` and `profile.json` in `sim/`, `test/`, and `prod/`.

Restoring or deleting **only** a profile data directory together with its JSON
files is detected when the on-disk JSON counters disagree with the external
epoch file.

Restoring the **entire** `/var/lib/kx-provision` tree (including `.epoch/` and
all profile directories) from the same backup snapshot is **not** detected
today. That is an accepted residual risk until the Architect rules on stronger
anchoring (e.g. off-box epoch, TPM, or installer-held secret).

## Token store transient grace

While `tokens.json` is missing or unreadable JSON, the daemon may serve the last
successfully loaded snapshot for at most about two seconds **total** (including up
to three read retries in that window), then rejects bearer-authenticated access until
a valid reload succeeds. Synthetic Unix principals are unaffected.
