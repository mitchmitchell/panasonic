# kx-provision — residual security risks

## Whole-`PROVISION_ROOT` restore (P4-R10, pending Architect)

Per-profile rollback detection uses monotonic epoch counters stored under
`/var/lib/kx-provision/.epoch/<profile>.counter`, plus a root-only
`.epoch/highest.counter`, separate from each profile’s `mode.json` and
`profile.json` in `sim/`, `test/`, and `prod/`. At runtime the effective highest epoch is the maximum of `highest.counter` (or
zero when that file is absent) and every per-profile counter file. Removing
`highest.counter` while per-profile counters remain fails closed to Production;
corrupt, unreadable, symlink, or rolled-back `highest.counter` values (below
the per-profile max) do the same. `set_operational` floors the next counter at
`max(last(profile), effective_highest) + 1`.

Restoring or deleting **only** a profile data directory together with its JSON
files is detected when the on-disk JSON counters disagree with the external
epoch file.

Restoring the **entire** `/var/lib/kx-provision` tree (including `.epoch/` and
all profile directories) from the same backup snapshot is **not** detected
today. That is an accepted residual risk until the Architect rules on stronger
anchoring (e.g. off-box epoch, TPM, or installer-held secret).

**Root-only residual risk:** an attacker with write access to the whole
provision root (including `.epoch/`) can still forge `highest.counter` or
per-profile counters upward; that only forces the next legitimate
`set_operational` to use a higher counter—it does not by itself downgrade mode.
Downgrade or stale snapshot replay is still blocked when on-disk JSON counters
fall below the effective highest derived from the counter files.

## Token store transient grace

While `tokens.json` is missing or unreadable JSON, the daemon may serve the last
successfully loaded snapshot for at most about two seconds **total** (including up
to three read retries in that window), then rejects bearer-authenticated access until
a valid reload succeeds. Synthetic Unix principals are unaffected.
