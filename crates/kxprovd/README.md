# kxprovd

Single serial owner for kx-provision (design v2.4): one-worker queue, flock lock, synthetic
backups (keep **20** by default), journal replay, **per-plan approvals**, immutable token-bound
plans, SO_PEERCRED + token scope enforcement, persisted LOCKED (cleared via `kxprov unlock`).
`.DBH` header bytes 0x1E–0xFF are read at runtime from the pre-write backup (never embedded).
Simulator **apply** runs after approval with per-block read-back; production apply stays A5.
LOCKED alerts are held until 08:00 America/Chicago. Optional TOTP for admin re-auth (A4).
