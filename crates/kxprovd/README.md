# kxprovd

Single serial owner for kx-provision (design v2.7 F1): unsigned **mode.json** + **profile.json**
(fail-closed Production), root **set_mode** while idle, **submit_approval** with plan id or 8-hex
prefix, profile-tied testing mode, live
DiffHash re-verify on apply. One-worker queue, flock lock, synthetic backups (keep **20**),
journal replay, immutable token-bound plans, SO_PEERCRED + token scope, persisted LOCKED
(`kxprov unlock` / `kxprov mode set`).
`.DBH` header bytes 0x1E–0xFF are read at runtime from the pre-write backup or the sim upload (never embedded); refused without either.
Simulator **apply** runs after approval with per-block read-back; production apply stays A5.
LOCKED alerts are held until 08:00 America/Chicago. Optional TOTP for admin re-auth (A4).
