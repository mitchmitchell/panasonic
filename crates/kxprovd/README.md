# kxprovd

Single serial owner for kx-provision (design v2.6 F1): signed **mode.json** (fail-closed Production),
**submit_approval** on the socket (Approve scope, rate limits), profile-tied testing mode, live
DiffHash re-verify on apply. One-worker queue, flock lock, synthetic backups (keep **20**),
journal replay, immutable token-bound plans, SO_PEERCRED + token scope, persisted LOCKED
(`kxprov unlock` / `kxprov mode set`).
`.DBH` header bytes 0x1E–0xFF are read at runtime from the pre-write backup or the sim upload (never embedded); refused without either.
Simulator **apply** runs after approval with per-block read-back; production apply stays A5.
LOCKED alerts are held until 08:00 America/Chicago. Optional TOTP for admin re-auth (A4).
