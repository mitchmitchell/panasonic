# kxprovd

Single serial owner for kx-provision (design v2.2/v2.3): one-worker job queue, flock process
lock, synthetic backups + journal replay, gate flags, immutable content-addressed plans,
single-use arms (plan id + diff hash, TTL), SO_PEERCRED scope enforcement, Goliath copy queue
(A3 uses a local directory target). Phase A3: simulator reads/plans/backups only; apply
execution is A5.
