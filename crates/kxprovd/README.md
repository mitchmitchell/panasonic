# kxprovd (stub, Phase A3)
The single serial owner: one-worker job queue, flock + TIOCEXCL, backups, journal, modes,
gates, audit, Goliath copy, Unix-socket API. Current-thread tokio; `tokio-serial` behind the
`kxtd1232::Transport` trait. Not a workspace member yet. See design v2.2 §2, §9, §9a, §9b.
