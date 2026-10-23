# kxprov-api

**Canonical shared API for `kxprovd` and the gateway (PR #4 owns this crate; PR #5 must match it byte-for-byte on types and protocol constants).**

- Unix-socket JSON protocol types (`RequestBody`, `ResponseResult`, …)
- Bearer auth shape: `RequestAuth { bearer }` — the daemon verifies secrets; gateways must not send bare token ids
- On-disk token schema: `TokensFile`, `TokenEntry`, `hash_bearer_secret`
- Rate-limit constants: `TOKEN_QUEUE_DEPTH_MAX`, `TOKEN_JOBS_PER_MINUTE`
- Production path constants and helpers: `DATA_DIR`, `DAEMON_SOCKET`, `TOKENS_JSON`, `MODE_COUNTER`, `SIM_PASSED_JSON`, `profile_data_dir`, `sim_passed_path`, … (`paths` module)
