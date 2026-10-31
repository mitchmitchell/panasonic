# Serial transport: sign-on file, wake, and the apply guard

## `signon_path` (kxprovd.json)

`transport: "serial"` needs `signon_path`, which points at a private JSON file holding the PBX's real sign-on text:

```json
{"banner": "<BANNER>", "password_prompt": "<PROMPT>", "mode_start": "<MODE_START>", "in_use": "<IN_USE>"}
```

- The daemon refuses to start if the file is missing, is readable by group or others (it must be `0600`), is not owned by the daemon user, has an empty `password_prompt`/`mode_start`/`in_use`, or has unknown keys.
- The real strings never go in this repo (clean room, decision 74). Tests and the simulator use placeholders.
- `transport: "sim"` without `signon_path` keeps the library placeholders that the simulator speaks.

## CR LF wake

Login normally sends CR LF after the PBX's XON (DTR edge). If nothing arrives for `wake_interval_ms` (1.5 s) before the password prompt, the client sends an unsolicited CR LF, at most `wake_attempts` (3) times, and then waits the normal reply timeout. Both values are defaults in `kxtd1232::Timing`.

## Apply stays simulator-only

`run_apply` returns `ApplyError::NotSim` on any non-sim transport before it opens the port, whatever `gates.live_writes_approved` says. `crates/kxprovd/tests/signon_config.rs` covers this.

## Errors

A failed daemon job is logged as `job failed` with its job kind and error code. The gateway maps `transport` errors to `PbxTransport` and `protocol` errors to `PbxProtocol`, which the web UI shows in plain words instead of "Invalid input: daemon."
