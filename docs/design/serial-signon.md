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

After XON, login sends the normal CR LF that is part of the sign-on flow. The wake is different: it is only for a line that stays silent.

1. Every sign-on starts with a DTR drop (250 ms) and rise (spec §2.2 amendment 3), even if the line isn't silent.
2. The client then waits `wake_interval_ms` (1.5 s) for XON.
3. If that fresh DTR edge brings no XON, it sends **one** unsolicited CR LF, then waits the normal reply timeout. It never sends another: an extra CR LF may count as an empty password attempt.

A transport that can't drive DTR (`Transport::cycle_dtr` returns `false`) never sends the wake. Confirming this on the real unit is tracked in #62.

## Login timeout trace

When login fails, `Client::login_trace` records:
- bytes received;
- whether XON arrived;
- whether DTR was cycled and the wake sent;
- DSR, CTS and DCD, where the port reports them.

kxprovd logs these as `login failed`. The trace holds no sent bytes, so the password is never logged.

## Port exclusivity

Before opening, kxprovd refuses the device if any other process holds it, found by a /proc fd scan like fuser. It then opens with TIOCEXCL and an exclusive flock (serialport `exclusive(true)`) and checks that exclusivity is in effect. The S5 PortManager lease replaces the pre-open scan; that is tracked in #63.

## Apply stays simulator-only

`run_apply` returns `ApplyError::NotSim` on any non-sim transport before it opens the port, whatever `gates.live_writes_approved` says. `crates/kxprovd/tests/signon_config.rs` covers this.

## Errors

A failed daemon job is logged as `job failed` with its job kind and error code. The gateway maps `transport` errors to `PbxTransport` and `protocol` errors to `PbxProtocol`, which the web UI shows in plain words instead of "Invalid input: daemon."
