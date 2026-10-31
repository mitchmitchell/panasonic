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

1. Every sign-on starts with a DTR drop (250 ms) and rise (spec §2.2 amendment 3), even if the line isn't silent. Input is flushed (tcflush TCIFLUSH) while DTR is still low, before the rise, so the `00` from the drop and any stale bytes are discarded but the XOFF/XON the PBX sends on the rise are kept, and the trace counts only this sign-on's bytes.
2. The client then waits `wake_interval_ms` (1.5 s) for XON.
3. If that fresh DTR edge brings no XON, it sends **one** unsolicited CR LF, then waits the normal reply timeout. It never sends another: an extra CR LF may count as an empty password attempt.

A transport that can't drive DTR (`Transport::cycle_dtr` returns `false`) never sends the wake. Confirming this on the real unit is tracked in #62.

## Login timeout trace

When login fails, `Client::login_trace` records:
- bytes received;
- whether XON arrived;
- whether DTR was cycled and the wake sent;
- DSR, CTS and DCD, each a `LineLevel`: `High`, `Low`, `ReadFailed` (the modem-line read returned an error) or `NotReported` (the transport doesn't report modem lines).

kxprovd logs these as `login failed`, with the error's variant name (`error_kind`) instead of its text. The trace holds no sent bytes, so the password is never logged.

## Port exclusivity

Every serial job opens the device through the S5 PortManager for that device path, one per process. The job first takes the programming lease, which pauses SMDR. The programming open then goes through `open_exclusive`: read-write, TIOCEXCL, and the exclusive flock (or, when SMDR holds the device, under SMDR's flock), with the termios applied and read back. A refused, timed-out or full lease queue fails the job with a `transport` error. The pre-open /proc scan is gone.

The shared port runs at 9600, so a serial open fails if `link_baud` is set to anything else.

When the job ends, the device sends BYE (and end-binary first if needed), drops DTR, flushes input and restores 9600, and only then releases the lease, so SMDR resumes on a line holding no programming bytes.

## Apply stays simulator-only

`run_apply` returns `ApplyError::NotSim` on any non-sim transport before it opens the port, whatever `gates.live_writes_approved` says. `crates/kxprovd/tests/signon_config.rs` covers this.

## Errors

A failed daemon job is logged as `job failed` with its job kind and error code. The gateway maps `transport` errors to `PbxTransport` and `protocol` errors to `PbxProtocol`, which the web UI shows in plain words instead of "Invalid input: daemon."

## Redacted failure logs

A failed job logs `job failed` with the job id, job kind, error code and the message's byte count, never the message. A PBX error also logs `pbx error` with `error_kind` (the `kxtd1232::Error` variant name). Error text can carry raw reply bytes, so it is never logged; it goes only to the gateway, which maps it to fixed strings.

## DTR cycle is lease-gated

Only the leased device can cycle DTR, so every sign-on's cycle runs while SMDR is paused. The cycle sets B0 (DTR and RTS low), waits `DTR_LOW_PERIOD`, flushes input and restores 9600 with a readback, so bytes from before the rise are never read as a reply.

Sign-on and release share one hold, `DTR_LOW_PERIOD` = 300 ms. That is the release hold the read-path spec records as supported (read-path-spec-v1 §3 step 3, PR #36). #57's separate 250 ms sign-on hold is gone.

If the input flush fails, the cycle returns `DtrError::Flush` without restoring the speed, so the line stays at B0 with DTR low. Sign-on fails with `LinkDown`. A failed release leaves the line hung up until the next open, which re-applies 9600.

## Modem lines are not reported on serial yet

The leased device has no safe TIOCMGET (the workspace forbids `unsafe`), so DSR, CTS and DCD read `NotReported` in the login trace. Tracked in https://github.com/mitchmitchell/panasonic/issues/69.
