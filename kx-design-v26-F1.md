# kx-provision design v2.6 — F1 (A3)

Reference copy for agents; authoritative requirements for mode, approvals, and apply gates.

## Mode and profile

- **Operational mode** (`Testing` | `Production`) is stored in signed `mode.json` and exposed in daemon status.
- **Testing** is valid only when the daemon **profile** is `Test`. On any other profile, a `testing` mode file is ignored (effective **Production**) with audit + alert.
- **Test** profile + **Testing** mode: apply does **not** require a prior approval; all other gates (LOCKED, backup-before-write, diff re-verify, rate limits on submit, etc.) still apply.
- **Prod** profile: **every** apply requires a consumed approval, regardless of `mode.json`.

## mode.json

- Path: `{data_dir}/mode.json`.
- Payload fields: `mode`, `counter`, `signature` (hex ed25519 over canonical message).
- **Fail closed to Production** on: missing file, corrupt JSON, bad signature, counter rollback (≤ last committed counter).
- Each failure: append **audit** record + emit **alert** (tracing warn); effective mode = Production.

## kxprov mode set

- CLI writes via daemon `set_mode` on the **root admin** Unix socket peer only.
- New mode file must be signed by a **pinned ed25519 public key** (`mode-signers.json` in data dir).
- Counter must strictly increase.

## submit_approval (socket)

- Replaces admin mint / web approval URL.
- Caller token must have **Approve** scope only (Approve sufficient; not Write).
- Plan must exist; `diff_hash` must match stored plan.
- **requester ≠ approver**: plan `creator_token` must differ from approver token id.
- Single-use approval, **10 min TTL**, bound to `(plan_id, diff_hash, profile)`.
- Rate limit per approver token: **5 / hour**, **20 / day**.

## Apply

- Before consume/execute: read live table base from PBX/sim, recompute **DiffHash** from stored plan writes + live base bytes; refuse if ≠ stored/`params` hash.
