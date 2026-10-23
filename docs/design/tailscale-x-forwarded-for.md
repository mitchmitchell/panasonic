# Tailscale Serve and `X-Forwarded-For`

Tailscale **Serve** forwards tailnet HTTPS to a **Unix socket** on the gateway host. Login rate limiting trusts `X-Forwarded-For` **only** on that Serve Unix listener when **SO_PEERCRED** matches configured `serve_peer_uid`, never on TCP (loopback LAN HTTPS, MCP, or any other TCP listener).

## Socket layout

Production defaults:

- Runtime directory: `/run/kx-provision` (mode **0750**, root-owned in production)
- Socket path: `/run/kx-provision/web-serve.sock`
- Mode: **0660** (umask tightened before `bind`, then explicit `chmod`)
- Owner: **root** (gateway should start as root)
- Group: **tailscale** (configurable via `serve_socket_group`; startup **fails** if the group name is missing)

Stale sockets are removed only after **`lstat`**: symlinks and non-socket paths are rejected.

`gateway.toml`:

```toml
web_serve_socket = "/run/kx-provision/web-serve.sock"
serve_socket_group = "tailscale"

[web_tailnet]
trust_x_forwarded_for = true
# Required — no default (stock tailscaled runs as root):
serve_peer_uid = 0
```

`serve_peer_uid` must be set whenever the Serve Unix listener is enabled. `4294967295` (`u32::MAX`) is rejected at startup.

On each accepted Unix connection the gateway reads **SO_PEERCRED** and sets `serve_proxy_trusted` only when the peer uid equals `serve_peer_uid`. Otherwise login limits use the synthetic loopback peer (`127.0.0.1:0`) and **ignore** client-supplied `X-Forwarded-For`.

## Identity vs XFF on the Unix path

When `serve_proxy_trusted` is true, login rate keys prefer (in order):

1. **`Tailscale-User-Login`** (set by tailscaled for tailnet Serve traffic)
2. **`X-Forwarded-For`** last hop (see below)
3. Synthetic loopback peer

SO_PEERCRED uid gates whether any of the above apply; without a matching peer uid, XFF and Tailscale identity headers are not trusted for login backoff.

## Does Serve append or replace `X-Forwarded-For`?

**Replace (set), not append.** In tailscaled’s Serve reverse proxy, `addProxyForwardedHeaders` assigns:

```go
r.Out.Header.Set("X-Forwarded-For", c.SrcAddr.Addr().String())
```

Source: [tailscale/tailscale `ipn/ipnlocal/serve.go` — `addProxyForwardedHeaders`](https://github.com/tailscale/tailscale/blob/main/ipn/ipnlocal/serve.go) (search for `addProxyForwardedHeaders`).

Tailscale maintainers have stated they do not forward client-supplied XFF chains to backends because of spoofing risk; a future “trusted proxy” mode would **append** only for explicitly trusted proxy IPs ([issue #19728](https://github.com/tailscale/tailscale/issues/19728)).

Because Serve **sets** a single address, the gateway’s “last hop” parsing matches the observed client IP. If upstream behavior ever changes to append, last-hop remains the Tailscale-appended client address **when** the header is trusted via SO_PEERCRED.

## TCP loopback spoofing

SO_PEERCRED on **TCP** loopback does not identify Tailscale Serve (peer uid is not meaningful). That is why Serve must use the Unix socket path above; direct TCP connections must not enable XFF trust.

## systemd

Ship `deploy/systemd/kxprov-gw.service` with:

```ini
RuntimeDirectory=kx-provision
RuntimeDirectoryMode=0750
```

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve) — identity headers (`Tailscale-User-Login`, …)
- Implementation: `crates/kxprov-gw/src/serve_peer.rs`, `crates/kxprov-web/src/login_client.rs`
