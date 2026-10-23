# Tailscale Serve and `X-Forwarded-For`

Tailscale **Serve** forwards tailnet HTTPS to a **Unix socket** on the gateway host. Login rate limiting trusts `X-Forwarded-For` **only** on that Serve Unix listener when **SO_PEERCRED** matches configured `serve_peer_uid`, never on TCP (loopback LAN HTTPS, MCP, or any other TCP listener).

## Socket layout

Production defaults:

- Gateway runtime directory: `/run/kx-provision-gw` (mode **0750**, owned by **`kxprov-gw`** via systemd `RuntimeDirectory=kx-provision-gw`)
- Serve socket path: `/run/kx-provision-gw/web-serve.sock`
- Daemon socket (separate dir): `/run/kx-provision/kxprovd.sock` on **`RuntimeDirectory=kx-provision`** (daemon unit); stopping the gateway does not remove the daemon socket.
- Mode: **0660** (umask tightened before `bind`, then explicit `chmod`)
- Group on Serve socket: **`tailscale`** (configurable via `serve_socket_group`; startup **fails** if the group name is missing). Gateway user is in `SupplementaryGroups=kxprovision` to reach `kxprovd.sock` (group **`kxprovision`** on the daemon socket).

Stale sockets are removed only after **`lstat`**: symlinks and non-socket paths are rejected.

`gateway.toml`:

```toml
web_serve_socket = "/run/kx-provision-gw/web-serve.sock"
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

Ship `deploy/systemd/kxprov-gw.service`: runs as **`User=kxprov-gw`**, `RuntimeDirectory=kx-provision` / `RuntimeDirectoryMode=0750`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` for HTTPS `:443`, and hardening (`ProtectSystem=strict`, `ReadWritePaths=/run/kx-provision`, …). Root-only **`kxprov sim-mark`** stays in the CLI, not the gateway.

Runtime directory checks use **`symlink_metadata`** on `/run/kx-provision` (reject symlinks; verify mode `0750` and owner uid matches the gateway process).

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve) — identity headers (`Tailscale-User-Login`, …)
- Implementation: `crates/kxprov-gw/src/serve_peer.rs`, `crates/kxprov-web/src/login_client.rs`
