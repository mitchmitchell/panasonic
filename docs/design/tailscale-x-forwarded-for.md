# Tailscale Serve and `X-Forwarded-For`

Tailscale **Serve** forwards tailnet HTTPS to a **Unix socket** on the gateway host. Login rate limiting trusts `X-Forwarded-For` **only** on that Serve Unix listener, never on TCP (loopback LAN HTTPS, MCP, or any other TCP listener).

## Socket layout

Production defaults:

- Path: `/run/kx-provision/web-serve.sock`
- Mode: `0660`
- Owner: `root` (gateway should start as root)
- Group: `tailscale` (configurable via `serve_socket_group`)

`gateway.toml`:

```toml
web_serve_socket = "/run/kx-provision/web-serve.sock"
serve_socket_group = "tailscale"

[web_tailnet]
trust_x_forwarded_for = true
# Tailscale Serve runs as root by default:
serve_peer_uid = 0
```

`serve_peer_uid = 4294967295` (`u32::MAX`, Linux “invalid uid”) is rejected at startup.

On each accepted Unix connection the gateway reads **SO_PEERCRED** and sets `serve_proxy_trusted` only when the peer uid equals `serve_peer_uid`. Otherwise login limits use the synthetic loopback peer (`127.0.0.1:0`) and ignore client-supplied `X-Forwarded-For`.

## Tailscale Serve command

Expose the site admin UI on the tailnet (HTTPS terminates at Serve; gateway sees plain HTTP on the Unix socket):

```bash
tailscale serve --bg --https=443 \
  http://unix:/run/kx-provision/web-serve.sock
```

Or with an explicit hostname on your tailnet:

```bash
tailscale serve --bg --https=443 \
  --set-path=/ \
  http://unix:/run/kx-provision/web-serve.sock
```

Use `tailscale serve status` to confirm the handler. Set `serve_hostname` in `gateway.toml` to that MagicDNS name so Host / Origin allowlists match.

## Does Serve append?

No. Tailscale Serve **replaces** the incoming `X-Forwarded-For` header with the client address it observed. The gateway uses the **last** non-empty hop when `serve_proxy_trusted` is true.

## TCP loopback spoofing

SO_PEERCRED on **TCP** loopback does not identify Tailscale Serve (peer uid is not meaningful). That is why Serve must use the Unix socket path above; direct TCP connections must not enable XFF trust.

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve)
- Implementation: `crates/kxprov-gw/src/serve_peer.rs`, `crates/kxprov-web/src/login_client.rs`
