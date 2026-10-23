# Tailscale Serve and `X-Forwarded-For`

When the gateway web listener is bound to loopback and exposed with **Tailscale Serve**, the TCP connection to the gateway process appears from `127.0.0.1`. Login rate limiting trusts `X-Forwarded-For` **only** on the plain HTTP tailnet listener (`web_tailnet_bind`), via `[web_tailnet] trust_x_forwarded_for = true` in `gateway.toml`. Direct TLS / LAN HTTPS (`web_https`) must **never** enable this flag.

Trust is **not** inferred from loopback alone. On Linux the gateway reads **SO_PEERCRED** on each tailnet TCP connection and sets `serve_proxy_trusted` only when the peer uid matches `[web_tailnet] serve_peer_uid` (default: the `tailscale` system user running `tailscaled`). Any other local process connecting to loopback keeps socket-peer rate limiting even if it sends a spoofed `X-Forwarded-For`.

Example production snippet:

```toml
[web_tailnet]
trust_x_forwarded_for = true
# optional; defaults to tailscale user uid
# serve_peer_uid = 997
```

Local `scripts/run-a4.sh` sets `serve_peer_uid` to the current user so curl-based smoke tests can exercise XFF trust without Tailscale Serve.

## Does Serve append?

No. Tailscale Serve **replaces** the incoming `X-Forwarded-For` header with the client address it observed (`Header.Set` in Tailscale’s `ipn/ipnlocal/serve.go`). A client cannot prepend spoofed hops that Serve will preserve.

Example after Serve:

```text
X-Forwarded-For: 203.0.113.5
                 ^ client Tailscale observed (trust this single value)
```

The gateway’s login rate limiter uses the **last** non-empty hop when the listener trusts XFF **and** `serve_proxy_trusted` is true for that connection.

## Loopback spoofing (non-Serve)

Any process on the same host can connect to a loopback listener and send an arbitrary `X-Forwarded-For` first hop. The gateway does **not** treat that value as proof of client identity unless the connection peer uid matches the configured Serve / `tailscaled` uid. Prefer binding site LAN HTTPS on the real site IP when loopback XFF trust is insufficient.

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve)
- Gateway: `crates/kxprov-gw/src/serve_peer.rs`, `crates/kxprov-web/src/login_client.rs`
