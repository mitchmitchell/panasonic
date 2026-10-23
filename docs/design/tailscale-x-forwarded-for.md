# Tailscale Serve and `X-Forwarded-For`

When the gateway web listener is bound to loopback and exposed with **Tailscale Serve**, the TCP connection to the gateway process appears from `127.0.0.1`. Login rate limiting trusts `X-Forwarded-For` **only** on listeners configured with `web_https.trust_x_forwarded_for = true` (or the matching `[web_https]` table in `gateway.toml`).

## Does Serve append?

No. Tailscale Serve **replaces** the incoming `X-Forwarded-For` header with the client address it observed (`Header.Set` in Tailscale’s `ipn/ipnlocal/serve.go`). A client cannot prepend spoofed hops that Serve will preserve.

Example after Serve:

```text
X-Forwarded-For: 203.0.113.5
                 ^ client Tailscale observed (trust this single value)
```

The gateway’s `client_ip` helper (`kxprov-web`) uses the **first** non-empty hop when that listener flag is set (Serve sets a single hop).

## Loopback spoofing (non-Serve)

Any process on the same host can connect to a loopback listener and send an arbitrary `X-Forwarded-For` first hop. The gateway does **not** treat that value as proof of client identity unless the request arrived through a trusted edge (for example Tailscale Serve) that overwrites the header. Prefer binding site LAN HTTPS on the real site IP when loopback XFF trust is insufficient.

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve)
- Gateway implementation: `crates/kxprov-web/src/lib.rs` (`client_ip`)
