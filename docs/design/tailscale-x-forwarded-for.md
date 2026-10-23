# Tailscale Serve and `X-Forwarded-For`

When the gateway web listener is bound to loopback and exposed with **Tailscale Serve**, the TCP connection to the gateway process appears from `127.0.0.1`. Login rate limiting therefore trusts `X-Forwarded-For` **only** when the peer address is loopback.

## Does Serve append?

No. Tailscale Serve **replaces** the incoming `X-Forwarded-For` header with the client address it observed (`Header.Set` in Tailscale’s `ipn/ipnlocal/serve.go`). A client cannot prepend spoofed hops that Serve will preserve.

Example after Serve:

```text
X-Forwarded-For: 203.0.113.5
                 ^ client Tailscale observed (trust this single value)
```

The gateway’s `client_ip` helper (`kxprov-web`) uses the **first** non-empty hop when the peer is loopback (which is also the only hop Serve sets).

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve)
- Gateway implementation: `crates/kxprov-web/src/lib.rs` (`client_ip`)
