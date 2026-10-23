# Tailscale Serve and `X-Forwarded-For`

When the gateway web listener is bound to loopback and exposed with **Tailscale Serve**, the TCP connection to the gateway process appears from `127.0.0.1`. Login rate limiting therefore trusts `X-Forwarded-For` **only** when the peer address is loopback.

## Does Serve append?

Yes. Tailscale Serve acts as a reverse proxy: it **appends** the client’s Tailscale or public egress address to any `X-Forwarded-For` value the client already sent. The leftmost entries are earlier hops; the **rightmost** non-empty hop is the client Serve observed.

Example:

```text
X-Forwarded-For: 198.51.100.1, 203.0.113.5
                 ^ spoofable      ^ client seen by Serve (use this)
```

The gateway’s `client_ip` helper (`kxprov-web`) takes the **last** comma-separated hop when the peer is loopback.

## References

- [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve) (reverse proxy semantics)
- Gateway implementation: `crates/kxprov-web/src/lib.rs` (`client_ip`)
