# kxprov-gw

One process hosting the web UI and MCP listeners. Production runs as the dedicated **`kxprov-gw`** user (see `deploy/systemd/kxprov-gw.service`), not root. HTTPS on port 443 uses `CAP_NET_BIND_SERVICE`; Tailscale Serve connects to the Unix socket via the **`tailscale`** group; the daemon API socket uses the **`kxprovision`** supplementary group.

Root-only operations (for example **`kxprov sim-mark`**) stay in the `kxprov` CLI.

## Listen addresses

| Listener | Default |
|----------|---------|
| Web (Tailscale Serve / Unix HTTP) | `/run/kx-provision/web-serve.sock` (`0660`, group `tailscale`, owner `kxprov-gw`) |
| Web (HTTPS, §5a) | `127.0.0.1:443`, plus `{lan_ip}:443` when configured |
| MCP (tailnet / loopback) | `127.0.0.1:8081` |

HTTPS and MCP use **TCP only** and never trust client `X-Forwarded-For`. Serve-fronted admin HTTP uses the Unix socket; XFF is honored only when SO_PEERCRED matches **`[web_tailnet] serve_peer_uid`** (required at startup — typically root/`0` for stock `tailscaled`).

### Tailscale Serve

```bash
tailscale serve --bg --https=443 \
  http://unix:/run/kx-provision/web-serve.sock
```

See `docs/design/tailscale-x-forwarded-for.md` for trust rules and config keys (`web_serve_socket`, `serve_socket_group`, `serve_peer_uid`).

### Site LAN IP (`lan_ip`)

Set the PBX/site LAN address explicitly — there is **no default LAN IP**.

- Config file: `lan_ip = "10.0.0.5"`
- Environment: `KXPROV_LAN_IP=10.0.0.5`

If `lan_ip` is unset and `--bind` / `bind` is not overriding addresses, the gateway listens for web HTTPS on **loopback only** and logs a warning that `lan_ip` / `KXPROV_LAN_IP` should be set for LAN access.

Override all HTTPS bind addresses (for example in tests): `--bind 127.0.0.1:8443` or config key `bind`.

Other useful environment variables: `KXPROV_CONFIG`, `KXPROV_BIND`, `KXPROV_MCP_TOKENS`, `KXPROV_DAEMON_SOCKET` (default `/run/kx-provision/kxprovd.sock`), `KXPROV_DAEMON_TOKENS` (default `/var/lib/kx-provision/tokens.json`).
