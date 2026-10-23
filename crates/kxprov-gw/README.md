# kxprov-gw

One process hosting the web UI and MCP listeners.

## Listen addresses

| Listener | Default |
|----------|---------|
| Web (tailnet / plain HTTP) | `127.0.0.1:8080` |
| Web (HTTPS, §5a) | `127.0.0.1:443`, plus `{lan_ip}:443` when configured |
| MCP (public) | `127.0.0.1:8444` |

HTTPS never binds to `0.0.0.0`. `lan_ip` and `bind` / `--bind` / `KXPROV_BIND` are rejected at startup if the address is unspecified (`0.0.0.0` or `::`). Loopback is always included when using the §5a bind list.

### Site LAN IP (`lan_ip`)

Set the PBX/site LAN address explicitly — there is **no default LAN IP**.

- Config file: `lan_ip = "10.0.0.5"`
- Environment: `KXPROV_LAN_IP=10.0.0.5`

If `lan_ip` is unset and `--bind` / `bind` is not overriding addresses, the gateway listens for web HTTPS on **loopback only** and logs a warning that `lan_ip` / `KXPROV_LAN_IP` should be set for LAN access.

Override all HTTPS bind addresses (for example in tests): `--bind 127.0.0.1:8443` or config key `bind`.

Other useful environment variables: `KXPROV_CONFIG`, `KXPROV_BIND`, `KXPROV_MCP_TOKENS`, `KXPROV_DAEMON_SOCKET` (default `/run/kx-provision/kxprovd.sock`), `KXPROV_DAEMON_TOKENS` (default `/var/lib/kx-provision/tokens.json`).
