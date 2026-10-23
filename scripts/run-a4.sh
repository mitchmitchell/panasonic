#!/usr/bin/env bash
# Local A4 stack: real kxprovd + kxprov-gw (sim profile).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run_dir="${KXPROV_RUN_DIR:-$root/.run/a4}"
data_dir="$run_dir/data"
etc_dir="$run_dir/etc"
secrets_dir="$run_dir/secrets"
tls_dir="$run_dir/tls"
mkdir -p "$data_dir"/{plans,backups,goliath} "$etc_dir" "$secrets_dir" "$tls_dir"

uid="$(id -u)"

cargo build --release -p kxprovd -p kxprov-gw -q

export KXPROV_RUN_DIR="$run_dir"
cargo test -p kxprovd --features test-util seed_run_dir_tokens -- --exact --nocapture >/dev/null
cargo test -p kxprov-gw --features test-secret-skip seed_run_dir_gateway_secrets -- --exact --nocapture >/dev/null

printf '%s\n' 'test-gateway-secret' >"$secrets_dir/gateway-daemon.bearer"
chmod 600 "$secrets_dir/gateway-daemon.bearer"

cat >"$secrets_dir/mcp-tokens.toml" <<'TOML'
[[tokens]]
id = "tester"
name = "Tester"
role = "tester"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
TOML

if [[ ! -f "$tls_dir/lan.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tls_dir/lan.key" \
    -out "$tls_dir/lan.crt" -days 365 -subj "/CN=localhost" 2>/dev/null
fi

printf '%s\n' '0000' >"$secrets_dir/pbx.password"

cat >"$etc_dir/kxprovd.json" <<JSON
{
  "data_dir": "$data_dir",
  "socket_path": "$run_dir/kxprovd.sock",
  "tokens_path": "$data_dir/tokens.json",
  "password_path": "$secrets_dir/pbx.password",
  "profile": "sim",
  "transport": "sim",
  "goliath_target": "$data_dir/goliath",
  "gateway_uid": $uid,
  "admin_uid": 0
}
JSON

cat >"$etc_dir/gateway.toml" <<TOML
bind = "127.0.0.1:8443"
web_tailnet_bind = "127.0.0.1:8080"
mcp_public_bind = "127.0.0.1:8444"
mcp_tokens_path = "$secrets_dir/mcp-tokens.toml"
gateway_bearer_path = "$secrets_dir/gateway-daemon.bearer"
admin_password_path = "$secrets_dir/admin.hash"
daemon_socket_path = "$run_dir/kxprovd.sock"
tls_cert_path = "$tls_dir/lan.crt"
tls_key_path = "$tls_dir/lan.key"
TOML

sudo chown root:root "$data_dir/tokens.json"
sudo chmod 600 "$data_dir/tokens.json"

export KXPROV_DAEMON_CONFIG="$etc_dir/kxprovd.json"
export KXPROV_SKIP_SECRET_FILE_CHECKS=1

if [[ -f "$run_dir/kxprovd.pid" ]] && kill -0 "$(cat "$run_dir/kxprovd.pid")" 2>/dev/null; then
  echo "run-a4: kxprovd already running (pid $(cat "$run_dir/kxprovd.pid"))" >&2
else
  sudo -E env KXPROV_DAEMON_CONFIG="$KXPROV_DAEMON_CONFIG" \
    "$root/target/release/kxprovd" &
  echo $! | tee "$run_dir/kxprovd.pid" >/dev/null
fi

for _ in $(seq 1 100); do
  [[ -S "$run_dir/kxprovd.sock" ]] && break
  sleep 0.05
done
[[ -S "$run_dir/kxprovd.sock" ]] || {
  echo "run-a4: daemon socket did not appear" >&2
  exit 1
}

exec "$root/target/release/kxprov-gw" --config "$etc_dir/gateway.toml"
