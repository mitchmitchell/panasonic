#!/usr/bin/env bash
# Local A4 stack: real kxprovd + kxprov-gw (sim profile).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run_dir="${KXPROV_RUN_DIR:-$root/.run/a4}"
data_dir="$run_dir/data"
etc_dir="$run_dir/etc"
secrets_dir="$run_dir/secrets"
tls_dir="$run_dir/tls"
mkdir -p "$data_dir"/{plans,backups,goliath,.epoch} "$etc_dir" "$secrets_dir" "$tls_dir"
chmod 0750 "$run_dir"

uid="$(id -u)"
gid="$(id -g)"
# Recover from prior runs that root-owned gateway secret seeds.
if [[ -d "$secrets_dir" ]]; then
  sudo chown -R "$uid:$gid" "$secrets_dir" 2>/dev/null || chown -R "$uid:$gid" "$secrets_dir"
fi
bin_dir="$root/target/debug"

cargo build -p kxprovd --features test-util -q
cargo build -p kxprov-gw --features test-secret-skip -q

export KXPROV_RUN_DIR="$run_dir"
cargo test -p kxprovd --features test-util seed_run_dir_tokens -- --exact --nocapture >/dev/null
cargo test -p kxprov-gw --features test-secret-skip seed_run_dir_gateway_secrets -- --exact --nocapture >/dev/null

printf '%s\n' 'test-gateway-secret' >"$secrets_dir/gateway-daemon.bearer"
chmod 600 "$secrets_dir/gateway-daemon.bearer"

cat >"$secrets_dir/mcp-tokens.toml" <<'TOML'
[[tokens]]
id = "approver"
name = "Approver"
role = "approver"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
[[tokens]]
id = "tester"
name = "Tester"
role = "tester"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
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
  "admin_uid": $((uid + 1)),
  "daemon_socket_group": ""
}
JSON

cat >"$etc_dir/gateway.toml" <<TOML
bind = "127.0.0.1:8443"
web_serve_socket = "$run_dir/web-serve.sock"
serve_socket_group = ""
mcp_tailnet_bind = "127.0.0.1:8081"
mcp_tokens_path = "$secrets_dir/mcp-tokens.toml"
gateway_bearer_path = "$secrets_dir/gateway-daemon.bearer"
admin_password_path = "$secrets_dir/admin.hash"
daemon_socket_path = "$run_dir/kxprovd.sock"
tls_cert_path = "$tls_dir/lan.crt"
tls_key_path = "$tls_dir/lan.key"

[web_tailnet]
trust_x_forwarded_for = true
serve_peer_uid = $uid
TOML
# Local smoke hits the Serve Unix socket directly (no tailscaled required).

chmod 600 "$data_dir/tokens.json" 2>/dev/null || true

export KXPROV_DAEMON_CONFIG="$etc_dir/kxprovd.json"
# Debug gateway (`test-secret-skip`) only; release builds ignore this env var.
export KXPROV_SKIP_SECRET_FILE_CHECKS=1

stop_stack() {
  if [[ -f "$run_dir/kxprov-gw.pid" ]]; then
    kill "$(cat "$run_dir/kxprov-gw.pid")" 2>/dev/null || true
    rm -f "$run_dir/kxprov-gw.pid"
  fi
  if [[ -f "$run_dir/kxprovd.pid" ]]; then
    kill "$(cat "$run_dir/kxprovd.pid")" 2>/dev/null || true
    rm -f "$run_dir/kxprovd.pid"
  fi
}

start_kxprovd() {
  if [[ -f "$run_dir/kxprovd.pid" ]] && kill -0 "$(cat "$run_dir/kxprovd.pid")" 2>/dev/null; then
    echo "run-a4: kxprovd already running (pid $(cat "$run_dir/kxprovd.pid"))" >&2
    return 0
  fi
  rm -f "$run_dir/kxprovd.pid" "$run_dir/kxprovd.sock"
  env KXPROV_DAEMON_CONFIG="$KXPROV_DAEMON_CONFIG" "$bin_dir/kxprovd" &
  echo $! | tee "$run_dir/kxprovd.pid" >/dev/null
}

wait_for_socket() {
  for _ in $(seq 1 100); do
    [[ -S "$run_dir/kxprovd.sock" ]] && return 0
    sleep 0.05
  done
  echo "run-a4: daemon socket did not appear" >&2
  return 1
}

start_kxprovd
wait_for_socket

if [[ "${1:-}" == "smoke" ]]; then
  trap stop_stack EXIT
  "$bin_dir/kxprov-gw" --config "$etc_dir/gateway.toml" &
  echo $! >"$run_dir/kxprov-gw.pid"
  for _ in $(seq 1 100); do
    if curl -sf --unix-socket "$run_dir/web-serve.sock" -H "Host: 127.0.0.1:80" -o /dev/null "http://127.0.0.1/login"; then
      break
    fi
    sleep 0.05
  done
  curl -sf --unix-socket "$run_dir/web-serve.sock" -H "Host: 127.0.0.1:80" -o /dev/null "http://127.0.0.1/login"
  curl -ksf -o /dev/null "https://127.0.0.1:8443/login"
  status_code="$(curl -s --unix-socket "$run_dir/web-serve.sock" -H "Host: 127.0.0.1:80" -o /dev/null -w '%{http_code}' "http://127.0.0.1/status")"
  [[ "$status_code" == "303" || "$status_code" == "302" || "$status_code" == "307" ]]
  KXPROV_RUN_DIR="$run_dir" cargo test -p kxprovd --features test-util a4_smoke_busy_trigger -- --exact --nocapture
  echo "run-a4: smoke ok" >&2
  exit 0
fi

exec "$bin_dir/kxprov-gw" --config "$etc_dir/gateway.toml"
