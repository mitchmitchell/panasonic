#!/usr/bin/env bash
# CI: install release binaries + systemd units, start sim stack, assert socket layout and credentials.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "ci-systemd-stack expects ubuntu (systemd); got ID=${ID:-unknown}" >&2
  exit 1
fi
if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" != "systemd" ]]; then
  echo "ci-systemd-stack requires systemd as PID 1 (ubuntu-latest GitHub Actions)" >&2
  exit 1
fi

log() { echo "ci-systemd-stack: $*"; }
on_fail() {
  log "FAILED — journalctl:"
  sudo journalctl -u kxprovd.service -u kxprov-gw.service -n 200 --no-pager || true
}
trap on_fail ERR

export PATH="${HOME}/.cargo/bin:/usr/local/cargo/bin:${PATH}"
cd "$root"
cargo build --release --locked -p kxprovd -p kxprov-gw -p kxprov

sudo install -Dm755 "$root/target/release/kxprovd" /usr/local/bin/kxprovd
sudo install -Dm755 "$root/target/release/kxprov-gw" /usr/local/bin/kxprov-gw
sudo install -Dm644 "$root/deploy/systemd/kxprovd.service" /etc/systemd/system/kxprovd.service
sudo install -Dm644 "$root/deploy/systemd/kxprov-gw.service" /etc/systemd/system/kxprov-gw.service
sudo install -Dm644 "$root/deploy/systemd/systemd-serial-device.md" \
  /usr/share/doc/kx-provision/systemd-serial-device.md

sudo groupadd -f kxprovision
if ! id kxprov-gw &>/dev/null; then
  sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
    --groups kxprovision kxprov-gw
fi
GW_UID="$(id -u kxprov-gw)"

sudo mkdir -p /etc/kx-provision/secrets /etc/kx-provision/tls \
  /var/lib/kx-provision/sim/{plans,backups,goliath} /var/lib/kx-provision/.epoch
sudo chmod 0750 /var/lib/kx-provision
sudo chmod 0700 /var/lib/kx-provision/.epoch

# Dummy secrets (not production values).
sudo bash -c 'echo -n "0000" > /etc/kx-provision/secrets/pbx.password'
sudo bash -c 'echo -n "test-gateway-secret" > /etc/kx-provision/secrets/gateway-daemon.bearer'
sudo chmod 600 /etc/kx-provision/secrets/pbx.password /etc/kx-provision/secrets/gateway-daemon.bearer

sudo tee /etc/kx-provision/secrets/mcp-tokens.toml >/dev/null <<'TOML'
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
sudo chmod 600 /etc/kx-provision/secrets/mcp-tokens.toml

if [[ ! -f /etc/kx-provision/tls/lan.crt ]]; then
  sudo openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/lan.key -out /tmp/lan.crt -days 1 -subj "/CN=localhost" 2>/dev/null
  sudo install -Dm600 /tmp/lan.key /etc/kx-provision/tls/lan.key
  sudo install -Dm644 /tmp/lan.crt /etc/kx-provision/tls/lan.crt
fi

# Admin hash (argon2) for gateway login store.
export KXPROV_RUN_DIR="/tmp/kxprov-ci-seed"
mkdir -p "$KXPROV_RUN_DIR/secrets"
(cd "$root" && cargo test -p kxprov-gw --features test-secret-skip seed_run_dir_gateway_secrets -- --exact --nocapture)
sudo install -Dm600 "$KXPROV_RUN_DIR/secrets/admin.hash" /etc/kx-provision/secrets/admin-password.hash

export KXPROV_RUN_DIR="/tmp/kxprov-ci-tokens"
mkdir -p "$KXPROV_RUN_DIR/data"
(cd "$root" && cargo test -p kxprovd --features test-util seed_run_dir_tokens -- --exact --nocapture)
sudo install -Dm600 "$KXPROV_RUN_DIR/data/tokens.json" /var/lib/kx-provision/tokens.json

sudo tee /etc/kx-provision/kxprovd.json >/dev/null <<JSON
{
  "data_dir": "/var/lib/kx-provision",
  "password_path": "/etc/kx-provision/secrets/pbx.password",
  "profile": "sim",
  "transport": "sim",
  "gateway_user": "kxprov-gw",
  "admin_uid": 0,
  "daemon_socket_group": "kxprovision"
}
JSON

sudo tee /etc/kx-provision/gateway.toml >/dev/null <<TOML
bind = "127.0.0.1:8443"
web_serve_socket = "/run/kx-provision-gw/web-serve.sock"
serve_socket_group = "kxprov-gw"
mcp_tailnet_bind = "127.0.0.1:8081"
mcp_tokens_path = "/etc/kx-provision/secrets/mcp-tokens.toml"
gateway_bearer_path = "/etc/kx-provision/secrets/gateway-daemon.bearer"
admin_password_path = "/etc/kx-provision/secrets/admin-password.hash"
daemon_socket_path = "/run/kx-provision/kxprovd.sock"
tls_cert_path = "/etc/kx-provision/tls/lan.crt"
tls_key_path = "/etc/kx-provision/tls/lan.key"

[web_tailnet]
trust_x_forwarded_for = false
serve_peer_uid = 0
TOML

# Patch units to use /usr/local/bin (CI layout).
sudo mkdir -p /etc/systemd/system/kxprovd.service.d /etc/systemd/system/kxprov-gw.service.d
sudo tee /etc/systemd/system/kxprovd.service.d/ci-paths.conf >/dev/null <<'INI'
[Service]
ExecStart=
ExecStart=/usr/local/bin/kxprovd --config /etc/kx-provision/kxprovd.json
INI
sudo tee /etc/systemd/system/kxprov-gw.service.d/ci-paths.conf >/dev/null <<'INI'
[Service]
ExecStart=
ExecStart=/usr/local/bin/kxprov-gw --config /etc/kx-provision/gateway.toml
INI

sudo systemctl daemon-reload
sudo systemd-analyze verify kxprovd.service kxprov-gw.service
sudo systemd-analyze security kxprovd.service kxprov-gw.service | tee /tmp/systemd-security.txt

sudo systemctl stop kxprov-gw.service 2>/dev/null || true
sudo systemctl stop kxprovd.service 2>/dev/null || true
sudo systemctl reset-failed kxprovd.service kxprov-gw.service 2>/dev/null || true
sudo rm -f /var/lib/kx-provision/sim/kxprovd.lock \
  /run/kx-provision/kxprovd.sock /run/kx-provision-gw/web-serve.sock

sudo systemctl start kxprovd.service
for _ in $(seq 1 300); do
  if [[ -S /run/kx-provision/kxprovd.sock ]]; then break; fi
  state=$(systemctl show -p ActiveState --value kxprovd.service)
  if [[ "$state" == "failed" || "$state" == "inactive" || "$state" == "dead" ]]; then
    log "kxprovd.service state=$state before socket bind"
    sudo systemctl status kxprovd.service --no-pager || true
    sudo journalctl -u kxprovd.service -n 80 --no-pager || true
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S /run/kx-provision/kxprovd.sock ]]; then
  log "kxprovd.sock missing (ActiveState=$(systemctl show -p ActiveState --value kxprovd.service))"
  ls -la /run/kx-provision 2>&1 || true
  sudo journalctl -u kxprovd.service -n 80 --no-pager || true
  exit 1
fi

run_prov_group="$(stat -c '%G' /run/kx-provision)"
run_prov_mode="$(stat -c '%a' /run/kx-provision)"
[[ "$run_prov_group" == "kxprovision" ]] || { log "/run/kx-provision group=$run_prov_group want kxprovision"; exit 1; }
[[ "$run_prov_mode" == "750" ]] || { log "/run/kx-provision mode=$run_prov_mode want 750"; exit 1; }
sudo -u kxprov-gw test -x /run/kx-provision \
  || { log "gateway cannot traverse /run/kx-provision"; exit 1; }

sock_group="$(stat -c '%G' /run/kx-provision/kxprovd.sock)"
sock_mode="$(stat -c '%a' /run/kx-provision/kxprovd.sock)"
[[ "$sock_group" == "kxprovision" ]] || { log "socket group=$sock_group want kxprovision"; exit 1; }
[[ "$sock_mode" == "660" ]] || { log "socket mode=$sock_mode want 660"; exit 1; }

sudo systemctl start kxprov-gw.service
for _ in $(seq 1 50); do
  if [[ -S /run/kx-provision-gw/web-serve.sock ]]; then break; fi
  sleep 0.1
done

systemctl is-active --quiet kxprovd.service
systemctl is-active --quiet kxprov-gw.service

GW_PID="$(systemctl show -p MainPID --value kxprov-gw.service)"
[[ "$GW_PID" != "0" ]] || { log "no kxprov-gw MainPID"; exit 1; }
sudo tr '\0' '\n' < "/proc/${GW_PID}/environ" | grep -q '^CREDENTIALS_DIRECTORY=' \
  || { log "LoadCredential did not set CREDENTIALS_DIRECTORY"; exit 1; }
CRED_DIR="$(sudo tr '\0' '\n' < "/proc/${GW_PID}/environ" | sed -n 's/^CREDENTIALS_DIRECTORY=//p')"
sudo test -r "${CRED_DIR}/gateway-daemon.bearer" -a -r "${CRED_DIR}/lan.key" \
  || { log "credential files missing under $CRED_DIR"; exit 1; }
cred_key_mode="$(sudo stat -c '%a' "${CRED_DIR}/lan.key")"
cred_key_uid="$(sudo stat -c '%u' "${CRED_DIR}/lan.key")"
[[ "$cred_key_uid" == "0" || "$cred_key_uid" == "$GW_UID" ]] \
  || { log "credential lan.key uid=$cred_key_uid want 0 or $GW_UID"; exit 1; }
case "$cred_key_mode" in
  400|440|600) ;;
  *) log "credential lan.key mode=$cred_key_mode want 400/440/600"; exit 1 ;;
esac
sudo -u kxprov-gw test -r "${CRED_DIR}/lan.key" \
  || { log "gateway cannot read LoadCredential lan.key"; exit 1; }

serve_sock_group="$(stat -c '%G' /run/kx-provision-gw/web-serve.sock)"
[[ "$serve_sock_group" == "kxprov-gw" ]] \
  || { log "web-serve.sock group=$serve_sock_group want kxprov-gw"; exit 1; }

run_dir_mode="$(stat -c '%a' /run/kx-provision-gw)"
[[ "$run_dir_mode" == "750" ]] || { log "gateway runtime mode=$run_dir_mode want 750"; exit 1; }

# Gateway user must reach the daemon socket (supplementary group + peer policy uid).
sudo -u kxprov-gw test -r /run/kx-provision/kxprovd.sock -a -w /run/kx-provision/kxprovd.sock

sudo systemctl stop kxprov-gw.service
sleep 0.5
[[ -S /run/kx-provision/kxprovd.sock ]] || { log "daemon socket removed when gateway stopped"; exit 1; }
[[ ! -e /run/kx-provision-gw/web-serve.sock ]] || [[ ! -S /run/kx-provision-gw/web-serve.sock ]] || true

sudo systemctl stop kxprovd.service
log "ok (security summary in /tmp/systemd-security.txt)"
