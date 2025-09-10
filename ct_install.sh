#!/usr/bin/env bash
set -euo pipefail

# =======================
# Configurable defaults
# =======================
DOMAIN="${DOMAIN:-}"                 # set later (e.g., --domain barxperience.com)
API_KEY="${API_KEY:-}"               # required (or pass --api-key)
REDIRECT_URL="${REDIRECT_URL:-https://example.com}"
SERVER_USER="canary"
SERVER_DIR="/opt/canary-server"
BIN_PATH="/usr/local/bin/canary-server"
LOG_DIR="/var/log/canary"
LOG_FILE="${LOG_DIR}/canary_token.jsonl"
LISTEN_ADDR="127.0.0.1:8080"
ALLOW_CORS="true"
ALIAS_ROUTES="true"
BEHIND_PROXY="true"

# =======================
# Args
# =======================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --redirect-url) REDIRECT_URL="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --source-dir) SERVER_DIR="${2:-}"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${API_KEY}" ]]; then
  echo "ERROR: --api-key is required (or export API_KEY=...)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw ca-certificates debian-keyring debian-archive-keyring apt-transport-https

# -----------------------
# Install Caddy (repo)
# -----------------------
if ! command -v caddy >/dev/null 2>&1; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | tee /usr/share/keyrings/caddy-stable-archive-keyring.gpg >/dev/null
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -y && apt-get install -y caddy
fi

# -----------------------
# Install Go (for build)
# -----------------------
if ! command -v go >/dev/null 2>&1; then
  apt-get install -y golang-go
fi

# -----------------------
# User & directories
# -----------------------
id -u "${SERVER_USER}" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "${SERVER_USER}"
mkdir -p "${LOG_DIR}"
chown -R "${SERVER_USER}:${SERVER_USER}" "${LOG_DIR}"
chmod 755 "${LOG_DIR}"

# Ensure source dir exists (user can scp into it)
mkdir -p "${SERVER_DIR}"

# -----------------------
# Install server binary
# -----------------------
if [[ ! -x "${BIN_PATH}" ]]; then
  if [[ -f "${SERVER_DIR}/main.go" ]]; then
    echo "Building server from ${SERVER_DIR}/main.go ..."
    (cd "${SERVER_DIR}" && go build -buildvcs=false -o "${BIN_PATH}" .)
    chown "${SERVER_USER}:${SERVER_USER}" "${BIN_PATH}"
    chmod 755 "${BIN_PATH}"
  else
    cat <<EOF >&2
No server binary at ${BIN_PATH} and no ${SERVER_DIR}/main.go found.
Place your source at ${SERVER_DIR} (go.mod + main.go) OR copy a prebuilt binary to:
  ${BIN_PATH}
Then rerun this script.
EOF
    exit 1
  fi
fi

# -----------------------
# Systemd unit
# -----------------------
cat >/etc/systemd/system/canary-server.service <<UNIT
[Unit]
Description=Canary Token Server
After=network-online.target
Wants=network-online.target

[Service]
User=${SERVER_USER}
Group=${SERVER_USER}
ExecStart=${BIN_PATH} \
  --addr=${LISTEN_ADDR} \
  --api-key=${API_KEY} \
  --log-file=${LOG_FILE} \
  --json-stdout=true \
  --pretty=true \
  --redirect-url=${REDIRECT_URL} \
  --allow-cors=${ALLOW_CORS} \
  --alias-routes=${ALIAS_ROUTES} \
  --behind-proxy=${BEHIND_PROXY}
Restart=on-failure
RestartSec=2s
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now canary-server

# -----------------------
# Caddyfile
# Phase 1: IP-only HTTP (:80) until DNS is ready
# Phase 2: If --domain provided, switch to HTTPS with ACME
# -----------------------

if [[ -z "${DOMAIN}" ]]; then
  # Bootstrap: HTTP on :80 (works by IP)
  cat >/etc/caddy/Caddyfile <<'CADDY'
:80 {
  encode gzip
  reverse_proxy 127.0.0.1:8080 {
    header_up X-Forwarded-For {remote_host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }
}
CADDY
else
  # Domain mode with HTTPS
  cat >/etc/caddy/Caddyfile <<CADDY
${DOMAIN} {
  encode gzip

  reverse_proxy 127.0.0.1:8080 {
    header_up X-Forwarded-For {remote_host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }

  header {
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "no-referrer-when-downgrade"
  }
}
CADDY
fi

# Format + reload Caddy
caddy fmt --overwrite /etc/caddy/Caddyfile || true
systemctl restart caddy || true

# -----------------------
# Firewall
# -----------------------
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable

# -----------------------
# Output
# -----------------------
SERVER_IP="$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')"
echo
echo "✅ Base install complete."
echo "   - Server: systemctl status canary-server"
echo "   - Logs:   ${LOG_FILE}"
echo "   - Proxy:  Caddy → 127.0.0.1:8080"
echo
if [[ -z "${DOMAIN}" ]]; then
  echo "Phase 1 (HTTP):"
  echo "   Test health:   curl -s http://${SERVER_IP}/healthz"
  echo "   Create token:  curl -i -X POST http://${SERVER_IP}/api/tokens \\"
  echo "                    -H 'Content-Type: application/json' \\"
  echo "                    -H 'X-API-Key: ${API_KEY}' \\"
  echo "                    -d '{\"type\":\"pixel\",\"label\":\"probe\"}'"
  echo
  echo "When DNS A record points to ${SERVER_IP}, switch to HTTPS:"
  echo "   sudo bash $0 --api-key \"${API_KEY}\" --redirect-url \"${REDIRECT_URL}\" --domain \"barxperience.com\""
else
  echo "Phase 2 (HTTPS / ${DOMAIN}):"
  echo "   Test health:   curl -s https://${DOMAIN}/healthz"
  echo "   Create token:  curl -i -X POST https://${DOMAIN}/api/tokens \\"
  echo "                    -H 'Content-Type: application/json' \\"
  echo "                    -H 'X-API-Key: ${API_KEY}' \\"
  echo "                    -d '{\"type\":\"pixel\",\"label\":\"probe\"}'"
fi
echo
echo "Tail logs:"
echo "   sudo tail -f ${LOG_FILE}"
