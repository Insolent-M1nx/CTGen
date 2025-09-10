#!/usr/bin/env bash
set -euo pipefail

# ====== CONFIG (edit as needed) ======
DOMAIN="barxperience.com"
API_KEY="${API_KEY:-}"         # export API_KEY="yoursecret" before running, or pass --api-key
SERVER_USER="canary"
SERVER_DIR="/opt/canary-server"
BIN_PATH="/usr/local/bin/canary-server"
LOG_DIR="/var/log/canary"
LOG_FILE="${LOG_DIR}/canary_token.jsonl"
LISTEN_ADDR="127.0.0.1:8080"   # Caddy will proxy 443->this
REDIRECT_URL="https://example.com"  # Where /l/{id} redirects (you can change later)
ALLOW_CORS="true"              # helpful when using your generator UI
ALIAS_ROUTES="true"
BEHIND_PROXY="true"            # trust X-Forwarded-For from Caddy

# ====== ARG PARSE ======
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --domain)  DOMAIN="${2:-}";  shift 2 ;;
    --redirect-url) REDIRECT_URL="${2:-}"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${API_KEY}" ]]; then
  echo "ERROR: please provide an API key (export API_KEY=... or pass --api-key ...)" >&2
  exit 1
fi

# ====== PREREQS ======
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw ca-certificates

# ----- Install Caddy (if not present) -----
if ! command -v caddy >/dev/null 2>&1; then
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | tee /usr/share/keyrings/caddy-stable-archive-keyring.gpg >/dev/null
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi

# ----- Optional: Install Go if you plan to build on the droplet -----
if ! command -v go >/dev/null 2>&1; then
  apt-get install -y golang-go
fi

# ====== SERVICE USER & DIRS ======
id -u "${SERVER_USER}" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "${SERVER_USER}"
mkdir -p "${SERVER_DIR}" "${LOG_DIR}"
chown -R "${SERVER_USER}:${SERVER_USER}" "${SERVER_DIR}" "${LOG_DIR}"
chmod 755 "${SERVER_DIR}" "${LOG_DIR}"

# ====== BINARY ======
# If you already have your built server binary locally, copy it to BIN_PATH before running this script.
# Otherwise, try to build from source if a main.go is present in SERVER_DIR.
if [[ ! -x "${BIN_PATH}" ]]; then
  echo "No server binary at ${BIN_PATH}. Looking for ${SERVER_DIR}/main.go to build..."
  if [[ -f "${SERVER_DIR}/main.go" ]]; then
    echo "Building server from ${SERVER_DIR}/main.go ..."
    (cd "${SERVER_DIR}" && go build -o "${BIN_PATH}" .)
    chown "${SERVER_USER}:${SERVER_USER}" "${BIN_PATH}"
    chmod 755 "${BIN_PATH}"
  else
    cat <<EOF >&2
ERROR: No binary found at ${BIN_PATH} and no ${SERVER_DIR}/main.go to build.
- Option A: scp your source into ${SERVER_DIR}/main.go and rerun this script.
- Option B: scp your compiled binary to ${BIN_PATH}, chmod +x it, and rerun.
EOF
    exit 1
  fi
fi

# ====== SYSTEMD UNIT ======
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

# ====== CADDYFILE (HTTPS + reverse proxy to 127.0.0.1:8080) ======
cat >/etc/caddy/Caddyfile <<CADDY
# Auto-HTTPS for your domain; Caddy handles Let's Encrypt
${DOMAIN} {
  encode gzip
  # Forward real client IP to the app
  header_up X-Forwarded-For {remote_host}
  header_up X-Real-IP {remote_host}

  # Proxy all requests to your Go server
  reverse_proxy ${LISTEN_ADDR}

  # (Optional) basic hardening
  header {
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "no-referrer-when-downgrade"
  }
}
CADDY

systemctl reload caddy

# ====== FIREWALL ======
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable

# ====== FINISH ======
echo
echo "✅ Setup complete."
echo "   - Server listening (locally) at http://${LISTEN_ADDR}"
echo "   - Public HTTPS at https://${DOMAIN}"
echo "   - Logs (JSONL) at ${LOG_FILE}"
echo "   - Systemd service: canary-server (use: systemctl status canary-server)"
echo "   - Caddy reverse proxy: systemctl status caddy"
echo
echo "Test token creation (replace YOURKEY if needed):"
echo "  curl -i -X POST https://${DOMAIN}/api/tokens \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H 'X-API-Key: ${API_KEY}' \\"
echo "    -d '{\"type\":\"pixel\",\"label\":\"probe\"}'"
echo
echo "If you get HTTP 308 from http:// (not https://), that's Caddy redirecting to TLS—expected."
