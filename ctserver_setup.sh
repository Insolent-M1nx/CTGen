#!/usr/bin/env bash
# setup-hosting-local-8080.sh
# Host an existing canary token server (already binding to 127.0.0.1:8080)
# behind Caddy with automatic HTTPS for barxperience.com.

set -euo pipefail

# ========= USER INPUT =========
BIN_SRC="${1:-}"                          # path to your uploaded binary (e.g., /tmp/ct_server.elf)

# ========= CONFIG =========
DOMAIN="barxperience.com"
ALT_DOMAIN="www.barxperience.com"
ADMIN_EMAIL="admin@$DOMAIN"

APP_USER="ct"
APP_DIR="/opt/ct_server"
BIN_DST="$APP_DIR/ct_server"              # stable name used by systemd
UPSTREAM="127.0.0.1:8080"                 # your app listens here (already binds to localhost)

# Optional: proxy-level Basic Auth for /admin (defense-in-depth)
ENABLE_ADMIN_BASICAUTH="no"               # "yes" or "no"
ADMIN_USER="admin"
ADMIN_PASS=""                             # leave empty to auto-generate if ENABLE_ADMIN_BASICAUTH="yes"

# ========= HELPERS =========
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root (sudo -i)"; exit 1; }; }
rand_pwd()   { tr -dc 'A-Za-z0-9!@#%^_+=' </dev/urandom | head -c 24; }
public_ip()  { curl -4fsS http://ifconfig.co || curl -4fsS http://ifconfig.me || true; }
resolve_a()  {
  if command -v dig >/dev/null 2>&1; then dig +short A "$1" | head -n1
  elif command -v getent >/dev/null 2>&1; then getent ahostsv4 "$1" | awk '/STREAM/ {print $1; exit}'
  fi
}

# ========= PRE-FLIGHT =========
need_root
if [[ -z "$BIN_SRC" || ! -f "$BIN_SRC" ]]; then
  echo "Usage: bash $0 /path/to/your/binary   (e.g., /tmp/ct_server.elf)"
  exit 1
fi

echo "==> Installing hosting stack for $DOMAIN"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
  ca-certificates curl dnsutils ufw caddy

# ========= APP USER & BINARY =========
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" /var/log/ct_server
install -m 0755 "$BIN_SRC" "$BIN_DST"
chown -R "$APP_USER:$APP_USER" "$APP_DIR" /var/log/ct_server

# ========= SYSTEMD UNIT =========
cat > /etc/systemd/system/ct-server.service <<UNIT
[Unit]
Description=Canary Token Server (your binary)
After=network-online.target
Wants=network-online.target

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DST
Restart=always
RestartSec=2
StandardOutput=append:/var/log/ct_server/server.out.log
StandardError=append:/var/log/ct_server/server.err.log
# Sandbox/hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
# Ensure only loopback is accessible from the service's perspective (not strictly required):
# RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
#IPAddressDeny=any
#IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ct-server

# ========= CADDY (HTTPS REVERSE PROXY) =========
mkdir -p /etc/caddy /var/log/caddy

BASIC_BLOCK=""
if [[ "$ENABLE_ADMIN_BASICAUTH" == "yes" ]]; then
  [[ -n "$ADMIN_PASS" ]] || ADMIN_PASS="$(rand_pwd)"
  HASHED_PASS="$(caddy hash-password --plaintext "$ADMIN_PASS")"
  read -r -d '' BASIC_BLOCK <<'EOF' || true
  @admin path /admin* /admin/** /admin
  basicauth @admin {
    __ADMIN_USER__ __HASH__
  }
EOF
  BASIC_BLOCK="${BASIC_BLOCK/__ADMIN_USER__/$ADMIN_USER}"
  BASIC_BLOCK="${BASIC_BLOCK/__HASH__/$HASHED_PASS}"
fi

cat > /etc/caddy/Caddyfile <<CADDY
{
  email $ADMIN_EMAIL
}

$DOMAIN, $ALT_DOMAIN {
  encode gzip
  log {
    output file /var/log/caddy/barxperience.access.log
    format json
  }

$BASIC_BLOCK
  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer-when-downgrade"
  }

  reverse_proxy $UPSTREAM
}
CADDY

systemctl enable --now caddy

# ========= FIREWALL =========
ufw default deny incoming || true
ufw default allow outgoing || true
ufw allow OpenSSH || true
ufw allow http || true
ufw allow https || true
ufw --force enable || true

# ========= DNS CHECK & SUMMARY =========
DROPLET_IP="$(public_ip || true)"
DNS_IP="$(resolve_a "$DOMAIN" || true)"

echo
echo "================ HOSTING READY ================"
echo "Domain:          $DOMAIN"
echo "Binary path:     $BIN_DST"
echo "App service:     systemctl status ct-server"
echo "Proxy upstream:  $UPSTREAM"
echo "Caddy service:   systemctl status caddy"
echo "App logs:        /var/log/ct_server/server.out.log"
echo "                 /var/log/ct_server/server.err.log"
echo "Caddy logs:      /var/log/caddy/barxperience.access.log"
if [[ "$ENABLE_ADMIN_BASICAUTH" == "yes" ]]; then
  echo "Proxy /admin auth -> user: $ADMIN_USER   pass: $ADMIN_PASS"
fi
if [[ -n "$DROPLET_IP" ]]; then
  echo "Droplet IP:      $DROPLET_IP"
fi
if [[ -n "$DNS_IP" ]]; then
  echo "A record now:    $DNS_IP"
fi
if [[ -n "$DROPLET_IP" && -n "$DNS_IP" && "$DROPLET_IP" != "$DNS_IP" ]]; then
  echo ">>> DNS mismatch: point A record for $DOMAIN to $DROPLET_IP, then Caddy will fetch certs."
fi
echo
echo "Quick checks:"
echo "  Local (app):   curl -I http://127.0.0.1:8080/healthz || true"
echo "  Via TLS:       curl -I https://$DOMAIN/healthz"
echo "================================================"
