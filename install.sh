#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/godseye
REPO=https://github.com/msapgroup/SMARTTHINGS.git
APP_USER=godseye
ENV_FILE=/etc/godseye.env

if [[ $EUID -ne 0 ]]; then echo 'Run as root: sudo bash install.sh'; exit 1; fi

apt-get update
# Core discovery/diagnostics plus optional native integrations. No Docker is
# required. nmap enables host discovery; snmp enables SNMP integrations.
apt-get install -y python3 python3-venv python3-pip arp-scan iproute2 openssl iputils-ping nmap snmp

if [[ ! -d "$APP_DIR/.git" ]]; then
  rm -rf "$APP_DIR"
  git clone "$REPO" "$APP_DIR"
else
  git -C "$APP_DIR" pull --ff-only
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$APP_DIR/data"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/data"
chmod 750 "$APP_DIR/data"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# --- Admin credentials -------------------------------------------------
# No fixed default password is shipped. If GODSEYE_ADMIN_USER and/or
# GODSEYE_ADMIN_PASSWORD are already set in the environment this script is
# run with, those values are used as-is. Otherwise a random password is
# generated fresh for this install.
if [[ ! -f "$ENV_FILE" ]]; then
  FIRST_INSTALL=1
  ADMIN_USER="${GODSEYE_ADMIN_USER:-GodsEye}"
  if [[ -n "${GODSEYE_ADMIN_PASSWORD:-}" ]]; then
    ADMIN_PASSWORD="$GODSEYE_ADMIN_PASSWORD"
    PASSWORD_WAS_GENERATED=0
  else
    ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-20)
    PASSWORD_WAS_GENERATED=1
  fi
  cat > "$ENV_FILE" <<EOF
GODSEYE_ADMIN_USER=${ADMIN_USER}
GODSEYE_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"
else
  FIRST_INSTALL=0
fi

install -m 0644 "$APP_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service
install -m 0644 "$APP_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service
mkdir -p /etc/systemd/system/godseye-web.service.d /etc/systemd/system/godseye-scanner.service.d
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-web.service.d/env.conf
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-scanner.service.d/env.conf

systemctl daemon-reload
systemctl enable --now godseye-scanner godseye-web

# --- TLS via Caddy (optional enhancement, never blocks the core app) ---
CADDY_OK=1
set +e
(
  set -e
  if ! command -v caddy >/dev/null 2>&1; then
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
    apt-get install -y caddy
  fi
  mkdir -p /etc/caddy
  cat > /etc/caddy/Caddyfile <<EOF
:8443 {
\ttls internal
\treverse_proxy 127.0.0.1:8080
}
EOF
  caddy validate --config /etc/caddy/Caddyfile
  systemctl enable --now caddy
  systemctl reload caddy || systemctl restart caddy
)
if [[ $? -ne 0 ]]; then
  CADDY_OK=0
  echo
  echo "NOTE: TLS setup (Caddy) failed and was skipped - this is not fatal."
fi
set -e

IP=$(hostname -I | awk '{print $1}')
echo
echo 'GODSEYE installed.'
if [[ "$CADDY_OK" == "1" ]]; then
  echo "Open: https://$IP:8443"
fi
echo "Direct URL: http://$IP:8080"
echo 'Web:     sudo systemctl status godseye-web'
echo 'Scanner: sudo systemctl status godseye-scanner'
if [[ "$CADDY_OK" == "1" ]]; then
  echo 'Caddy:   sudo systemctl status caddy'
fi
echo
if [[ "$FIRST_INSTALL" == "1" ]]; then
  echo '=================================================================='
  if [[ "$PASSWORD_WAS_GENERATED" == "1" ]]; then
    echo 'First-time setup - a random admin password was generated:'
    echo "  Username: ${ADMIN_USER}"
    echo "  Password: ${ADMIN_PASSWORD}"
    echo 'Save this password now - it is not printed again.'
  else
    echo 'First-time setup - using the credentials you provided.'
  fi
  echo '=================================================================='
fi
if [[ "$CADDY_OK" == "1" ]]; then
  echo
  echo "Caddy is using a self-signed internal certificate."
  echo "Run 'sudo caddy trust' on a client with Caddy installed, or import"
  echo "Caddy's internal root CA manually."
fi
