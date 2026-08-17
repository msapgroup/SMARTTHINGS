#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/godseye
REPO=https://github.com/msapgroup/SMARTTHINGS.git
APP_USER=godseye
ENV_FILE=/etc/godseye.env

if [[ $EUID -ne 0 ]]; then echo 'Run as root: sudo bash install.sh'; exit 1; fi

apt-get update
apt-get install -y python3 python3-venv python3-pip arp-scan iproute2 openssl

# Caddy isn't in the default Debian/Raspberry Pi OS apt repos - add the
# official repository first (per https://caddyserver.com/docs/install).
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
# run with (e.g. exported by your own client-provisioning template),
# those values are used as-is. Otherwise a random password is generated
# fresh for this install - there is no window where a well-known default
# is live, even briefly. The forced-password-change behavior in the app
# itself still applies as a second layer regardless of which path is used.
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
GODSEYE_COOKIE_SECURE=true
EOF
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"
else
  FIRST_INSTALL=0
fi

install -m 0644 "$APP_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service
install -m 0644 "$APP_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service
# EnvironmentFile pulls in the generated (or pre-set) admin credentials and
# GODSEYE_COOKIE_SECURE without editing the unit files themselves.
mkdir -p /etc/systemd/system/godseye-web.service.d /etc/systemd/system/godseye-scanner.service.d
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-web.service.d/env.conf
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-scanner.service.d/env.conf

# --- TLS by default via Caddy -------------------------------------------
# GODSEYE has no public DNS name (it's meant to sit behind a VPN, never
# port-forwarded - see the README), so Caddy can't use its normal
# zero-config Let's Encrypt flow, which needs a real public hostname.
# Instead it self-signs a certificate for internal use. Browsers will warn
# about that self-signed cert on first visit (expected for an internal-only
# TLS setup); import Caddy's root CA (printed below) onto client devices to
# make that warning go away.
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
:8443 {
	tls internal
	reverse_proxy 127.0.0.1:8080
}
EOF
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy || systemctl restart caddy

systemctl daemon-reload
systemctl enable --now godseye-scanner godseye-web

IP=$(hostname -I | awk '{print $1}')
echo
echo 'GODSEYE installed.'
echo "Open: https://$IP:8443  (self-signed cert - see note below)"
echo "Internal-only URL (bypasses Caddy, LAN/VPN only, no TLS): http://$IP:8080"
echo 'Web:     sudo systemctl status godseye-web'
echo 'Scanner: sudo systemctl status godseye-scanner'
echo 'Caddy:   sudo systemctl status caddy'
echo
if [[ "$FIRST_INSTALL" == "1" ]]; then
  echo '=================================================================='
  if [[ "$PASSWORD_WAS_GENERATED" == "1" ]]; then
    echo 'First-time setup - a random admin password was generated'
    echo '(also saved to /etc/godseye.env):'
    echo "  Username: ${ADMIN_USER}"
    echo "  Password: ${ADMIN_PASSWORD}"
    echo 'Save this password now - it is not printed again.'
  else
    echo "First-time setup - using the GODSEYE_ADMIN_USER/GODSEYE_ADMIN_PASSWORD"
    echo "you provided (saved to /etc/godseye.env)."
  fi
  echo 'You will be forced to set a new password on first login regardless.'
  echo '=================================================================='
fi
echo
echo "Caddy is using a self-signed internal certificate (no public DNS name"
echo "to get a real one from - GODSEYE is meant to stay off the public"
echo "internet, see the README's Remote Access section). To make the"
echo "browser warning go away on a device, run on that device:"
echo "  sudo caddy trust"
echo "(only works if that device also has Caddy installed; otherwise export"
echo "Caddy's root CA from this Pi and import it manually - see:"
echo "https://caddyserver.com/docs/command-line#caddy-trust)"
