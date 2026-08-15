#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/godseye
REPO=https://github.com/msapgroup/SMARTTHINGS.git
APP_USER=godseye

if [[ $EUID -ne 0 ]]; then echo 'Run as root: sudo bash install.sh'; exit 1; fi

apt-get update
apt-get install -y python3 python3-venv python3-pip arp-scan iproute2

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

install -m 0644 "$APP_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service
install -m 0644 "$APP_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service

systemctl daemon-reload
systemctl enable --now godseye-scanner godseye-web

IP=$(hostname -I | awk '{print $1}')
echo
echo 'GODSEYE installed.'
echo "Open: http://$IP:8080"
echo 'Web:     sudo systemctl status godseye-web'
echo 'Scanner: sudo systemctl status godseye-scanner'
