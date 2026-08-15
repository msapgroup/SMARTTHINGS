#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/pi-network-monitor
REPO=https://github.com/msapgroup/SMARTTHINGS.git

if [[ $EUID -ne 0 ]]; then echo 'Run as root: sudo bash install.sh'; exit 1; fi

apt-get update
apt-get install -y python3 python3-venv python3-pip arp-scan iproute2

if [[ ! -d "$APP_DIR/.git" ]]; then
  rm -rf "$APP_DIR"
  git clone "$REPO" "$APP_DIR"
else
  git -C "$APP_DIR" pull --ff-only
fi

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
mkdir -p "$APP_DIR/data"
cp "$APP_DIR/pi-network-monitor.service" /etc/systemd/system/pi-network-monitor.service
systemctl daemon-reload
systemctl enable --now pi-network-monitor

echo
echo 'Pi Network Monitor installed.'
echo "Open: http://$(hostname -I | awk '{print $1}'):8080"
echo 'Status: sudo systemctl status pi-network-monitor'
