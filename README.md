# GODSEYE

**GODSEYE** is a lightweight, local-first Raspberry Pi 4 network intelligence and monitoring appliance inspired by Pi.Alert.

## Current release: 0.2

- Automatic ARP LAN discovery with `arp-scan`
- Persistent SQLite inventory
- New-device, disconnect, reconnect and IP-change events
- Trusted/unknown device state
- Device names, type and notes
- Search and status filtering
- Activity history
- Mobile-friendly dark dashboard
- Manual scan requests
- Privilege separation: scanner is isolated from the web application
- systemd services for automatic startup/restart

## Architecture

The web application runs as the unprivileged `godseye` user. Only `godseye-scanner.service` runs as root because `arp-scan` needs elevated network privileges. Both services share the SQLite database through the `godseye` group.

## Raspberry Pi installation

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/SMARTTHINGS.git /opt/godseye-src
cd /opt/godseye-src
sudo bash install.sh
```

The installer installs the application under `/opt/godseye` and creates two services:

```bash
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
```

Then open `http://<raspberry-pi-ip>:8080` from a device on your LAN.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app
```

## Roadmap

- OUI/manufacturer database
- Better automatic device classification
- ntfy / Telegram / email alerts
- Device detail and historical timelines
- Ping and service monitoring
- Internet/DNS health monitoring
- Network topology map
- Router/AP integrations
- Wake-on-LAN
- Raspberry Pi health metrics
- Authentication and optional HTTPS
- Backup/restore and database retention controls
- Automatic updates
