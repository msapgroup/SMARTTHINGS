# GODSEYE

**GODSEYE** is a lightweight, local-first Raspberry Pi 4 network intelligence and monitoring appliance inspired by Pi.Alert.

## Current release: 0.3

- Automatic ARP LAN discovery with `arp-scan`
- Persistent SQLite inventory
- New-device, disconnect, reconnect and IP-change events, tagged with severity
- Three-state device lifecycle (online / suspected offline / offline) that tolerates a missed scan or two before flagging a device gone
- Device classification (new / known / ignored / investigate) instead of a blunt trusted flag
- Device names, type and notes
- Search, status and classification filtering
- Activity history
- Scanner health heartbeat, surfaced on the dashboard if scans go stale
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

## Configuration

Set these as `Environment=` lines in the systemd unit files (or export them before running `python -m app` / `python -m app.scanner` in development). All are optional; defaults are shown.

| Variable | Default | Applies to | Purpose |
| --- | --- | --- | --- |
| `GODSEYE_DB` | `<app dir>/data/godseye.db` | both | SQLite database path |
| `GODSEYE_SCAN_INTERVAL` | `60` | scanner | Seconds between scan cycles |
| `GODSEYE_SUSPECTED_THRESHOLD` | `1` | scanner | Consecutive missed scans before a device is marked suspected offline |
| `GODSEYE_OFFLINE_THRESHOLD` | `3` | scanner | Consecutive missed scans before a device is marked offline and a disconnect event is logged |
| `GODSEYE_HEARTBEAT_STALE_AFTER` | `180` | web | Seconds since the scanner's last successful run before the dashboard reports it unhealthy |

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app
```

## Roadmap

Near-term, following the phased plan in `docs/roadmap.md`:

- Local admin authentication (session + CSRF), LAN-only by default
- Alert/rule engine on top of the new event severity field
- OUI/manufacturer lookup and better automatic device classification
- ntfy / Telegram / email notification plugins
- Device detail and historical timelines
- Ping and service monitoring, internet/DNS health
- Network topology map, router/AP integrations, Wake-on-LAN
- Raspberry Pi health metrics
- Backup/restore and database retention controls
- Automatic updates
