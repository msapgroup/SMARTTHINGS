# Pi Network Monitor

A lightweight Raspberry Pi 4 network discovery and monitoring dashboard inspired by Pi.Alert.

## Features in v0.1

- ARP-based LAN discovery using `arp-scan`
- Persistent SQLite device inventory
- Online/offline and new-device detection
- Friendly device names and trusted/unknown status
- Event history
- Browser dashboard
- REST API
- Raspberry Pi installer and systemd service

## Raspberry Pi install

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/SMARTTHINGS.git /opt/pi-network-monitor
cd /opt/pi-network-monitor
sudo bash install.sh
```

Then open `http://<raspberry-pi-ip>:8080`.

The scanner requires root privileges for `arp-scan`; the supplied systemd service runs the application as root for the MVP. Restrict access to your LAN.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt install arp-scan
sudo python3 -m app
```

## Roadmap

- Notifications (ntfy, Telegram, email)
- Vendor/OUI database
- Ping/service monitoring
- Network topology
- Router integrations
- Authentication and HTTPS
- Wake-on-LAN
- Better device classification
