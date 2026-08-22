# GODSEYE — How to Use

GODSEYE is a local-first Raspberry Pi network intelligence appliance. It discovers devices, records network events, monitors health, and helps diagnose problems without Docker.

## 1. Install

On Raspberry Pi OS 64-bit:

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/SMARTTHINGS.git /opt/godseye-src
cd /opt/godseye-src
sudo bash install.sh
```

The installer creates the web and privileged scanner services. Keep the Pi on the LAN you want to monitor.

## 2. First login

Open `http://PI-IP:8080`. Sign in with the credentials created during installation. Change the seeded password immediately. If MFA is enabled, complete TOTP enrollment and store the backup codes securely.

## 3. Overview

The Overview screen is the normal starting point. Use it to see online, suspected-offline, offline, unknown/investigate devices, recent events, and scanner health.

A stale scanner heartbeat means discovery has stopped reporting even if systemd still shows the service as active.

## 4. Devices

Use search and filters to find a device. Each device can have a friendly name, type, notes, and lifecycle classification:

- **New** — discovered but not reviewed.
- **Known** — recognized and trusted.
- **Investigate** — requires attention.
- **Ignored** — excluded from normal attention workflows.

Review MAC address, IP, hostname, vendor, first seen, last seen, and event history before changing a classification.

## 5. Activity and alerts

Activity shows new-device, disconnect, reconnect, and IP-change events. Alert Rules can turn repeated or significant events into notifications. Use storm protection to avoid notification floods.

## 6. Security

Use the Security view for authentication and account controls. GODSEYE supports admin and read-only roles, session timeout, account lockout, CSRF protection, security headers, TOTP MFA, backup codes, password history, and audit logging.

## 7. Diagnostics

When a device has a problem, run read-only diagnostics before making changes. GODSEYE can test:

- Device ping and packet loss
- Default gateway reachability
- Public Internet reachability
- DNS resolution
- Availability of local diagnostic tools

The recommendation engine converts those results into likely causes and safe next actions. Diagnostics do not automatically change router or device configuration.

### Example

If a device fails ping while the gateway and Internet are healthy, GODSEYE will suggest checking the device's Wi-Fi/Ethernet link, sleep state, and recent disconnect history rather than blaming the ISP.

## 8. Plugins and integrations

GODSEYE uses a native plugin model. Integrations are intentionally disabled until configured. Planned and supported capability families include ARP/Nmap/NDP/mDNS discovery, DHCP and router imports, Pi-hole and UniFi, SNMP, website/service monitoring, notifications, Wake-on-LAN, workflows, reports, and Prometheus metrics.

Do not enable an integration until its credentials and network permissions have been reviewed.

## 9. Safe troubleshooting workflow

```text
Detect problem
    ↓
Review event history
    ↓
Run read-only diagnostics
    ↓
Compare related devices
    ↓
Review GODSEYE recommendation
    ↓
Make the change yourself or explicitly approve a future automated fix
    ↓
Run diagnostics again
    ↓
Confirm recovery
```

GODSEYE should follow **diagnose → explain → recommend → confirm → fix**, never silently modify network infrastructure.

## 10. Service health

```bash
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
sudo journalctl -u godseye-web -n 100 --no-pager
sudo journalctl -u godseye-scanner -n 100 --no-pager
```

If the scanner is stale, check `arp-scan` permissions, the Pi's network interface, and scanner logs.

## 11. Backups

Back up the SQLite database before upgrades or configuration changes. Keep a copy outside the Raspberry Pi.

## 12. Screenshots

Screenshots in the README are maintained as documentation assets. They should always be regenerated from a running GODSEYE build after major UI changes; do not use mock images to claim a feature is live.
