# GODSEYE Feature Matrix

GODSEYE keeps its existing security and monitoring features while expanding toward the useful functionality exposed by NetAlertX. Docker/container configuration is intentionally excluded.

## Implemented in the current codebase

- Raspberry Pi/native Linux deployment
- SQLite persistent inventory
- ARP discovery via arp-scan
- Reverse DNS and ICMP cross-checks
- Online/suspected-offline/offline lifecycle
- New-device, disconnect, reconnect and IP-change events
- Device classification
- Search/filter and activity views
- Scanner heartbeat
- Alert rules
- Webhook, ntfy and email notification channels
- Session authentication and roles
- TOTP MFA and backup codes
- Account lockout and session timeout
- CSRF/security headers
- Password history and optional rotation
- Audit log
- Privilege-separated scanner/web services
- Safe diagnostic engine
- Evidence-based troubleshooting recommendations
- Native plugin registry and scheduler
- Native discovery helpers for Nmap, IP neighbors, mDNS and DNS tools
- CI compile/smoke tests
- User guide

## Integration roadmap

The plugin registry reserves capability IDs for the remaining integrations so they can be added without changing the application model:

- DHCP lease import/server discovery
- Pi-hole import/API
- UniFi import/API
- SNMP discovery
- ASUSWRT
- OpenWRT/LuCI
- MikroTik
- TP-Link Omada
- FRITZ!Box
- Freebox
- Kea DHCP
- Generic REST import
- Multi-site GODSEYE sync
- Public IP monitoring
- Internet speed tests
- Website/service monitoring
- Wake-on-LAN
- Vendor/OUI updates
- CSV backup/export
- Workflows
- Telegram, Pushover, Pushsafer and Apprise
- MQTT/Home Assistant
- Prometheus metrics
- Reports and maintenance

## Safety rule

Integrations and active network actions must be explicitly enabled and configured. Discovery and diagnostics should be read-only by default. Automated fixes should require an explicit confirmation and provide a rollback path where practical.
