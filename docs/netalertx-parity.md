# GODSEYE / NetAlertX feature parity plan

GODSEYE keeps its existing Pi.Alert-style dashboard, authentication, MFA, audit log, privilege separation, scanner heartbeat, alert rules, SQLite storage and notifications. This document tracks the additional capability surface we are adding based on the current NetAlertX project. NetAlertX's current plugin catalog includes ARP/Nmap/IP-neighbor discovery, DNS/mDNS/NetBIOS enrichment, DHCP/Pi-hole/UniFi/SNMP/router imports, notifications, website monitoring, Wake-on-LAN, workflows, synchronization, backups, vendor updates and other utilities.

**Deployment decision:** GODSEYE is a native Raspberry Pi/Linux application. Docker, docker-compose files, container entrypoints and container-specific settings are intentionally excluded.

## Capability matrix

| Capability | GODSEYE status | Planned implementation |
|---|---|---|
| ARP scan | Existing | Keep `arp-scan` scanner |
| Nmap discovery | Planned | Optional native `nmap` plugin |
| IPv4 ARP / IPv6 NDP neighbors | Planned | `ip neigh` / `ip -6 neigh` |
| ICMP monitoring | Existing/basic | Expand latency/loss history |
| mDNS/Avahi names | Planned | Native `avahi-browse` plugin |
| NetBIOS names | Planned | Optional `nbtscan` plugin |
| DNS / nslookup / dig | Existing/basic | Resolver plugin family |
| DHCP lease import | Planned | File/API adapters |
| Pi-hole DB import | Planned | SQLite adapter |
| Pi-hole API v6+ | Planned | HTTP API adapter |
| UniFi import | Planned | Controller/API adapters |
| SNMP discovery | Planned | Optional native SNMP module |
| ASUSWRT | Planned | Read-only importer |
| OpenWRT/LuCI | Planned | Read-only importer |
| MikroTik | Planned | Read-only importer |
| Omada | Planned | OpenAPI importer |
| FRITZ!Box | Planned | TR-064 importer |
| Freebox | Planned | API/importer |
| Kea DHCP | Planned | API importer |
| Generic REST import | Planned | Authenticated JSON importer |
| Multi-site sync | Planned | GODSEYE sync nodes |
| Public IP monitoring | Planned | External IP monitor |
| Internet speed test | Planned | Opt-in scheduled test |
| Website/service monitor | Planned | HTTP/TCP/ICMP monitor |
| Wake-on-LAN | Planned | Native WOL utility |
| CSV backup/export | Planned | Streaming export/import |
| MAC vendor updates | Planned | OUI database updater |
| Device custom properties | Planned | JSON/custom-fields schema |
| Workflows | Planned | Rule-based governance engine |
| ntfy | Existing | Keep and expand per-device rules |
| Email/SMTP | Existing | Keep |
| Telegram | Planned | Native publisher |
| Pushover | Planned | Native publisher |
| Pushsafer | Planned | Native publisher |
| Apprise | Planned | Optional dependency, not required |
| Webhooks | Existing | Keep |
| MQTT/Home Assistant | Planned | Native publisher |
| Reports | Planned | Presence, changes, inventory, services |
| Prometheus metrics | Planned | Native `/metrics` endpoint |
| Maintenance | Planned | Retention, VACUUM, log cleanup |
| Topology | Planned | Network-node graph and parent/child links |
| Troubleshooting | In progress | Diagnostics + recommendations engine |
| Authentication/MFA | Existing | Keep |
| Native install/systemd | Existing | Keep; no Docker |

## Architecture

The plugin registry in `app/plugins.py` is the common contract. A feature is not considered complete merely because it appears in the registry: it becomes enabled only after its native implementation, settings, tests and UI are added.

Plugin classes are grouped as:

- scanner
- importer
- resolver
- publisher
- monitor
- workflow
- utility

This keeps integrations isolated so a failure in UniFi, Pi-hole or SNMP cannot stop the primary ARP scanner.

## Troubleshooting model

`app/diagnostics.py` provides read-only evidence collection. The intended pipeline is:

`discovery -> events -> diagnostics -> evidence correlation -> recommendation -> optional confirmed fix`

Automatic changes to routers, access points or endpoints are disabled by default.

## Raspberry Pi constraints

Features should be designed for a Pi 4 first:

- SQLite/WAL remains the default local database.
- Heavy scans are scheduled and rate limited.
- Nmap and SNMP are opt-in.
- Internet speed tests are not run on every discovery cycle.
- Vendor data is cached locally.
- Imports use timeouts and circuit breakers.
- Plugin failures are isolated and recorded.
- Web and privileged scanning processes remain separated.

## Implementation order

1. Core plugin lifecycle, settings and job scheduler.
2. Nmap, IP-neighbor, mDNS and DNS enrichment.
3. Device history/presence/IPAM views and topology.
4. DHCP, Pi-hole, UniFi and generic REST importers.
5. SNMP and router/controller integrations.
6. Notification expansion and per-device notification policies.
7. Website monitoring, public-IP and speed tests.
8. Workflows, reports, Prometheus and maintenance.
9. Multi-site sync.
10. Final Pi 4 performance/security testing.
