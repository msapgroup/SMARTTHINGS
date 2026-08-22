# GODSEYE Network Tools

GODSEYE now exposes a native, Docker-free Tools page at `/api/v1/tools` for authenticated users.

## Discovery

- **Nmap discovery**: administrator-only active host discovery. Install `nmap` (the Raspberry Pi installer now does this automatically).
- **IPv4/IPv6 neighbors**: reads the Linux neighbor table with `ip neigh`.
- **Hostname lookup**: best-effort local reverse lookup.

## Diagnostics

- Host ping and packet loss
- DNS resolution
- Gateway detection
- Internet connectivity
- Evidence-based recommendations

## Monitoring

- HTTP/HTTPS URL availability and response time
- Plugin capability inventory

## Integrations

- Pi-hole API connectivity test
- UniFi controller login test
- SNMP system-description test using `snmpwalk`
- Wake-on-LAN

Credentials supplied to integration test endpoints are not persisted by these endpoints. SNMP community configuration is read from the local `GODSEYE_SNMP_COMMUNITY` environment variable.

## Safety

GODSEYE separates read-only diagnostics from active actions. Nmap and Wake-on-LAN require administrator authentication. GODSEYE does not automatically change router, DHCP, DNS, Wi-Fi, or firewall settings.

## Roadmap

The integration framework is intentionally extensible. The next integration work will add persistent configuration and scheduled collectors for DHCP, Pi-hole, UniFi, SNMP, router APIs, website/service monitoring, notifications, workflows, reports, Prometheus, and multi-site synchronization.
