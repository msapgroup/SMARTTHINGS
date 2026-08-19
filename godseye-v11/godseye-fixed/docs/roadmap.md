# GODSEYE Roadmap

This is the architectural review behind GODSEYE's direction past 0.2, and the
build order it implies. Items marked **done** shipped in 0.3.

## Principles

Local-first. Privacy-respecting. Reliable. Explainable. Secure by default.

Pipeline: `Discover → Observe → Normalize → Correlate → Decide → Alert → Audit`

## Design notes

1. **Separate detection from security decisions** *(done, 0.3)* — a newly
   discovered device is not automatically malicious. Devices carry a
   `classification` (new / known / ignored / investigate) independent of
   network `status`, so MAC-randomizing phones and reconnecting IoT gear
   don't read as alarms by default.

2. **Alert engine, not hard-coded notifications** — `Scanner → Event Engine
   → Rules → Alert Channels`. Example rules: unknown device online for 5+
   minutes, known device offline 30+ minutes, router IP changes
   unexpectedly, new devices during selected hours, disk usage over 85%.
   Keeps behavior configurable without code changes.

3. **Confidence scoring** — instead of "Unknown Device," show a likely
   identity with a confidence percentage and the evidence behind it (OUI
   match, DHCP hostname pattern, prior sightings, behavior pattern).

4. **Privacy as a first-class feature** — local-only by default, no
   telemetry, no cloud account, explicit opt-in for remote notifications,
   optional database encryption, easy data deletion, configurable
   retention. Don't store more than needed (presence history, not every
   packet).

5. **Design for MAC randomization** — identity should eventually combine
   MAC, vendor, hostname, DHCP client ID, mDNS name, behavior pattern, and
   prior IPs, distinguishing physical / network / observed identity.

6. **Plugin architecture early** — discovery plugins (ARP, DHCP, mDNS,
   router APIs), notification plugins (ntfy, email, Telegram, Discord),
   monitoring plugins (ping, HTTP, DNS, SNMP) — so the core doesn't become
   one large script.

7. **Structured event model** *(done, 0.3 — severity field added)* —
   events as structured records (id, timestamp, type, severity, device_id,
   source, metadata), not free text, so filtering/APIs/automations/reports
   have something to build on.

8. **Plan for database growth now** — hot data (detailed events, 30-90
   days), summaries (hourly/daily, 1-2 years), optional archive/export.
   Automatic vacuuming, retention policies, backup rotation, DB health
   checks.

9. **Backup and recovery** — manual and scheduled backup (USB, NAS, SFTP,
   local share) covering database, config, inventory, trust/classification
   settings, and alert config — without dumping secrets in plain text.

10. **Secrets management** — API keys, SMTP passwords, tokens, router
    credentials never go in the SQLite DB or source in plain text.
    Restrictive-permission env files, secrets kept separate from normal
    config, redacted in logs, never returned via API.

11. **Authentication earlier than originally planned** — even on a home
    LAN, an unauthenticated dashboard exposes inventory, topology, and
    security events. Start with local admin account, strong password,
    session cookie, CSRF protection, rate limiting. Later: TOTP/MFA,
    passkeys, OAuth/OIDC, multiple users and roles.

12. **Role-based access** — relevant once GODSEYE has multiple users.

13. **Don't expose the web interface by default** — LAN-only listening, no
    public internet exposure, remote access off by default. If remote
    access is wanted, point at VPN or an explicitly configured reverse
    proxy — never "just forward a port."

14. **Health model for GODSEYE itself** *(done, 0.3 — scanner heartbeat)* —
    scanner, database, and web service health, last-scan age, disk/memory/
    CPU temp, uptime. Critically: if the scanner hasn't run successfully in
    N minutes, alert — otherwise the dashboard can look healthy while doing
    nothing.

15. **Protect against false offline alerts** *(done, 0.3)* — devices sleep,
    roam, or miss a probe. A single missed scan should not mean "offline."
    State machine: `online → suspected offline → offline`, with
    per-device-type-configurable thresholds (a printer and a phone behave
    differently — thresholds are currently global, per-type is a later
    refinement).

16. **Audit log** — separate from network events: "admin marked device
    known," "admin changed alert rule," "device renamed," etc. Valuable for
    troubleshooting who changed what.

17. **API versioning** *(done, 0.3)* — `/api/v1/...` so a future v2 doesn't
    break existing integrations.

18. **Observability from the start** — structured logs, log rotation,
    error IDs, scan duration metrics, failed-scan counts, DB size — a
    troubleshooting page showing last successful scan, duration, devices
    found, scanner errors.

19. **Multiple network interfaces** — don't hard-code `eth0`; support a
    configurable interface list, and eventually VLANs/multiple subnets.

20. **Network inventory concept** — group devices by role (infrastructure,
    computers, entertainment, IoT), not just a flat list — useful even when
    nothing is wrong.

## Build order

**Phase A — Foundation**
Configuration system, structured event model *(done)*, database
migrations, retention policies, logging and health checks *(heartbeat
done)*, scanner reliability/state machine *(done)*, authentication,
secrets management.

**Phase B — Intelligence**
Vendor/OUI lookup, hostname discovery, mDNS discovery, device
classification, confidence scoring, MAC randomization handling.

**Phase C — Alerts**
Rule engine, alert severity, acknowledgement, notification plugins, alert
suppression/deduplication.

**Phase D — Network Monitoring**
Ping/latency, DNS monitoring, internet monitoring, HTTP/HTTPS monitoring,
Pi health monitoring.

**Phase E — Appliance & Expansion**
Backup/restore, automatic updates, plugin architecture, multi-interface
support, network topology, integrations.
