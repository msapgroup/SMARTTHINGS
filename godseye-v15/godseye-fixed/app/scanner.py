import datetime as dt
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import time
from pathlib import Path

from . import notifications

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))
SCAN_INTERVAL = int(os.environ.get("GODSEYE_SCAN_INTERVAL", "60"))
SCAN_FLAG = DB_PATH.parent / "scan-now"

dispatcher = notifications.NotificationDispatcher()

# Consecutive missed scans before a device moves online -> suspected_offline -> offline.
# A single missed scan (Wi-Fi roam, sleeping laptop, one dropped probe) should not
# immediately read as "gone" - see record_scan().
SUSPECTED_THRESHOLD = int(os.environ.get("GODSEYE_SUSPECTED_THRESHOLD", "1"))
OFFLINE_THRESHOLD = int(os.environ.get("GODSEYE_OFFLINE_THRESHOLD", "3"))

# --- Additional discovery methods, layered on top of ARP -------------------
# Both are stdlib/system-tool only (no new dependency): reverse DNS uses
# Python's socket module, ping shells out to the system `ping` binary that
# every Linux box already has. Both are enrichment/cross-check signals, not
# replacements for ARP as the primary discovery method.

# Reverse DNS: arp-scan gives MAC/IP/vendor but never a hostname. Most home
# routers register local DHCP names in their own DNS, so a PTR lookup often
# fills that in for free. Only attempted for devices that don't already have
# a hostname, so a healthy network's steady-state scan cycles aren't paying
# a DNS-lookup cost for every device, every cycle - only for ones still
# missing a name.
REVERSE_DNS_ENABLED = os.environ.get("GODSEYE_REVERSE_DNS", "true").lower() == "true"
REVERSE_DNS_TIMEOUT = float(os.environ.get("GODSEYE_REVERSE_DNS_TIMEOUT", "1.5"))

# Ping cross-check: ARP and ICMP normally agree on the same L2 segment, but
# an occasional dropped ARP probe on an otherwise-reachable device is exactly
# the kind of flakiness that used to generate false "disconnected" events
# (see the state-machine work in record_scan()). Before demoting a device
# that didn't answer this cycle's ARP scan, this gives it one more chance to
# prove it's still there via a plain ICMP ping.
PING_ENABLED = os.environ.get("GODSEYE_PING_CHECK", "true").lower() == "true"
PING_TIMEOUT_SECONDS = int(os.environ.get("GODSEYE_PING_TIMEOUT", "1"))

# DHCP lease file parsing: opt-in, since it only works where GODSEYE actually
# has read access to a DHCP server's lease file (e.g. running alongside
# Pi-hole/dnsmasq, or on pfSense/OPNsense where dnsmasq is the DHCP server).
# Most home setups have the router itself as the DHCP server with no lease
# file exposed to the Pi at all - this is enrichment for the setups where it
# IS available, not something that works everywhere the way ARP does.
# Unlike the ping/reverse-DNS signals, a DHCP lease is NOT used as a
# liveness signal (a lease can outlive the device actually being present),
# only as a hostname enrichment source - same trust level as reverse DNS.
DHCP_LEASES_FILE = os.environ.get("GODSEYE_DHCP_LEASES_FILE", "")
DHCP_LEASES_FORMAT = os.environ.get("GODSEYE_DHCP_LEASES_FORMAT", "dnsmasq")

VALID_CLASSIFICATIONS = {"new", "known", "ignored", "investigate"}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=15000")
    return c


def _add_column_if_missing(c, table, column, ddl):
    cols = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            name TEXT,
            device_type TEXT,
            status TEXT NOT NULL DEFAULT 'unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trusted INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            offline_escalated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            mac TEXT,
            event_type TEXT NOT NULL,
            ip TEXT,
            created_at TEXT NOT NULL,
            details TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS scanner_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_run_at TEXT,
            last_success_at TEXT,
            last_error TEXT,
            devices_found INTEGER,
            scan_duration_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            must_change_password_by TEXT,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            password_changed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            changed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT DEFAULT '',
            ip TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_secrets (
            user_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            confirmed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_backup_codes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            code_salt TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_pending (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            params TEXT NOT NULL DEFAULT '{}',
            severity TEXT NOT NULL DEFAULT 'critical',
            created_at TEXT NOT NULL,
            last_triggered_at TEXT
        );
        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            name TEXT NOT NULL,
            definition TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_pwhistory_user ON password_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_backupcodes_user ON mfa_backup_codes(user_id);
        CREATE INDEX IF NOT EXISTS idx_savedfilters_user ON saved_filters(user_id);
        """)
        # Additive, idempotent migrations for installs created before these columns existed.
        # (A real migration framework - versioned, ordered scripts - belongs on the roadmap;
        # this keeps existing 0.2 databases working without one for now.)
        _add_column_if_missing(c, "devices", "classification", "classification TEXT NOT NULL DEFAULT 'new'")
        _add_column_if_missing(c, "devices", "missed_scans", "missed_scans INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "events", "severity", "severity TEXT NOT NULL DEFAULT 'info'")
        # Backfill classification from the legacy trusted flag so existing data isn't lost.
        c.execute("UPDATE devices SET classification='known' WHERE trusted=1 AND classification='new'")


def local_subnet():
    try:
        out = subprocess.check_output(["ip", "-4", "route", "get", "1.1.1.1"], text=True, timeout=3)
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
        dev = re.search(r"dev (\S+)", out)
        if m and dev:
            addr = subprocess.check_output(["ip", "-4", "addr", "show", "dev", dev.group(1)], text=True, timeout=3)
            m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr)
            if m2:
                return str(ipaddress.ip_network(f"{m2.group(1)}/{m2.group(2)}", strict=False))
    except Exception as exc:
        print(f"subnet detection failed: {exc}")
    return None


def resolve_hostname(ip: str) -> str | None:
    """Reverse-DNS lookup, best-effort. Returns the short hostname (not
    FQDN, to match arp-scan's terse style) or None if it can't be resolved
    within the timeout - never raises."""
    if not REVERSE_DNS_ENABLED:
        return None
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(REVERSE_DNS_TIMEOUT)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.split(".")[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def ping_reachable(ip: str) -> bool:
    """One ICMP echo, best-effort. False on any failure (unreachable,
    ping missing, timeout) - never raises."""
    if not PING_ENABLED:
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT_SECONDS + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def load_dhcp_leases() -> dict:
    """Best-effort read of a DHCP server's lease file, returning
    {mac_lowercase: hostname}. Returns {} if not configured, unreadable, or
    empty - callers should treat this purely as an optional enrichment
    source, never as a required one. Only 'dnsmasq' format is supported
    today (used by dnsmasq itself, and by Pi-hole and OpenWrt, both of
    which run dnsmasq as their DHCP server); other DHCP servers use
    different lease file formats and aren't parsed by this function.
    """
    if not DHCP_LEASES_FILE:
        return {}
    if DHCP_LEASES_FORMAT != "dnsmasq":
        print(f"[GODSEYE] GODSEYE_DHCP_LEASES_FORMAT={DHCP_LEASES_FORMAT!r} is not supported (only 'dnsmasq' is)")
        return {}
    leases = {}
    try:
        with open(DHCP_LEASES_FILE, "r") as f:
            for line in f:
                fields = line.split()
                # dnsmasq.leases: <expiry-epoch> <mac> <ip> <hostname-or-'*'> <client-id-or-'*'>
                if len(fields) < 4:
                    continue
                mac, hostname = fields[1], fields[3]
                if _MAC_RE.match(mac) and hostname and hostname != "*":
                    leases[mac.lower()] = hostname
    except FileNotFoundError:
        print(f"[GODSEYE] DHCP leases file not found: {DHCP_LEASES_FILE}")
    except Exception as exc:
        print(f"[GODSEYE] could not read DHCP leases file: {exc}")
    return leases


def scan():
    # Returns None when the scan could not be performed at all (so the caller
    # must NOT treat it as "no devices found"), and a list (possibly empty)
    # when arp-scan actually ran to completion.
    if not local_subnet():
        return None
    try:
        raw = subprocess.check_output(["arp-scan", "--localnet", "--retry=2"], text=True, stderr=subprocess.STDOUT, timeout=45)
    except Exception as exc:
        print(f"scan failed: {exc}")
        return None
    found = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]) and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]):
            found.append({"ip": parts[0], "mac": parts[1].lower(), "vendor": " ".join(parts[2:]).strip()})
    return found


def _log_event(c, mac, event_type, ip, timestamp, details, severity="info"):
    c.execute(
        "INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
        (mac, event_type, ip, timestamp, details, severity),
    )
    return {"mac": mac, "event_type": event_type, "ip": ip, "created_at": timestamp,
            "details": details, "severity": severity}


def record_scan(found, dhcp_leases=None):
    """Apply one scan cycle's results using a three-state device lifecycle
    (online -> suspected_offline -> offline) instead of flipping straight to
    offline on the first missed scan. This absorbs normal flakiness (Wi-Fi
    roaming, sleeping devices, one dropped ARP probe) without generating
    false disconnect events, while still surfacing genuinely offline devices
    after OFFLINE_THRESHOLD consecutive misses.

    Supplementary discovery methods layer on top of the primary ARP scan:
    a DHCP lease file (if configured) and reverse DNS both fill in a
    hostname for newly-seen devices - DHCP checked first since it's a
    local file read with no network round trip, reverse DNS as a fallback.
    Both are attempted once, at first sight, not every cycle. A ping
    cross-check separately gives a device ARP missed this cycle one more
    chance to prove it's still there before it gets demoted.

    Notifications (webhook/ntfy/email) are dispatched after the database
    transaction closes, so a slow or unreachable notification endpoint
    never holds the SQLite write lock open.
    """
    dhcp_leases = dhcp_leases or {}
    timestamp = now()
    found_macs = set()
    fired_events = []
    with db() as c:
        existing = {r["mac"]: r for r in c.execute("SELECT * FROM devices")}
        for d in found:
            mac = d["mac"]
            found_macs.add(mac)
            old = existing.get(mac)
            if old is None:
                hostname = dhcp_leases.get(mac) or resolve_hostname(d["ip"])
                c.execute(
                    "INSERT INTO devices(mac,ip,hostname,vendor,status,first_seen,last_seen,classification,missed_scans) "
                    "VALUES(?,?,?,?,?,?,?,?,0)",
                    (mac, d["ip"], hostname, d["vendor"], "online", timestamp, timestamp, "new"),
                )
                fired_events.append(_log_event(c, mac, "new_device", d["ip"], timestamp, "New device discovered", severity="warning"))
            else:
                if old["ip"] != d["ip"]:
                    fired_events.append(_log_event(c, mac, "ip_changed", d["ip"], timestamp, f"IP changed from {old['ip']} to {d['ip']}"))
                elif old["status"] != "online":
                    fired_events.append(_log_event(c, mac, "connected", d["ip"], timestamp, "Device returned to the network"))
                c.execute(
                    "UPDATE devices SET ip=?,vendor=?,status='online',last_seen=?,missed_scans=0,"
                    "offline_escalated_at=NULL WHERE mac=?",
                    (d["ip"], d["vendor"] or old["vendor"], timestamp, mac),
                )
        for mac, old in existing.items():
            if mac in found_macs:
                continue
            if old["ip"] and ping_reachable(old["ip"]):
                # ARP missed it, but it answers ping - still there. Rescue it
                # the same way a re-appearing device would be handled, so it
                # doesn't drift toward suspected_offline/offline over a false
                # negative in one discovery method.
                c.execute(
                    "UPDATE devices SET status='online',last_seen=?,missed_scans=0,offline_escalated_at=NULL WHERE mac=?",
                    (timestamp, mac),
                )
                if old["status"] != "online":
                    fired_events.append(_log_event(c, mac, "connected", old["ip"], timestamp,
                                        "Device returned to the network (confirmed via ping after a missed ARP reply)"))
                continue
            missed = old["missed_scans"] + 1
            if old["status"] == "online" and missed >= SUSPECTED_THRESHOLD:
                c.execute("UPDATE devices SET status='suspected_offline',missed_scans=? WHERE mac=?", (missed, mac))
            elif old["status"] == "suspected_offline":
                c.execute("UPDATE devices SET missed_scans=? WHERE mac=?", (missed, mac))
            if old["status"] != "offline" and missed >= OFFLINE_THRESHOLD:
                c.execute("UPDATE devices SET status='offline',missed_scans=? WHERE mac=?", (missed, mac))
                fired_events.append(_log_event(c, mac, "disconnected", old["ip"], timestamp,
                                    f"Not seen for {missed} consecutive scans", severity="warning"))

    return fired_events


def evaluate_rules():
    """Evaluates every enabled rule against current DB state and fires
    events for any that trigger. Runs every cycle regardless of whether
    this cycle's ARP scan itself succeeded - offline-duration rules in
    particular depend on stored timestamps, not on this cycle's results.

    Two rule types are supported:
      - new_device_burst: {"count": N, "window_minutes": M} - fires if N+
        new_device events landed in the last M minutes. Cooldown of M
        minutes after firing, so it doesn't re-fire every single cycle
        while the burst condition persists.
      - offline_duration: {"minutes": N, "classifications": [...]} - fires
        once per offline episode when a device whose classification is in
        the given list has been offline for N+ minutes. Tracked via
        devices.offline_escalated_at, cleared automatically whenever the
        device comes back online (see record_scan()), so it can fire again
        on a future offline episode without manual reset.
    """
    timestamp = now()
    fired_events = []
    with db() as c:
        rules = c.execute("SELECT * FROM rules WHERE enabled=1").fetchall()
        for rule in rules:
            try:
                params = json.loads(rule["params"])
            except (json.JSONDecodeError, TypeError):
                print(f"[GODSEYE] rule '{rule['name']}' has invalid params JSON, skipping")
                continue

            if rule["rule_type"] == "new_device_burst":
                count_threshold = int(params.get("count", 10))
                window_minutes = float(params.get("window_minutes", 5))
                if rule["last_triggered_at"]:
                    since_last = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(rule["last_triggered_at"])).total_seconds() / 60
                    if since_last < window_minutes:
                        continue  # cooldown - don't re-fire every cycle while the burst persists
                window_start = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=window_minutes)).isoformat()
                actual_count = c.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='new_device' AND created_at >= ?", (window_start,)
                ).fetchone()[0]
                if actual_count >= count_threshold:
                    fired_events.append(_log_event(
                        c, None, "rule_triggered", None, timestamp,
                        f"Rule '{rule['name']}': {actual_count} new devices in the last {window_minutes:g} minute(s) "
                        f"(threshold {count_threshold})",
                        severity=rule["severity"],
                    ))
                    c.execute("UPDATE rules SET last_triggered_at=? WHERE id=?", (timestamp, rule["id"]))

            elif rule["rule_type"] == "offline_duration":
                minutes_threshold = float(params.get("minutes", 30))
                classifications = params.get("classifications") or list(VALID_CLASSIFICATIONS)
                cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_threshold)).isoformat()
                placeholders = ",".join("?" * len(classifications))
                candidates = c.execute(
                    f"SELECT * FROM devices WHERE status='offline' AND offline_escalated_at IS NULL "
                    f"AND last_seen <= ? AND classification IN ({placeholders})",
                    (cutoff, *classifications),
                ).fetchall()
                for device in candidates:
                    fired_events.append(_log_event(
                        c, device["mac"], "rule_triggered", device["ip"], timestamp,
                        f"Rule '{rule['name']}': {device['name'] or device['hostname'] or device['mac']} "
                        f"has been offline for over {minutes_threshold:g} minute(s)",
                        severity=rule["severity"],
                    ))
                    c.execute("UPDATE devices SET offline_escalated_at=? WHERE mac=?", (timestamp, device["mac"]))
                if candidates:
                    c.execute("UPDATE rules SET last_triggered_at=? WHERE id=?", (timestamp, rule["id"]))
            else:
                print(f"[GODSEYE] rule '{rule['name']}' has unknown rule_type '{rule['rule_type']}', skipping")

    return fired_events


def record_heartbeat(success, devices_found=None, duration_ms=None, error=None):
    timestamp = now()
    with db() as c:
        c.execute(
            """INSERT INTO scanner_heartbeat(id,last_run_at,last_success_at,last_error,devices_found,scan_duration_ms)
               VALUES(1,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 last_run_at=excluded.last_run_at,
                 last_success_at=CASE WHEN ?=1 THEN excluded.last_success_at ELSE scanner_heartbeat.last_success_at END,
                 last_error=excluded.last_error,
                 devices_found=CASE WHEN ?=1 THEN excluded.devices_found ELSE scanner_heartbeat.devices_found END,
                 scan_duration_ms=excluded.scan_duration_ms""",
            (timestamp, timestamp if success else None, error, devices_found, duration_ms, int(success), int(success)),
        )


def dispatch_events(fired_events):
    suppressed = 0
    dispatcher.reset()
    for event in fired_events:
        if not dispatcher.notify(event):
            suppressed += 1
    if suppressed:
        print(f"[GODSEYE] {suppressed} notification(s) suppressed this scan cycle "
              f"(GODSEYE_MAX_NOTIFICATIONS_PER_SCAN={notifications.MAX_NOTIFICATIONS_PER_SCAN}) - "
              "events were still recorded, just not pushed out, to avoid an alert storm")


def main():
    init_db()
    print(f"GODSEYE scanner started; interval={SCAN_INTERVAL}s, "
          f"suspected>={SUSPECTED_THRESHOLD} missed, offline>={OFFLINE_THRESHOLD} missed")
    while True:
        start = time.monotonic()
        fired_events = []
        try:
            found = scan()
            duration_ms = int((time.monotonic() - start) * 1000)
            if found is None:
                print("scan cycle skipped (subnet detection or arp-scan failed); leaving device statuses unchanged")
                record_heartbeat(success=False, duration_ms=duration_ms, error="scan unavailable")
            else:
                dhcp_leases = load_dhcp_leases() if DHCP_LEASES_FILE else {}
                fired_events += record_scan(found, dhcp_leases=dhcp_leases)
                record_heartbeat(success=True, devices_found=len(found), duration_ms=duration_ms)
            # Rules run every cycle regardless of whether the ARP scan itself
            # succeeded - offline-duration rules depend on stored timestamps
            # already in the DB, not on this cycle's scan results.
            fired_events += evaluate_rules()
        except Exception as exc:
            print(f"scanner cycle failed: {exc}")
            record_heartbeat(success=False, duration_ms=int((time.monotonic() - start) * 1000), error=str(exc))
        dispatch_events(fired_events)
        for _ in range(SCAN_INTERVAL):
            if SCAN_FLAG.exists():
                SCAN_FLAG.unlink(missing_ok=True)
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
