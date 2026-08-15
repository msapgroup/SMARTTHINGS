import datetime as dt
import ipaddress
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))
SCAN_INTERVAL = int(os.environ.get("GODSEYE_SCAN_INTERVAL", "60"))
SCAN_FLAG = DB_PATH.parent / "scan-now"

# Consecutive missed scans before a device moves online -> suspected_offline -> offline.
# A single missed scan (Wi-Fi roam, sleeping laptop, one dropped probe) should not
# immediately read as "gone" - see record_scan().
SUSPECTED_THRESHOLD = int(os.environ.get("GODSEYE_SUSPECTED_THRESHOLD", "1"))
OFFLINE_THRESHOLD = int(os.environ.get("GODSEYE_OFFLINE_THRESHOLD", "3"))

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
            notes TEXT DEFAULT ''
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
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
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


def record_scan(found):
    """Apply one scan cycle's results using a three-state device lifecycle
    (online -> suspected_offline -> offline) instead of flipping straight to
    offline on the first missed scan. This absorbs normal flakiness (Wi-Fi
    roaming, sleeping devices, one dropped ARP probe) without generating
    false disconnect events, while still surfacing genuinely offline devices
    after OFFLINE_THRESHOLD consecutive misses.
    """
    timestamp = now()
    found_macs = set()
    with db() as c:
        existing = {r["mac"]: r for r in c.execute("SELECT * FROM devices")}
        for d in found:
            mac = d["mac"]
            found_macs.add(mac)
            old = existing.get(mac)
            if old is None:
                c.execute(
                    "INSERT INTO devices(mac,ip,vendor,status,first_seen,last_seen,classification,missed_scans) "
                    "VALUES(?,?,?,?,?,?,?,0)",
                    (mac, d["ip"], d["vendor"], "online", timestamp, timestamp, "new"),
                )
                _log_event(c, mac, "new_device", d["ip"], timestamp, "New device discovered", severity="warning")
            else:
                if old["ip"] != d["ip"]:
                    _log_event(c, mac, "ip_changed", d["ip"], timestamp, f"IP changed from {old['ip']} to {d['ip']}")
                elif old["status"] != "online":
                    _log_event(c, mac, "connected", d["ip"], timestamp, "Device returned to the network")
                c.execute(
                    "UPDATE devices SET ip=?,vendor=?,status='online',last_seen=?,missed_scans=0 WHERE mac=?",
                    (d["ip"], d["vendor"] or old["vendor"], timestamp, mac),
                )
        for mac, old in existing.items():
            if mac in found_macs:
                continue
            missed = old["missed_scans"] + 1
            if old["status"] == "online" and missed >= SUSPECTED_THRESHOLD:
                c.execute("UPDATE devices SET status='suspected_offline',missed_scans=? WHERE mac=?", (missed, mac))
            elif old["status"] == "suspected_offline":
                c.execute("UPDATE devices SET missed_scans=? WHERE mac=?", (missed, mac))
            if old["status"] != "offline" and missed >= OFFLINE_THRESHOLD:
                c.execute("UPDATE devices SET status='offline',missed_scans=? WHERE mac=?", (missed, mac))
                _log_event(c, mac, "disconnected", old["ip"], timestamp,
                           f"Not seen for {missed} consecutive scans", severity="warning")


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


def main():
    init_db()
    print(f"GODSEYE scanner started; interval={SCAN_INTERVAL}s, "
          f"suspected>={SUSPECTED_THRESHOLD} missed, offline>={OFFLINE_THRESHOLD} missed")
    while True:
        start = time.monotonic()
        try:
            found = scan()
            duration_ms = int((time.monotonic() - start) * 1000)
            if found is None:
                print("scan cycle skipped (subnet detection or arp-scan failed); leaving device statuses unchanged")
                record_heartbeat(success=False, duration_ms=duration_ms, error="scan unavailable")
            else:
                record_scan(found)
                record_heartbeat(success=True, devices_found=len(found), duration_ms=duration_ms)
        except Exception as exc:
            print(f"scanner cycle failed: {exc}")
            record_heartbeat(success=False, duration_ms=int((time.monotonic() - start) * 1000), error=str(exc))
        for _ in range(SCAN_INTERVAL):
            if SCAN_FLAG.exists():
                SCAN_FLAG.unlink(missing_ok=True)
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
