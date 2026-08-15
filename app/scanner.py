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


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=15000")
    return c


def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, mac TEXT NOT NULL UNIQUE, ip TEXT, hostname TEXT, vendor TEXT, name TEXT, device_type TEXT, status TEXT NOT NULL DEFAULT 'unknown', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, trusted INTEGER NOT NULL DEFAULT 0, notes TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, mac TEXT, event_type TEXT NOT NULL, ip TEXT, created_at TEXT NOT NULL, details TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        """)


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
    if not local_subnet():
        return []
    try:
        raw = subprocess.check_output(["arp-scan", "--localnet", "--retry=2"], text=True, stderr=subprocess.STDOUT, timeout=45)
    except Exception as exc:
        print(f"scan failed: {exc}")
        return []
    found = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]) and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]):
            found.append({"ip": parts[0], "mac": parts[1].lower(), "vendor": " ".join(parts[2:]).strip()})
    return found


def record_scan(found):
    timestamp = now()
    found_macs = set()
    with db() as c:
        existing = {r["mac"]: r for r in c.execute("SELECT * FROM devices")}
        for d in found:
            mac = d["mac"]
            found_macs.add(mac)
            old = existing.get(mac)
            if old is None:
                c.execute("INSERT INTO devices(mac,ip,vendor,status,first_seen,last_seen) VALUES(?,?,?,?,?,?)", (mac,d["ip"],d["vendor"],"online",timestamp,timestamp))
                c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)", (mac,"new_device",d["ip"],timestamp,"New device discovered"))
            else:
                if old["ip"] != d["ip"]:
                    c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)", (mac,"ip_changed",d["ip"],timestamp,f"IP changed from {old['ip']} to {d['ip']}"))
                elif old["status"] != "online":
                    c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)", (mac,"connected",d["ip"],timestamp,"Device returned to the network"))
                c.execute("UPDATE devices SET ip=?,vendor=?,status='online',last_seen=? WHERE mac=?", (d["ip"],d["vendor"] or old["vendor"],timestamp,mac))
        for mac, old in existing.items():
            if mac not in found_macs and old["status"] == "online":
                c.execute("UPDATE devices SET status='offline' WHERE mac=?", (mac,))
                c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)", (mac,"disconnected",old["ip"],timestamp,"Device not found during scan"))


def main():
    init_db()
    print(f"GODSEYE scanner started; interval={SCAN_INTERVAL}s")
    while True:
        try:
            record_scan(scan())
        except Exception as exc:
            print(f"scanner cycle failed: {exc}")
        for _ in range(SCAN_INTERVAL):
            if SCAN_FLAG.exists():
                SCAN_FLAG.unlink(missing_ok=True)
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
