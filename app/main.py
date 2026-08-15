import asyncio
import datetime as dt
import html
import ipaddress
import os
import re
import sqlite3
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("PI_MONITOR_DB", BASE_DIR / "data" / "monitor.db"))
SCAN_INTERVAL = int(os.environ.get("PI_MONITOR_SCAN_INTERVAL", "60"))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            name TEXT,
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
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        """)


def local_subnet():
    # Prefer the route used for the default gateway.
    try:
        out = subprocess.check_output(["ip", "-4", "route", "get", "1.1.1.1"], text=True, timeout=3)
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
        dev = re.search(r"dev (\S+)", out)
        if m and dev:
            ip = ipaddress.ip_address(m.group(1))
            out2 = subprocess.check_output(["ip", "-4", "addr", "show", "dev", dev.group(1)], text=True, timeout=3)
            m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out2)
            if m2:
                return str(ipaddress.ip_network(f"{m2.group(1)}/{m2.group(2)}", strict=False))
    except Exception:
        pass
    return None


def scan():
    subnet = local_subnet()
    if not subnet:
        return []
    try:
        raw = subprocess.check_output(["arp-scan", "--localnet"], text=True, stderr=subprocess.STDOUT, timeout=30)
    except Exception as exc:
        print(f"scan failed: {exc}")
        return []

    devices = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]) and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]):
            devices.append({"ip": parts[0], "mac": parts[1].lower(), "vendor": " ".join(parts[2:])})
    return devices


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
                c.execute("INSERT INTO devices(mac,ip,vendor,status,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                          (mac, d["ip"], d["vendor"], "online", timestamp, timestamp))
                c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)",
                          (mac, "new_device", d["ip"], timestamp, "New device discovered"))
            else:
                event = None
                if old["ip"] != d["ip"]:
                    event = ("ip_changed", f"IP changed from {old['ip']} to {d['ip']}")
                elif old["status"] != "online":
                    event = ("connected", "Device returned to the network")
                c.execute("UPDATE devices SET ip=?, vendor=?, status='online', last_seen=? WHERE mac=?",
                          (d["ip"], d["vendor"] or old["vendor"], timestamp, mac))
                if event:
                    c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)",
                              (mac, event[0], d["ip"], timestamp, event[1]))

        for mac, old in existing.items():
            if mac not in found_macs and old["status"] == "online":
                c.execute("UPDATE devices SET status='offline' WHERE mac=?", (mac,))
                c.execute("INSERT INTO events(mac,event_type,ip,created_at,details) VALUES(?,?,?,?,?)",
                          (mac, "disconnected", old["ip"], timestamp, "Device not found during scan"))


async def scanner_loop():
    while True:
        await asyncio.to_thread(record_scan, await asyncio.to_thread(scan))
        await asyncio.sleep(SCAN_INTERVAL)


@asynccontextmanager
async def lifespan(app):
    init_db()
    task = asyncio.create_task(scanner_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Pi Network Monitor", version="0.1.0", lifespan=lifespan)


class DeviceUpdate(BaseModel):
    name: str | None = None
    trusted: bool | None = None
    notes: str | None = None


@app.get("/api/health")
def health():
    with db() as c:
        count = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
    return {"ok": True, "devices": count, "online": online}


@app.get("/api/devices")
def devices():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY status DESC, last_seen DESC")]


@app.patch("/api/devices/{device_id}")
def update_device(device_id: int, payload: DeviceUpdate):
    fields, values = [], []
    if payload.name is not None:
        fields.append("name=?"); values.append(payload.name)
    if payload.trusted is not None:
        fields.append("trusted=?"); values.append(int(payload.trusted))
    if payload.notes is not None:
        fields.append("notes=?"); values.append(payload.notes)
    if not fields:
        return {"ok": True}
    values.append(device_id)
    with db() as c:
        cur = c.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(404, "Device not found")
    return {"ok": True}


@app.get("/api/events")
def events(limit: int = 100):
    limit = min(max(limit, 1), 500)
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]


@app.post("/api/scan")
def manual_scan():
    found = scan()
    record_scan(found)
    return {"ok": True, "found": len(found)}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD)


DASHBOARD = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pi Network Monitor</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}header{padding:22px 5%;background:#111827;display:flex;justify-content:space-between;align-items:center}main{padding:24px 5%}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card,table{background:#1e293b;border-radius:12px}.card{padding:18px}.num{font-size:30px;font-weight:700;margin-top:5px}table{width:100%;border-collapse:collapse;margin-top:22px}th,td{text-align:left;padding:12px;border-bottom:1px solid #334155}th{color:#94a3b8}.online{color:#4ade80}.offline{color:#94a3b8}.unknown{color:#facc15}button{background:#2563eb;border:0;color:white;padding:10px 14px;border-radius:8px;cursor:pointer}input{background:#0f172a;color:white;border:1px solid #475569;padding:7px;border-radius:6px;width:140px}.muted{color:#94a3b8}
@media(max-width:700px){.cards{grid-template-columns:1fr}th:nth-child(4),td:nth-child(4){display:none}}
</style></head>
<body><header><div><strong>Pi Network Monitor</strong><div class="muted">Raspberry Pi LAN visibility</div></div><button onclick="scan()">Scan Now</button></header>
<main><div class="cards"><div class="card">Devices<div class="num" id="total">-</div></div><div class="card">Online<div class="num online" id="online">-</div></div><div class="card">Unknown<div class="num unknown" id="unknown">-</div></div></div>
<h2>Devices</h2><table><thead><tr><th>Status</th><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Trusted</th></tr></thead><tbody id="devices"></tbody></table>
<h2>Recent events</h2><table><thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></main>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
async function load(){let d=await (await fetch('/api/devices')).json(); document.getElementById('total').textContent=d.length;document.getElementById('online').textContent=d.filter(x=>x.status==='online').length;document.getElementById('unknown').textContent=d.filter(x=>!x.trusted).length;document.getElementById('devices').innerHTML=d.map(x=>`<tr><td class="${esc(x.status)}">● ${esc(x.status)}</td><td><input value="${esc(x.name||'')}" onchange="rename(${x.id},this.value)"></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor)}</td><td><input type="checkbox" ${x.trusted?'checked':''} onchange="trust(${x.id},this.checked)"></td></tr>`).join('');let e=await (await fetch('/api/events')).json();document.getElementById('events').innerHTML=e.slice(0,25).map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.event_type)}</td><td>${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join('')}
async function rename(id,name){await fetch('/api/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})})}async function trust(id,trusted){await fetch('/api/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({trusted})});load()}async function scan(){await fetch('/api/scan',{method:'POST'});load()}load();setInterval(load,10000);
</script></body></html>'''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
