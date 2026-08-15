import datetime as dt
import html
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


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
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        """)


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="GODSEYE", version="0.2.0", lifespan=lifespan)


class DeviceUpdate(BaseModel):
    name: str | None = None
    trusted: bool | None = None
    notes: str | None = None
    device_type: str | None = None


@app.get("/api/health")
def health():
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
        unknown = c.execute("SELECT COUNT(*) FROM devices WHERE trusted=0").fetchone()[0]
        events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"ok": True, "total": total, "online": online, "unknown": unknown, "events": events}


@app.get("/api/devices")
def devices(search: str | None = None, status: str | None = None):
    query = "SELECT * FROM devices WHERE 1=1"
    values = []
    if search:
        query += " AND (mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR name LIKE ?)"
        term = f"%{search}%"
        values += [term] * 5
    if status in {"online", "offline", "unknown"}:
        query += " AND status=?"
        values.append(status)
    query += " ORDER BY CASE WHEN status='online' THEN 0 ELSE 1 END, trusted ASC, last_seen DESC"
    with db() as c:
        return [dict(r) for r in c.execute(query, values)]


@app.patch("/api/devices/{device_id}")
def update_device(device_id: int, payload: DeviceUpdate):
    fields, values = [], []
    for field in ("name", "trusted", "notes", "device_type"):
        value = getattr(payload, field)
        if value is not None:
            fields.append(f"{field}=?")
            values.append(int(value) if field == "trusted" else value)
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


@app.get("/api/devices/{device_id}/events")
def device_events(device_id: int, limit: int = 200):
    limit = min(max(limit, 1), 500)
    with db() as c:
        device = c.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(404, "Device not found")
        return [dict(r) for r in c.execute("SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (device["mac"], limit))]


@app.post("/api/scan")
def manual_scan():
    # Scanning is deliberately isolated into the privileged godseye-scanner service.
    # Touching this endpoint asks that service to scan on its next cycle.
    flag = BASE_DIR / "data" / "scan-now"
    flag.touch()
    return {"ok": True, "message": "Scan requested"}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD)


DASHBOARD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Network Monitor</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#070b12;color:#e8eef7}header{position:sticky;top:0;z-index:5;background:rgba(7,11,18,.94);backdrop-filter:blur(14px);border-bottom:1px solid #1d2838;padding:16px 4%;display:flex;justify-content:space-between;align-items:center}.brand{display:flex;gap:12px;align-items:center}.eye{width:38px;height:38px;border-radius:12px;background:#182338;display:grid;place-items:center;font-size:21px}.brand b{font-size:20px;letter-spacing:.08em}.muted{color:#7f8da3;font-size:12px}button,.filter{border:1px solid #2b3a52;background:#111a28;color:#dbe7f7;border-radius:9px;padding:9px 13px;cursor:pointer}button.primary{background:#2563eb;border-color:#2563eb}.wrap{max-width:1500px;margin:auto;padding:28px 4%}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:22px}.hero h1{font-size:32px;margin:0 0 5px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:linear-gradient(145deg,#101927,#0d141f);border:1px solid #1d2a3d;border-radius:14px;padding:18px}.label{color:#8090a7;font-size:12px;text-transform:uppercase;letter-spacing:.1em}.num{font-size:32px;font-weight:750;margin-top:7px}.green{color:#50e3a4}.yellow{color:#f7c948}.red{color:#ff6b81}.toolbar{display:flex;gap:9px;margin:22px 0;flex-wrap:wrap}.toolbar input{flex:1;min-width:220px}.input{background:#0d141f;border:1px solid #2b3a52;border-radius:9px;padding:10px;color:#e8eef7}.panel{background:#0d141f;border:1px solid #1d2a3d;border-radius:14px;overflow:hidden;margin-top:18px}.panel h2{font-size:16px;margin:0;padding:16px 18px;border-bottom:1px solid #1d2a3d}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #182335;font-size:13px}th{color:#72819a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:hover{background:#111a27}.dot{font-size:10px}.online{color:#50e3a4}.offline{color:#68758a}.unknown{color:#f7c948}.pill{border:1px solid #31415a;border-radius:999px;padding:3px 8px;font-size:11px;color:#9eb0c8}.trusted{color:#50e3a4;border-color:#245c49}.danger{color:#ff8194;border-color:#6d2e3c}.name{font-weight:650}.smallinput{width:145px}.empty{padding:35px;text-align:center;color:#72819a}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}@media(max-width:600px){.cards{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}th:nth-child(4),td:nth-child(4){display:none}.wrap{padding:20px 3%}}
</style></head>
<body><header><div class="brand"><div class="eye">◉</div><div><b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div></div><button class="primary" onclick="scan()">⟳ Scan Now</button></header>
<div class="wrap"><div class="hero"><div><h1>Network Overview</h1><div class="muted" id="updated">Loading telemetry…</div></div></div>
<div class="cards"><div class="card"><div class="label">Known Devices</div><div class="num" id="total">—</div></div><div class="card"><div class="label">Online</div><div class="num green" id="online">—</div></div><div class="card"><div class="label">Unknown</div><div class="num yellow" id="unknown">—</div></div><div class="card"><div class="label">Events</div><div class="num" id="eventsCount">—</div></div></div>
<div class="toolbar"><input id="search" class="input" placeholder="Search name, IP, MAC, hostname or vendor…" oninput="loadDevices()"><select id="status" class="filter" onchange="loadDevices()"><option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option></select></div>
<section class="panel"><h2>Devices</h2><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Trust</th></tr></thead><tbody id="devices"></tbody></table></div></section>
<section class="panel"><h2>Recent Activity</h2><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Event</th><th>Device</th><th>IP</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div></section>
</div><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
async function json(url,opt){let r=await fetch(url,opt);if(!r.ok)throw new Error(await r.text());return r.json()}
async function loadDevices(){let q=new URLSearchParams();if(search.value)q.set('search',search.value);if(status.value)q.set('status',status.value);let d=await json('/api/devices?'+q);devices.innerHTML=d.length?d.map(x=>`<tr><td class="${esc(x.status)}"><span class="dot">●</span> ${esc(x.status)}</td><td><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td><button class="pill ${x.trusted?'trusted':'danger'}" onclick="trust(${x.id},${!x.trusted})">${x.trusted?'Trusted':'Unknown'}</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No devices match this filter.</td></tr>'}
async function load(){let h=await json('/api/health');total.textContent=h.total;online.textContent=h.online;unknown.textContent=h.unknown;eventsCount.textContent=h.events;updated.textContent='Last refreshed '+new Date().toLocaleTimeString();await loadDevices();let e=await json('/api/events?limit=30');events.innerHTML=e.length?e.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td><span class="pill">${esc(x.event_type)}</span></td><td>${esc(x.mac)}</td><td>${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>'}
async function trust(id,value){await json('/api/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({trusted:value})});load()}
async function scan(){await json('/api/scan',{method:'POST'});updated.textContent='Scan requested…';setTimeout(load,3000)}
load();setInterval(load,10000);
</script></body></html>'''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8080")))
