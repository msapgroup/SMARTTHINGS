"""GODSEYE integration API.

Native, Docker-free integration endpoints. Secrets are accepted only for an
individual test request and are never written to the database by this module.
"""
from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .discovery import ip_neighbors, mdns_name, nmap_discover
from .diagnostics import diagnose_host
from .plugins import manifest
from .main import get_current_user, require_admin

router = APIRouter(prefix="/api/v1", tags=["integrations"])


class HostRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)


class NmapRequest(BaseModel):
    target: str = Field(min_length=1, max_length=64)


class UrlRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    timeout: float = Field(default=8, ge=1, le=30)


class WOLRequest(BaseModel):
    mac: str = Field(min_length=12, max_length=17)
    broadcast: str = Field(default="255.255.255.255", min_length=7, max_length=45)
    port: int = Field(default=9, ge=1, le=65535)


class ControllerTestRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    verify_tls: bool = True


def _urlopen(req: urllib.request.Request, timeout: float, verify_tls: bool):
    context = None
    if not verify_tls:
        context = ssl._create_unverified_context()
    return urllib.request.urlopen(req, timeout=timeout, context=context)


@router.get("/plugins")
def plugins(user=Depends(get_current_user)):
    return {"plugins": manifest()}


@router.post("/discovery/nmap")
def discovery_nmap(payload: NmapRequest, admin=Depends(require_admin)):
    return nmap_discover(payload.target)


@router.get("/discovery/neighbors")
def discovery_neighbors(user=Depends(get_current_user)):
    return ip_neighbors()


@router.post("/discovery/hostname")
def discovery_hostname(payload: HostRequest, user=Depends(get_current_user)):
    return mdns_name(payload.host)


@router.post("/diagnostics/host")
def diagnostics_host(payload: HostRequest, user=Depends(get_current_user)):
    return diagnose_host(payload.host)


@router.post("/monitor/url")
def monitor_url(payload: UrlRequest, user=Depends(get_current_user)):
    started = time.monotonic()
    try:
        req = urllib.request.Request(payload.url, headers={"User-Agent": "GODSEYE/1.0"}, method="GET")
        with _urlopen(req, payload.timeout, True) as response:
            body = response.read(256)
            return {"ok": 200 <= response.status < 400, "status": response.status,
                    "final_url": response.geturl(), "elapsed_ms": round((time.monotonic()-started)*1000, 1),
                    "sample_bytes": len(body)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": round((time.monotonic()-started)*1000, 1)}


@router.post("/integrations/pihole/test")
def pihole_test(payload: UrlRequest, admin=Depends(require_admin)):
    """Tests a Pi-hole HTTP API endpoint without storing credentials."""
    try:
        req = urllib.request.Request(payload.url.rstrip("/") + "/api/info", headers={"User-Agent": "GODSEYE/1.0"})
        with _urlopen(req, payload.timeout, True) as response:
            data = response.read(4096).decode("utf-8", "replace")
            return {"ok": 200 <= response.status < 400, "status": response.status, "response": data[:4000]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/integrations/unifi/test")
def unifi_test(payload: ControllerTestRequest, admin=Depends(require_admin)):
    """Tests a UniFi controller login. Credentials are never persisted."""
    url = payload.url.rstrip("/") + "/api/auth/login"
    body = ("{\"username\":\"" + payload.username.replace('"', '') + "\",\"password\":\"" + payload.password.replace('"', '') + "\"}").encode()
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "GODSEYE/1.0"}, method="POST")
        with _urlopen(req, 10, payload.verify_tls) as response:
            return {"ok": 200 <= response.status < 300, "status": response.status}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": "Controller rejected the login"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/integrations/snmp/test")
def snmp_test(payload: HostRequest, admin=Depends(require_admin)):
    binary = shutil.which("snmpwalk")
    if not binary:
        return {"ok": False, "installed": False, "error": "snmpwalk is not installed. Install snmp on Raspberry Pi OS to enable SNMP."}
    community = os.environ.get("GODSEYE_SNMP_COMMUNITY", "public")
    try:
        p = subprocess.run([binary, "-v2c", "-c", community, "-On", payload.host, "1.3.6.1.2.1.1.1.0"], capture_output=True, text=True, timeout=8)
        return {"ok": p.returncode == 0, "installed": True, "response": (p.stdout or p.stderr).strip()[-2000:]}
    except Exception as exc:
        return {"ok": False, "installed": True, "error": str(exc)}


@router.post("/tools/wol")
def wake_on_lan(payload: WOLRequest, admin=Depends(require_admin)):
    raw = payload.mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(raw) != 12 or any(ch not in "0123456789abcdef" for ch in raw):
        raise HTTPException(400, "Invalid MAC address")
    packet = bytes.fromhex("ff" * 6 + raw * 16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sent = sock.sendto(packet, (payload.broadcast, payload.port))
    finally:
        sock.close()
    return {"ok": sent == 102, "bytes_sent": sent, "broadcast": payload.broadcast, "port": payload.port}


@router.get("/tools", response_class=HTMLResponse)
def tools_page(user=Depends(get_current_user)):
    return HTMLResponse(r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GODSEYE Tools</title><style>body{font-family:system-ui;background:#070b12;color:#e8eef7;max-width:1000px;margin:auto;padding:28px}section{background:#101927;border:1px solid #26364d;border-radius:14px;padding:18px;margin:14px 0}input,button{background:#0b1422;color:#e8eef7;border:1px solid #33445d;border-radius:8px;padding:9px;margin:4px}button{cursor:pointer}pre{white-space:pre-wrap;background:#070b12;padding:12px;border-radius:8px;max-height:350px;overflow:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}.ok{color:#50e3a4}.bad{color:#ff8194}</style></head><body><h1>◉ GODSEYE Tools</h1><p>Discovery, diagnostics and safe network utilities. Changes such as Wake-on-LAN require administrator privileges.</p><div class="grid"><section><h2>Host diagnostics</h2><input id="host" placeholder="192.168.1.1"><button onclick="hostDiag()">Diagnose</button></section><section><h2>Nmap discovery</h2><input id="target" placeholder="192.168.1.0/24"><button onclick="nmap()">Scan LAN</button></section><section><h2>Neighbors</h2><button onclick="neighbors()">Read ARP/NDP table</button></section><section><h2>Website monitor</h2><input id="url" placeholder="http://192.168.1.1"><button onclick="urltest()">Test URL</button></section><section><h2>Wake-on-LAN</h2><input id="mac" placeholder="AA:BB:CC:DD:EE:FF"><button onclick="wol()">Wake device</button></section><section><h2>Plugin capabilities</h2><button onclick="plugins()">Show capabilities</button></section></div><section><h2>Result</h2><pre id="out">Ready.</pre></section><script>function csrf(){return decodeURIComponent(document.cookie.split('; ').find(x=>x.startsWith('godseye_csrf='))?.split('=')[1]||'')}async function call(path,method='GET',body=null){const o={method,headers:{'X-CSRF-Token':csrf()}};if(body){o.headers['Content-Type']='application/json';o.body=JSON.stringify(body)}const r=await fetch('/api/v1'+path,o);const t=await r.text();try{return JSON.parse(t)}catch{return {status:r.status,response:t}}}function show(x){document.getElementById('out').textContent=JSON.stringify(x,null,2)}async function hostDiag(){show(await call('/diagnostics/host','POST',{host:document.getElementById('host').value}))}async function nmap(){show(await call('/discovery/nmap','POST',{target:document.getElementById('target').value}))}async function neighbors(){show(await call('/discovery/neighbors'))}async function urltest(){show(await call('/monitor/url','POST',{url:document.getElementById('url').value}))}async function wol(){show(await call('/tools/wol','POST',{mac:document.getElementById('mac').value}))}async function plugins(){show(await call('/plugins'))}</script></body></html>''')
