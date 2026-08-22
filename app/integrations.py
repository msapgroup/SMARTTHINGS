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
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
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
            return {
                "ok": 200 <= response.status < 400,
                "status": response.status,
                "final_url": response.geturl(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
                "sample_bytes": len(body),
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": round((time.monotonic() - started) * 1000, 1)}


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
    # Never accept a community string through the URL. Use an environment
    # variable for a local admin-controlled test instead.
    community = os.environ.get("GODSEYE_SNMP_COMMUNITY", "public")
    code, output = 1, ""
    try:
        p = subprocess.run([binary, "-v2c", "-c", community, "-On", payload.host, "1.3.6.1.2.1.1.1.0"], capture_output=True, text=True, timeout=8)
        code, output = p.returncode, (p.stdout or p.stderr).strip()
    except Exception as exc:
        output = str(exc)
    return {"ok": code == 0, "installed": True, "response": output[-2000:]}


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
