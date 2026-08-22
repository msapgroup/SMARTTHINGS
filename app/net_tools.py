"""Native, read-only discovery helpers used by GODSEYE plugins."""
from __future__ import annotations
import shutil
import socket
import subprocess
from typing import Any


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def available(name: str) -> bool:
    return shutil.which(name) is not None


def nmap_discover(target: str) -> dict[str, Any]:
    if not available("nmap"):
        return {"ok": False, "error": "nmap is not installed"}
    code, output = run(["nmap", "-sn", "-n", target], 60)
    hosts = []
    for line in output.splitlines():
        if line.startswith("Nmap scan report for "):
            hosts.append(line.split("for ", 1)[1].strip())
    return {"ok": code == 0, "target": target, "hosts": hosts, "raw": output[-12000:]}


def neighbors() -> dict[str, Any]:
    if not available("ip"):
        return {"ok": False, "error": "ip command is not installed"}
    code, output = run(["ip", "-j", "neigh", "show"], 10)
    if code != 0:
        return {"ok": False, "error": output}
    try:
        import json
        return {"ok": True, "neighbors": json.loads(output)}
    except Exception:
        return {"ok": True, "raw": output}


def mdns_lookup(host: str) -> dict[str, Any]:
    if available("avahi-resolve-host-name"):
        code, output = run(["avahi-resolve-host-name", host], 5)
        return {"ok": code == 0, "host": host, "result": output}
    try:
        return {"ok": True, "host": host, "addresses": sorted({x[4][0] for x in socket.getaddrinfo(host, None)})}
    except OSError as exc:
        return {"ok": False, "host": host, "error": str(exc)}


def dns_lookup(host: str) -> dict[str, Any]:
    try:
        return {"ok": True, "host": host, "addresses": sorted({x[4][0] for x in socket.getaddrinfo(host, None)})}
    except OSError as exc:
        return {"ok": False, "host": host, "error": str(exc)}
