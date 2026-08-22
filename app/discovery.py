"""Native discovery helpers used by GODSEYE plugins."""
from __future__ import annotations
import ipaddress
import json
import shutil
import socket
import subprocess


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr).strip()
    except Exception as exc:
        return 1, str(exc)


def nmap_discover(target: str, timeout: int = 30) -> dict:
    binary = shutil.which("nmap")
    if not binary:
        return {"ok": False, "error": "nmap is not installed"}
    code, output = run([binary, "-sn", "-n", target], timeout)
    hosts = []
    current = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for "):
            current = line.split(" for ", 1)[1]
            try:
                ipaddress.ip_address(current)
            except ValueError:
                pass
            hosts.append({"ip": current})
        elif line.startswith("MAC Address:") and hosts:
            parts = line.split()
            if len(parts) >= 3:
                hosts[-1]["mac"] = parts[2].lower()
    return {"ok": code == 0, "hosts": hosts, "raw": output[-5000:]}


def ip_neighbors() -> dict:
    code, output = run(["ip", "-j", "neigh"], 5)
    if code != 0:
        return {"ok": False, "error": output}
    try:
        return {"ok": True, "neighbors": json.loads(output)}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Unable to parse ip-neighbor output"}


def mdns_name(ip: str, timeout: float = 2) -> dict:
    """Best-effort local reverse lookup; does not require a cloud service."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, aliases, addresses = socket.gethostbyaddr(ip)
        return {"ok": True, "hostname": host, "aliases": aliases, "addresses": addresses}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        socket.setdefaulttimeout(old)
