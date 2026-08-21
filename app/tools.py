"""Safe network diagnostics exposed to the GODSEYE troubleshooting layer."""
from __future__ import annotations
import ipaddress
import platform
import shutil
import socket
import subprocess
import time


def _run(cmd: list[str], timeout: float = 5) -> tuple[int, str, float]:
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr).strip(), (time.monotonic() - started) * 1000
    except Exception as exc:
        return 1, str(exc), (time.monotonic() - started) * 1000


def ping(host: str, count: int = 4) -> dict:
    count = max(1, min(count, 10))
    binary = shutil.which("ping")
    if not binary:
        return {"ok": False, "error": "ping is not installed"}
    code, output, elapsed = _run([binary, "-c", str(count), "-W", "2", host], timeout=15)
    loss = None
    for line in output.splitlines():
        if "% packet loss" in line:
            try:
                loss = float(line.split("%", 1)[0].split()[-1])
            except ValueError:
                pass
    return {"ok": code == 0, "target": host, "packet_loss_percent": loss, "elapsed_ms": round(elapsed, 1), "raw": output[-2000:]}


def dns(host: str) -> dict:
    started = time.monotonic()
    try:
        answers = socket.getaddrinfo(host, None)
        ips = sorted({a[4][0] for a in answers})
        return {"ok": True, "host": host, "addresses": ips, "elapsed_ms": round((time.monotonic()-started)*1000, 1)}
    except Exception as exc:
        return {"ok": False, "host": host, "error": str(exc), "elapsed_ms": round((time.monotonic()-started)*1000, 1)}


def gateway() -> dict:
    code, output, elapsed = _run(["ip", "route", "show", "default"], timeout=3)
    gateway_ip = None
    if code == 0:
        parts = output.split()
        if "via" in parts:
            gateway_ip = parts[parts.index("via") + 1]
    return {"ok": bool(gateway_ip), "gateway": gateway_ip, "elapsed_ms": round(elapsed, 1), "raw": output}


def internet() -> dict:
    result = dns("example.com")
    if not result["ok"]:
        return {"ok": False, "stage": "dns", "details": result}
    g = gateway()
    if not g["ok"]:
        return {"ok": False, "stage": "gateway", "details": g}
    p = ping(g["gateway"], 2)
    if not p["ok"]:
        return {"ok": False, "stage": "gateway_ping", "details": p}
    return {"ok": True, "stage": "internet", "gateway": g["gateway"], "dns": result}


def diagnose_host(host: str) -> dict:
    result = {"target": host, "ping": ping(host), "dns": dns(host)}
    recommendations = []
    if not result["ping"]["ok"]:
        recommendations.append("Check power, Wi-Fi/Ethernet link, DHCP address, and whether the device blocks ICMP.")
    elif result["ping"].get("packet_loss_percent", 0) and result["ping"]["packet_loss_percent"] >= 10:
        recommendations.append("Packet loss is elevated; check Wi-Fi signal, cabling, AP health, and congestion.")
    if not result["dns"]["ok"]:
        recommendations.append("DNS lookup failed; check DHCP DNS settings and the router/DNS server.")
    result["recommendations"] = recommendations
    return result
