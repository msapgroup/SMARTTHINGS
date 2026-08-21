"""Safe, local network diagnostics used by GODSEYE troubleshooting.

Diagnostics are read-only by default.  They gather evidence and return a
structured result that the recommendation engine can explain to the user.
No router/device configuration is changed by this module.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(slots=True)
class DiagnosticResult:
    test: str
    status: str
    summary: str
    details: dict[str, Any]
    duration_ms: int

    def as_dict(self):
        return asdict(self)


def _run(cmd: list[str], timeout: float = 5) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def ping(host: str, count: int = 3, timeout: float = 2) -> DiagnosticResult:
    start = time.monotonic()
    if not host:
        return DiagnosticResult("ping", "error", "No target supplied", {}, 0)
    cmd = ["ping", "-c", str(max(1, min(count, 10))), "-W", str(max(1, int(timeout))), host]
    rc, out, err = _run(cmd, timeout=max(3, count * timeout + 2))
    loss = None
    avg_ms = None
    for line in out.splitlines():
        if "% packet loss" in line:
            try:
                loss = float(line.split("% packet loss")[0].split()[-1])
            except (ValueError, IndexError):
                pass
        if " = " in line and "/" in line and " ms" in line:
            try:
                avg_ms = float(line.split(" = ", 1)[1].split("/", 2)[1])
            except (ValueError, IndexError):
                pass
    status = "ok" if rc == 0 and (loss is None or loss < 1) else ("warning" if loss is not None and loss < 50 else "failed")
    summary = f"{host} reachable" if status == "ok" else f"{host} has connectivity problems"
    return DiagnosticResult("ping", status, summary, {"target": host, "packet_loss_pct": loss, "avg_latency_ms": avg_ms, "stderr": err}, int((time.monotonic()-start)*1000))


def dns_lookup(host: str) -> DiagnosticResult:
    start = time.monotonic()
    try:
        name, aliases, addresses = socket.gethostbyname_ex(host)
        return DiagnosticResult("dns", "ok", f"DNS resolved {host}", {"canonical": name, "aliases": aliases, "addresses": addresses}, int((time.monotonic()-start)*1000))
    except OSError as exc:
        return DiagnosticResult("dns", "failed", f"DNS lookup failed for {host}", {"error": str(exc)}, int((time.monotonic()-start)*1000))


def gateway() -> DiagnosticResult:
    start = time.monotonic()
    rc, out, err = _run(["ip", "route", "show", "default"], timeout=3)
    gateway_ip = None
    if rc == 0:
        parts = out.split()
        if "via" in parts:
            gateway_ip = parts[parts.index("via") + 1]
    if gateway_ip:
        result = ping(gateway_ip, count=2)
        result.test = "gateway"
        result.details["gateway"] = gateway_ip
        result.duration_ms = int((time.monotonic()-start)*1000)
        return result
    return DiagnosticResult("gateway", "failed", "No default gateway was detected", {"error": err or out}, int((time.monotonic()-start)*1000))


def internet() -> DiagnosticResult:
    start = time.monotonic()
    targets = ["1.1.1.1", "8.8.8.8"]
    results = [ping(target, count=2) for target in targets]
    ok = [r for r in results if r.status == "ok"]
    status = "ok" if ok else "failed"
    return DiagnosticResult("internet", status, "Internet is reachable" if ok else "Internet connectivity failed", {"tests": [r.as_dict() for r in results]}, int((time.monotonic()-start)*1000))


def tools_available() -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in ("arp-scan", "nmap", "avahi-browse", "nbtscan", "dig", "nslookup", "ip", "ping")}


def diagnose_device(ip: str) -> dict[str, Any]:
    """Run a conservative evidence bundle against a single LAN IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Target must be a valid IP address")
    tests = [ping(ip), gateway(), internet()]
    return {"target": ip, "tests": [t.as_dict() for t in tests], "tools": tools_available()}


def recommendations(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn diagnostic evidence into explainable, non-destructive advice."""
    tests = {item["test"]: item for item in bundle.get("tests", [])}
    recs = []
    device = tests.get("ping")
    gw = tests.get("gateway")
    net = tests.get("internet")
    if device and device["status"] == "failed" and gw and gw["status"] == "ok" and net and net["status"] == "ok":
        recs.append({"severity": "warning", "cause": "The LAN and Internet are healthy but this device is unreachable.", "actions": ["Check the device's Wi-Fi/Ethernet connection", "Check whether the device is sleeping", "Review the device's recent disconnect history"]})
    if device and device["details"].get("packet_loss_pct", 0) not in (None, 0) and device["details"].get("packet_loss_pct", 0) >= 10:
        recs.append({"severity": "warning", "cause": "Elevated packet loss was measured.", "actions": ["Check Wi-Fi signal strength", "Test the device from another access point or Ethernet", "Check for AP/channel congestion"]})
    if gw and gw["status"] == "failed":
        recs.append({"severity": "critical", "cause": "The default gateway is unreachable.", "actions": ["Check router power and LAN link", "Check switch/AP connectivity", "Verify the Raspberry Pi is on the expected VLAN/subnet"]})
    if net and net["status"] == "failed" and gw and gw["status"] == "ok":
        recs.append({"severity": "critical", "cause": "The gateway responds but public Internet targets do not.", "actions": ["Check WAN/ISP status", "Check router WAN state", "Test DNS separately before changing DNS settings"]})
    if not recs:
        recs.append({"severity": "info", "cause": "No obvious fault was established by the selected tests.", "actions": ["Run a longer continuous ping", "Review GODSEYE event history", "Compare the device with other clients on the same access point"]})
    return recs
