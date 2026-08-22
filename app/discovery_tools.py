"""Optional native discovery/enrichment helpers for Raspberry Pi deployments."""
from __future__ import annotations
import shutil
import subprocess


def run_tool(command: list[str], timeout: int = 30) -> dict:
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "returncode": p.returncode, "stdout": p.stdout[-10000:], "stderr": p.stderr[-5000:]}
    except Exception as exc:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": str(exc)}


def available_discovery_tools() -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in ("arp-scan", "nmap", "ip", "avahi-browse", "nbtscan", "dig", "nslookup")}


def nmap_ping_sweep(cidr: str) -> dict:
    """Run a conservative host-discovery-only Nmap sweep. No port scan."""
    if not shutil.which("nmap"):
        return {"ok": False, "error": "nmap is not installed"}
    return run_tool(["nmap", "-sn", "-n", "--max-retries", "1", "--host-timeout", "10s", cidr], timeout=60)


def neighbor_table() -> dict:
    if not shutil.which("ip"):
        return {"ok": False, "error": "iproute2 is not installed"}
    return run_tool(["ip", "neigh", "show"], timeout=5)


def mdns_browse() -> dict:
    if not shutil.which("avahi-browse"):
        return {"ok": False, "error": "avahi-browse is not installed"}
    return run_tool(["avahi-browse", "-all", "-rt"], timeout=20)


def dns_name(host: str) -> dict:
    tool = shutil.which("dig") or shutil.which("nslookup")
    if not tool:
        return {"ok": False, "error": "dig/nslookup is not installed"}
    if tool.endswith("dig"):
        return run_tool([tool, "+short", "-x", host], timeout=5)
    return run_tool([tool, host], timeout=5)
