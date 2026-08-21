"""Evidence-based troubleshooting rules for GODSEYE."""
from __future__ import annotations


def analyze(host_result: dict) -> dict:
    recommendations = list(host_result.get("recommendations", []))
    ping_result = host_result.get("ping", {})
    dns_result = host_result.get("dns", {})
    if ping_result.get("ok") and not dns_result.get("ok"):
        cause = "Device is reachable but DNS resolution failed."
        severity = "warning"
    elif not ping_result.get("ok"):
        cause = "Device is not responding to ICMP; it may be offline, sleeping, filtered, or experiencing a network-path problem."
        severity = "warning"
    elif ping_result.get("packet_loss_percent", 0) >= 10:
        cause = "Elevated packet loss suggests an unstable network path, Wi-Fi signal, cabling, or congestion issue."
        severity = "warning"
    else:
        cause = "No immediate connectivity fault detected by the available tests."
        severity = "info"
    return {"severity": severity, "likely_cause": cause, "recommendations": recommendations}
