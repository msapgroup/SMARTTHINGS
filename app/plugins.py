"""GODSEYE plugin framework.

Plugins are deliberately small Python modules with explicit capabilities and
configuration.  This gives GODSEYE the extensibility of NetAlertX without
requiring Docker or copying NetAlertX's implementation.

A plugin may be a scanner, importer, name resolver, publisher, monitor,
workflow, or utility.  Plugins should never execute automatically unless they
are enabled in configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


PLUGIN_TYPES = {"scanner", "importer", "resolver", "publisher", "monitor", "workflow", "utility"}


@dataclass(slots=True)
class Plugin:
    plugin_id: str
    display_name: str
    description: str
    plugin_type: str
    capabilities: tuple[str, ...] = ()
    enabled: bool = False
    schedule_seconds: int | None = None
    run: Callable[..., Any] | None = None
    settings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.plugin_type not in PLUGIN_TYPES:
            raise ValueError(f"Unsupported plugin type: {self.plugin_type}")


_REGISTRY: dict[str, Plugin] = {}


def register(plugin: Plugin) -> Plugin:
    if plugin.plugin_id in _REGISTRY:
        raise ValueError(f"Plugin already registered: {plugin.plugin_id}")
    _REGISTRY[plugin.plugin_id] = plugin
    return plugin


def get(plugin_id: str) -> Plugin | None:
    return _REGISTRY.get(plugin_id)


def all_plugins() -> list[Plugin]:
    return list(_REGISTRY.values())


def enabled_plugins() -> list[Plugin]:
    return [p for p in _REGISTRY.values() if p.enabled]


def manifest() -> list[dict[str, Any]]:
    return [
        {
            "id": p.plugin_id,
            "name": p.display_name,
            "description": p.description,
            "type": p.plugin_type,
            "capabilities": list(p.capabilities),
            "enabled": p.enabled,
            "schedule_seconds": p.schedule_seconds,
        }
        for p in all_plugins()
    ]


# Feature-parity manifest. Implementations are enabled as they are completed.
# Keeping this explicit makes the Settings UI and future installer aware of the
# complete capability surface without pretending an unimplemented integration
# is ready for production.
BUILTIN_FEATURES = (
    ("ARPSCAN", "ARP LAN discovery", "scanner"),
    ("NMAPDEV", "Nmap discovery", "scanner"),
    ("IPNEIGH", "IPv4 ARP and IPv6 NDP neighbor discovery", "scanner"),
    ("ICMP", "ICMP reachability and latency monitoring", "monitor"),
    ("AVAHISCAN", "mDNS/Avahi name discovery", "resolver"),
    ("NBTSCAN", "NetBIOS name discovery", "resolver"),
    ("NSLOOKUP", "DNS name discovery", "resolver"),
    ("DIGSCAN", "DNS dig name discovery", "resolver"),
    ("DHCPLSS", "DHCP lease import", "importer"),
    ("DHCPSRVS", "DHCP server discovery", "monitor"),
    ("PIHOLE", "Pi-hole database/lease import", "importer"),
    ("PIHOLEAPI", "Pi-hole API import", "importer"),
    ("UNFIMP", "UniFi controller import", "importer"),
    ("UNIFIAPI", "UniFi API multi-site import", "importer"),
    ("SNMPDSC", "SNMP discovery/import", "scanner"),
    ("ASUSWRT", "ASUSWRT connected-device import", "importer"),
    ("LUCIRPC", "OpenWRT/LuCI import", "importer"),
    ("MTSCAN", "MikroTik discovery/import", "importer"),
    ("OMDSDNOPENAPI", "TP-Link Omada OpenAPI import", "importer"),
    ("FRITZBOX", "FRITZ!Box TR-064 import", "importer"),
    ("FREEBOX", "Freebox import", "importer"),
    ("KEALSS", "Kea DHCP API import", "importer"),
    ("RSTIMPRT", "Generic REST import", "importer"),
    ("SYNC", "GODSEYE multi-site sync", "importer"),
    ("INTRNT", "Public Internet IP discovery", "monitor"),
    ("INTRSPD", "Internet speed testing", "monitor"),
    ("WEBMON", "Website/service availability monitoring", "monitor"),
    ("WOL", "Wake-on-LAN", "utility"),
    ("CSV", "CSV backup/export", "utility"),
    ("VENDOR", "MAC vendor database updates", "utility"),
    ("WORKFLOWS", "Device governance and automation workflows", "workflow"),
    ("NTFY", "ntfy notifications", "publisher"),
    ("SMTP", "Email notifications", "publisher"),
    ("TELEGRAM", "Telegram notifications", "publisher"),
    ("PUSHOVER", "Pushover notifications", "publisher"),
    ("PUSHSAFER", "Pushsafer notifications", "publisher"),
    ("APPRISE", "Apprise notification gateway", "publisher"),
    ("WEBHOOK", "Generic webhook notifications", "publisher"),
    ("MQTT", "MQTT/Home Assistant publishing", "publisher"),
    ("MAINT", "Database/log maintenance", "utility"),
    ("REPORTS", "Reports and analytics", "utility"),
    ("PROMETHEUS", "Prometheus metrics", "utility"),
)

for _id, _name, _type in BUILTIN_FEATURES:
    register(Plugin(_id, _name, f"GODSEYE {_name.lower()} capability", _type))
