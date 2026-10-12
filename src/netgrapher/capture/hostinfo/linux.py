"""Linux HostInfo implementation based on `ip -j` (iproute2) and /etc/resolv.conf.

See design §9.2.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

from netgrapher.capture.hostinfo import (
    HostAddress,
    HostConfig,
    HostInterface,
    HostNeighbor,
    HostRoute,
)

_VALID_NEIGH_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}


def _ip_json(*args: str) -> Any:
    out = subprocess.run(
        ["ip", "-j", *args], check=True, capture_output=True, text=True, timeout=10
    ).stdout
    return json.loads(out) if out.strip() else []


def parse_addresses(doc: list[dict[str, Any]]) -> list[HostInterface]:
    interfaces = []
    for link in doc:
        flags = link.get("flags", [])
        iface = HostInterface(
            name=link.get("ifname", "?"),
            mac=link.get("address") if link.get("link_type") == "ether" else None,
            up="UP" in flags,
            loopback="LOOPBACK" in flags,
        )
        for info in link.get("addr_info", []):
            if info.get("family") in ("inet", "inet6") and "local" in info:
                iface.addresses.append(HostAddress(info["local"], int(info["prefixlen"])))
        interfaces.append(iface)
    return interfaces


def parse_routes(doc: list[dict[str, Any]]) -> list[HostRoute]:
    routes = []
    for r in doc:
        if r.get("type", "unicast") != "unicast" or r.get("table") == "local":
            continue
        dst = r.get("dst", "")
        if dst != "default":
            try:
                dst = str(ipaddress.ip_network(dst, strict=False))
            except ValueError:
                continue
        routes.append(HostRoute(dst, r.get("gateway"), r.get("dev"), r.get("metric")))
    return routes


def parse_neighbors(doc: list[dict[str, Any]]) -> list[HostNeighbor]:
    return [
        HostNeighbor(n["dst"], n["lladdr"].lower(), n.get("dev"))
        for n in doc
        if "lladdr" in n and "dst" in n and set(n.get("state", [])) & _VALID_NEIGH_STATES
    ]


def parse_resolv_conf(text: str) -> list[str]:
    resolvers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            resolvers.append(parts[1])
    return resolvers


def read() -> HostConfig:
    config = HostConfig()
    try:
        config.interfaces = parse_addresses(_ip_json("addr"))
        config.routes = parse_routes(_ip_json("-4", "route", "show", "table", "all"))
        config.neighbors = parse_neighbors(_ip_json("-4", "neigh"))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError) as exc:
        config.warnings.append(f"cannot read interfaces/routes with `ip -j`: {exc}")
    try:
        config.resolvers = parse_resolv_conf(Path("/etc/resolv.conf").read_text())
    except OSError as exc:
        config.warnings.append(f"cannot read /etc/resolv.conf: {exc}")
    return config
