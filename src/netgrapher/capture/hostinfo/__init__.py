"""Capture-host configuration (addresses, routes, neighbors, resolvers) as facts.

See design §9.2.
"""

from __future__ import annotations

import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from netgrapher.facts.model import FactKind, Provenance, observe
from netgrapher.facts.store import FactStore
from netgrapher.net import is_ipv4, is_usable_unicast


@dataclass
class HostAddress:
    ip: str
    prefixlen: int


@dataclass
class HostInterface:
    name: str
    mac: str | None
    up: bool
    loopback: bool
    addresses: list[HostAddress] = field(default_factory=list)


@dataclass
class HostRoute:
    dst: str  # "default" or a prefix
    gateway: str | None
    dev: str | None
    metric: int | None = None


@dataclass
class HostNeighbor:
    ip: str
    mac: str
    dev: str | None


@dataclass
class HostConfig:
    hostname: str = ""
    interfaces: list[HostInterface] = field(default_factory=list)
    routes: list[HostRoute] = field(default_factory=list)
    neighbors: list[HostNeighbor] = field(default_factory=list)
    resolvers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    taken_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def default_interface(self) -> str | None:
        """Interface of the default route with the lowest metric."""
        defaults = [r for r in self.routes if r.dst == "default" and r.dev]
        if not defaults:
            return None
        return min(defaults, key=lambda r: (r.metric if r.metric is not None else 0, r.dev)).dev


def read_host_config() -> HostConfig:
    if sys.platform.startswith("linux"):
        from netgrapher.capture.hostinfo.linux import read

        config = read()
    else:
        config = HostConfig(warnings=[f"host configuration is not supported on {sys.platform}"])
    config.hostname = socket.gethostname()
    config.taken_at = time.time()
    return config


def add_host_facts(store: FactStore, config: HostConfig, run_id: str) -> None:
    """Record a host-configuration snapshot as hostcfg facts."""

    def add(kind: FactKind, subject: str, **data: Any) -> None:
        store.add(
            observe(kind, subject, **data),
            ts=config.taken_at,
            frame=None,
            run_id=run_id,
            provenance=Provenance.HOSTCFG,
        )

    for iface in config.interfaces:
        if iface.loopback:
            continue
        for addr in iface.addresses:
            if not is_ipv4(addr.ip) or not is_usable_unicast(addr.ip):
                continue  # IPv6 inference is v2
            add(
                FactKind.HOST_ADDRESS,
                addr.ip,
                prefixlen=addr.prefixlen,
                iface=iface.name,
                mac=iface.mac,
            )
            if config.hostname:
                add(FactKind.NAME, addr.ip, name=config.hostname.lower(), source="hostcfg")
    for route in config.routes:
        if route.gateway is not None and not is_ipv4(route.gateway):
            continue
        add(FactKind.HOST_ROUTE, route.dst, gateway=route.gateway, iface=route.dev)
    for neigh in config.neighbors:
        if is_ipv4(neigh.ip) and is_usable_unicast(neigh.ip):
            add(FactKind.ARP_BINDING, neigh.ip, mac=neigh.mac, vlan=None)
    for resolver in config.resolvers:
        if is_ipv4(resolver) and is_usable_unicast(resolver):
            add(FactKind.HOST_RESOLVER, resolver)
