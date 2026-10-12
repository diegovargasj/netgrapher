"""Facts: atomic observations with provenance. See design §6.4.

Extractors emit immutable Observations. The FactStore deduplicates them into Facts, which keep
counters, first/last-seen times and the first few frame numbers for traceability.
"""

from __future__ import annotations

import hashlib
from collections.abc import Hashable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

MAX_FRAMES = 10


class Provenance(StrEnum):
    HOSTCFG = "hostcfg"
    PASSIVE = "passive"
    PROBE = "probe"


class FactKind(StrEnum):
    # Seen in IPv4 headers
    IP_SEEN = "ip_seen"  # data: dir ("src" | "dst")
    IP_MAC = "ip_mac"  # data: mac, vlan, dir
    TTL_OBSERVED = "ttl_observed"  # data: ttl
    # ARP
    ARP_BINDING = "arp_binding"  # data: mac, vlan
    ARP_QUERY = "arp_query"  # subject: target IP; data: vlan
    # ICMP from routers
    ICMP_TIME_EXCEEDED = "icmp_time_exceeded"
    ICMP_UNREACHABLE = "icmp_unreachable"  # data: code
    ICMP_REDIRECT = "icmp_redirect"  # data: gateway
    # DHCP
    DHCP_LEASE = "dhcp_lease"  # subject: yiaddr; data: msg, mask, routers, dns, server, chaddr
    DHCP_HOSTNAME = "dhcp_hostname"  # subject: client MAC; data: name
    # Names and services
    NAME = "name"  # data: name, source
    SERVICE = "service"  # data: service ("dns" | "dhcp")
    # Routing and redundancy protocols
    ROUTING_SPEAKER = "routing_speaker"  # data: proto, router_id (OSPF)
    REDUNDANCY_SPEAKER = "redundancy_speaker"  # data: proto, group, vips
    SUBNET_HINT = "subnet_hint"  # data: mask, source


@dataclass(frozen=True, slots=True)
class Observation:
    kind: FactKind
    subject: str
    data: tuple[tuple[str, Hashable], ...] = ()


def observe(kind: FactKind, subject: str, **data: Hashable) -> Observation:
    return Observation(kind, subject, tuple(sorted(data.items())))


@dataclass(slots=True)
class Fact:
    kind: FactKind
    subject: str
    data: tuple[tuple[str, Hashable], ...]
    provenance: Provenance
    run_id: str
    first_seen: float
    last_seen: float
    count: int = 1
    frames: list[int] = field(default_factory=list)
    probe_id: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        for k, v in self.data:
            if k == key:
                return v
        return default

    @property
    def id(self) -> str:
        raw = f"{self.kind}|{self.subject}|{self.data!r}|{self.provenance}|{self.run_id}"
        return "f:" + hashlib.sha1(raw.encode()).hexdigest()[:12]
