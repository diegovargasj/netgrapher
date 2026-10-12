"""Fact and provenance types. See design §6.4."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Provenance(StrEnum):
    HOSTCFG = "hostcfg"
    PASSIVE = "passive"
    PROBE = "probe"


class FactKind(StrEnum):
    # Capture-host configuration
    HOST_ADDRESS = "host_address"
    HOST_ROUTE = "host_route"
    HOST_NEIGHBOR = "host_neighbor"
    HOST_RESOLVER = "host_resolver"
    # Passive or probe observations
    ARP_BINDING = "arp_binding"
    IP_SEEN = "ip_seen"
    TTL_OBSERVED = "ttl_observed"
    MAC_SOURCES = "mac_sources"
    DHCP_ACK = "dhcp_ack"
    DNS_ANSWER = "dns_answer"
    NAME_ANNOUNCED = "name_announced"
    ICMP_TIME_EXCEEDED = "icmp_time_exceeded"
    ICMP_UNREACHABLE = "icmp_unreachable"
    ICMP_REDIRECT = "icmp_redirect"
    ROUTING_SPEAKER = "routing_speaker"
    REDUNDANCY_SPEAKER = "redundancy_speaker"
    ECHO_REPLY = "echo_reply"
    TCP_RESPONSE = "tcp_response"
    TRACE_HOP = "trace_hop"


@dataclass(frozen=True)
class Fact:
    kind: FactKind
    subject: str
    data: Mapping[str, Any]
    provenance: Provenance
    run_id: str
    first_seen: float
    last_seen: float
    count: int = 1
    frames: tuple[int, ...] = ()
    probe_id: str | None = None
