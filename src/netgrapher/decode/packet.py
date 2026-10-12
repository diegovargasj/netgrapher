"""DecodedPacket: L2 evidence fields, IP and L4 headers, selected payloads."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ArpInfo:
    op: int
    sha: str
    spa: str
    tha: str
    tpa: str


@dataclass(slots=True)
class IcmpInfo:
    type: int
    code: int
    gateway: str | None = None  # redirects
    inner_src: str | None = None  # header quoted in error messages
    inner_dst: str | None = None
    inner_proto: int | None = None


@dataclass(slots=True)
class DecodedPacket:
    frame: int
    ts: float
    iface: int
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan: int | None = None
    arp: ArpInfo | None = None
    is_ipv6: bool = False
    ip_src: str | None = None
    ip_dst: str | None = None
    ttl: int = 0
    proto: int = 0
    ip_len: int = 0
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    icmp: IcmpInfo | None = None
    payload: bytes = b""  # UDP/TCP payload, or the IP payload for other protocols
