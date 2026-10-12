"""Routing (OSPF, EIGRP, RIP, BGP) and first-hop redundancy (VRRP, HSRP) speakers."""

from __future__ import annotations

import socket
from collections.abc import Iterator

from netgrapher.decode.decoder import PROTO_TCP, PROTO_UDP
from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

PROTO_EIGRP = 88
PROTO_OSPF = 89
PROTO_VRRP = 112
PORT_RIP = 520
PORT_BGP = 179
PORT_HSRP = 1985

_OSPF_HELLO = 1
_HSRP_V1_GROUP = "224.0.0.2"


def _usable_src(pkt: DecodedPacket) -> str | None:
    src = pkt.ip_src
    return src if src is not None and is_usable_unicast(src) else None


def extract_ospf(pkt: DecodedPacket) -> Iterator[Observation]:
    src = _usable_src(pkt)
    if pkt.proto != PROTO_OSPF or src is None or len(pkt.payload) < 24:
        return
    if pkt.payload[0] != 2:  # OSPFv2 only
        return
    router_id = socket.inet_ntoa(pkt.payload[4:8])
    yield observe(FactKind.ROUTING_SPEAKER, src, proto="ospf", router_id=router_id)
    if pkt.payload[1] == _OSPF_HELLO and len(pkt.payload) >= 28:
        mask = socket.inet_ntoa(pkt.payload[24:28])
        if mask != "0.0.0.0":
            yield observe(FactKind.SUBNET_HINT, src, mask=mask, source="ospf")


def extract_eigrp(pkt: DecodedPacket) -> Iterator[Observation]:
    src = _usable_src(pkt)
    if pkt.proto == PROTO_EIGRP and src is not None:
        yield observe(FactKind.ROUTING_SPEAKER, src, proto="eigrp", router_id=None)


def extract_rip(pkt: DecodedPacket) -> Iterator[Observation]:
    src = _usable_src(pkt)
    if pkt.proto == PROTO_UDP and pkt.sport == PORT_RIP and pkt.dport == PORT_RIP and src:
        yield observe(FactKind.ROUTING_SPEAKER, src, proto="rip", router_id=None)


def extract_bgp(pkt: DecodedPacket) -> Iterator[Observation]:
    if pkt.proto != PROTO_TCP or PORT_BGP not in (pkt.sport, pkt.dport) or not pkt.payload:
        return
    # BGP messages start with a 16-byte all-ones marker.
    if pkt.payload[:16] != b"\xff" * 16:
        return
    for ip in (pkt.ip_src, pkt.ip_dst):
        if ip and is_usable_unicast(ip):
            yield observe(FactKind.ROUTING_SPEAKER, ip, proto="bgp", router_id=None)


def extract_vrrp(pkt: DecodedPacket) -> Iterator[Observation]:
    src = _usable_src(pkt)
    payload = pkt.payload
    if pkt.proto != PROTO_VRRP or src is None or len(payload) < 8:
        return
    if payload[0] >> 4 not in (2, 3):
        return
    count = payload[3]
    vips = tuple(
        ip
        for i in range(count)
        if len(payload) >= 12 + 4 * i
        and is_usable_unicast(ip := socket.inet_ntoa(payload[8 + 4 * i : 12 + 4 * i]))
    )
    yield observe(FactKind.REDUNDANCY_SPEAKER, src, proto="vrrp", group=payload[1], vips=vips)


def extract_hsrp(pkt: DecodedPacket) -> Iterator[Observation]:
    src = _usable_src(pkt)
    if pkt.proto != PROTO_UDP or pkt.sport != PORT_HSRP or pkt.dport != PORT_HSRP or not src:
        return
    vips: tuple[str, ...] = ()
    group = None
    if pkt.ip_dst == _HSRP_V1_GROUP and len(pkt.payload) >= 20:
        group = pkt.payload[6]
        vip = socket.inet_ntoa(pkt.payload[16:20])
        vips = (vip,) if is_usable_unicast(vip) else ()
    yield observe(FactKind.REDUNDANCY_SPEAKER, src, proto="hsrp", group=group, vips=vips)
