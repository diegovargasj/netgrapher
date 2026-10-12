"""Names from DNS, mDNS and LLMNR responses; DNS servers."""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Iterator

import dpkt

from netgrapher.decode.decoder import PROTO_TCP, PROTO_UDP
from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

_SOURCES = {53: "dns", 5353: "mdns", 5355: "llmnr"}
_TYPE_A = 1
_TYPE_PTR = 12


def _ptr_to_ip(name: str) -> str | None:
    suffix = ".in-addr.arpa"
    if not name.endswith(suffix):
        return None
    parts = name[: -len(suffix)].split(".")
    if len(parts) != 4:
        return None
    try:
        return str(ipaddress.IPv4Address(".".join(reversed(parts))))
    except ValueError:
        return None


def _clean(name: str) -> str:
    return name.rstrip(".").lower()


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    source = _SOURCES.get(pkt.sport or -1)
    if source is None or not pkt.payload:
        return
    payload = pkt.payload
    if pkt.proto == PROTO_TCP:
        payload = payload[2:]  # length prefix
    elif pkt.proto != PROTO_UDP:
        return
    try:
        msg = dpkt.dns.DNS(payload)
    except (dpkt.UnpackError, struct.error, ValueError, IndexError):
        return
    if msg.qr != dpkt.dns.DNS_R:
        return
    if source == "dns" and pkt.ip_src and is_usable_unicast(pkt.ip_src):
        yield observe(FactKind.SERVICE, pkt.ip_src, service="dns")
    for rr in [*msg.an, *msg.ar]:
        if rr.type == _TYPE_A and len(getattr(rr, "ip", b"")) == 4:
            ip = socket.inet_ntoa(rr.ip)
            name = _clean(rr.name)
            if name and is_usable_unicast(ip):
                yield observe(FactKind.NAME, ip, name=name, source=source)
        elif rr.type == _TYPE_PTR:
            ptr_ip = _ptr_to_ip(_clean(rr.name))
            target = _clean(getattr(rr, "ptrname", ""))
            if ptr_ip and target and is_usable_unicast(ptr_ip):
                yield observe(FactKind.NAME, ptr_ip, name=target, source=f"{source}-ptr")
