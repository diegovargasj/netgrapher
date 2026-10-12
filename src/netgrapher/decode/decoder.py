"""Linktype dispatch and header decoding.

L2-L4 headers are parsed by hand with struct: it is faster than building dpkt objects and gives
full control over truncated or malformed input. Application payloads (DHCP, DNS) are left to
the extractors.
"""

from __future__ import annotations

import socket
import struct

from netgrapher.capture.source import RawPacket
from netgrapher.decode.packet import ArpInfo, DecodedPacket, IcmpInfo

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_DLT12 = 12
LINKTYPE_RAW_DLT14 = 14
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINKTYPES = frozenset(
    {
        LINKTYPE_NULL,
        LINKTYPE_ETHERNET,
        LINKTYPE_RAW_DLT12,
        LINKTYPE_RAW_DLT14,
        LINKTYPE_RAW,
        LINKTYPE_LOOP,
        LINKTYPE_LINUX_SLL,
        LINKTYPE_IPV4,
        LINKTYPE_IPV6,
        LINKTYPE_LINUX_SLL2,
    }
)

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
_ETH_VLAN = (0x8100, 0x88A8, 0x9100)

PROTO_ICMP = 1
PROTO_IPIP = 4
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_GRE = 47

_GRE_TEB = 0x6558  # transparent Ethernet bridging
_MAX_TUNNEL_DEPTH = 2

_ICMP_ERRORS = (3, 5, 11, 12)


class DecodeError(Exception):
    """Malformed packet."""


class UnsupportedLinktype(Exception):
    pass


def _mac(b: bytes) -> str:
    return b.hex(":")


def decode(raw: RawPacket) -> DecodedPacket:
    pkt = DecodedPacket(frame=raw.frame, ts=raw.ts, iface=raw.iface)
    lt = raw.linktype
    buf = raw.data
    if lt == LINKTYPE_ETHERNET:
        _decode_ethernet(pkt, buf)
    elif lt == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            raise DecodeError("short SLL header")
        hatype, alen = struct.unpack_from("!HH", buf, 2)
        if hatype == 1 and alen == 6:
            pkt.src_mac = _mac(buf[6:12])
        _decode_ethertype(pkt, struct.unpack_from("!H", buf, 14)[0], buf[16:])
    elif lt == LINKTYPE_LINUX_SLL2:
        if len(buf) < 20:
            raise DecodeError("short SLL2 header")
        (ethertype,) = struct.unpack_from("!H", buf, 0)
        (hatype,) = struct.unpack_from("!H", buf, 8)
        if hatype == 1 and buf[11] == 6:
            pkt.src_mac = _mac(buf[12:18])
        _decode_ethertype(pkt, ethertype, buf[20:])
    elif lt in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(buf) < 4:
            raise DecodeError("short loopback header")
        _decode_ip_by_version(pkt, buf[4:])
    elif lt in (LINKTYPE_RAW, LINKTYPE_RAW_DLT12, LINKTYPE_RAW_DLT14, LINKTYPE_IPV4, LINKTYPE_IPV6):
        _decode_ip_by_version(pkt, buf)
    else:
        raise UnsupportedLinktype(lt)
    return pkt


def _decode_ethernet(pkt: DecodedPacket, buf: bytes) -> None:
    if len(buf) < 14:
        raise DecodeError("short Ethernet header")
    pkt.dst_mac = _mac(buf[0:6])
    pkt.src_mac = _mac(buf[6:12])
    (ethertype,) = struct.unpack_from("!H", buf, 12)
    offset = 14
    while ethertype in _ETH_VLAN:
        if len(buf) < offset + 4:
            raise DecodeError("short VLAN tag")
        tci, ethertype = struct.unpack_from("!HH", buf, offset)
        if pkt.vlan is None:
            pkt.vlan = tci & 0x0FFF
        offset += 4
    _decode_ethertype(pkt, ethertype, buf[offset:])


def _decode_ethertype(pkt: DecodedPacket, ethertype: int, buf: bytes) -> None:
    if ethertype == ETH_IPV4:
        _decode_ipv4(pkt, buf)
    elif ethertype == ETH_ARP:
        _decode_arp(pkt, buf)
    elif ethertype == ETH_IPV6:
        pkt.is_ipv6 = True


def _decode_ip_by_version(pkt: DecodedPacket, buf: bytes) -> None:
    if not buf:
        raise DecodeError("empty IP packet")
    version = buf[0] >> 4
    if version == 4:
        _decode_ipv4(pkt, buf)
    elif version == 6:
        pkt.is_ipv6 = True
    else:
        raise DecodeError(f"unknown IP version {version}")


def _decode_arp(pkt: DecodedPacket, buf: bytes) -> None:
    if len(buf) < 28:
        raise DecodeError("short ARP packet")
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", buf)
    if htype != 1 or ptype != ETH_IPV4 or hlen != 6 or plen != 4:
        return
    pkt.arp = ArpInfo(
        op=op,
        sha=_mac(buf[8:14]),
        spa=socket.inet_ntoa(buf[14:18]),
        tha=_mac(buf[18:24]),
        tpa=socket.inet_ntoa(buf[24:28]),
    )


def _decode_ipv4(pkt: DecodedPacket, buf: bytes) -> None:
    if len(buf) < 20:
        raise DecodeError("short IPv4 header")
    ver_ihl = buf[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4 or ihl < 20 or len(buf) < ihl:
        raise DecodeError("bad IPv4 header")
    total_len, _, frag, ttl, proto = struct.unpack_from("!HHHBB", buf, 2)
    if total_len < ihl:
        raise DecodeError("bad IPv4 total length")
    pkt.ip_src = socket.inet_ntoa(buf[12:16])
    pkt.ip_dst = socket.inet_ntoa(buf[16:20])
    pkt.ttl = ttl
    pkt.proto = proto
    pkt.ip_len = total_len
    payload = buf[ihl:total_len]  # may be shorter than declared because of the snaplen
    if frag & 0x1FFF:
        return  # non-first fragment: no L4 header
    if proto == PROTO_TCP:
        if len(payload) >= 14:
            pkt.sport, pkt.dport = struct.unpack_from("!HH", payload)
            pkt.tcp_flags = payload[13]
            data_off = (payload[12] >> 4) * 4
            pkt.payload = payload[data_off:] if data_off >= 20 else b""
    elif proto == PROTO_UDP:
        if len(payload) >= 8:
            pkt.sport, pkt.dport = struct.unpack_from("!HH", payload)
            pkt.payload = payload[8:]
    elif proto == PROTO_ICMP:
        if len(payload) >= 2:
            pkt.icmp = _decode_icmp(payload)
    else:
        pkt.payload = payload
        if proto in (PROTO_IPIP, PROTO_GRE) and pkt.tunnel_depth < _MAX_TUNNEL_DEPTH:
            _decode_tunnel(pkt, proto, payload)


def _decode_tunnel(pkt: DecodedPacket, proto: int, payload: bytes) -> None:
    """Decode the inner packet; malformed inner data is ignored, the outer packet stays valid."""
    inner = DecodedPacket(
        frame=pkt.frame,
        ts=pkt.ts,
        iface=pkt.iface,
        vlan=pkt.vlan,
        tunneled=True,
        tunnel_depth=pkt.tunnel_depth + 1,
    )
    try:
        if proto == PROTO_IPIP:
            _decode_ipv4(inner, payload)
        else:
            if len(payload) < 4:
                return
            flags, ethertype = struct.unpack_from("!HH", payload)
            offset = 4 + 4 * sum(1 for bit in (0x8000, 0x2000, 0x1000) if flags & bit)
            if ethertype == _GRE_TEB:
                _decode_ethernet(inner, payload[offset:])
                inner.src_mac = inner.dst_mac = None  # remote L2 addresses: not evidence here
            else:
                _decode_ethertype(inner, ethertype, payload[offset:])
    except DecodeError:
        return
    if inner.ip_src is not None or inner.arp is not None or inner.is_ipv6:
        pkt.inner = inner


def _decode_icmp(buf: bytes) -> IcmpInfo:
    info = IcmpInfo(type=buf[0], code=buf[1])
    if info.type == 5 and len(buf) >= 8:
        info.gateway = socket.inet_ntoa(buf[4:8])
    if info.type in _ICMP_ERRORS and len(buf) >= 28 and buf[8] >> 4 == 4:
        info.inner_src = socket.inet_ntoa(buf[20:24])
        info.inner_dst = socket.inet_ntoa(buf[24:28])
        info.inner_proto = buf[17]
    return info
