"""DHCP facts: leases (address, mask, routers, DNS servers), client hostnames, servers."""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator

import dpkt

from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

_PORTS = frozenset({67, 68})

OPT_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54

MSG_DISCOVER, MSG_OFFER, MSG_REQUEST, MSG_ACK, MSG_INFORM = 1, 2, 3, 5, 8
_BOOTREPLY = 2


def _ip_list(value: bytes) -> tuple[str, ...]:
    return tuple(
        socket.inet_ntoa(value[i : i + 4]) for i in range(0, len(value) - len(value) % 4, 4)
    )


def _int_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    if pkt.sport not in _PORTS or pkt.dport not in _PORTS or not pkt.payload:
        return
    try:
        msg = dpkt.dhcp.DHCP(pkt.payload)
    except (dpkt.UnpackError, struct.error, ValueError):
        return
    opts = dict(msg.opts)
    msg_type = opts.get(OPT_MSG_TYPE, b"\x00")[0]
    chaddr = msg.chaddr[:6].hex(":")

    if msg.op == _BOOTREPLY and msg_type in (MSG_OFFER, MSG_ACK):
        server = (
            _ip_list(opts[OPT_SERVER_ID])[0] if len(opts.get(OPT_SERVER_ID, b"")) >= 4 else None
        )
        server = server or pkt.ip_src
        if server and is_usable_unicast(server):
            yield observe(FactKind.SERVICE, server, service="dhcp")
        yiaddr = _int_ip(msg.yiaddr)
        if is_usable_unicast(yiaddr):
            mask = _ip_list(opts[OPT_MASK])[0] if len(opts.get(OPT_MASK, b"")) >= 4 else None
            yield observe(
                FactKind.DHCP_LEASE,
                yiaddr,
                msg="ack" if msg_type == MSG_ACK else "offer",
                mask=mask,
                routers=_ip_list(opts.get(OPT_ROUTER, b"")),
                dns=_ip_list(opts.get(OPT_DNS, b"")),
                server=server,
                chaddr=chaddr,
            )
        return

    hostname = opts.get(OPT_HOSTNAME)
    if msg_type in (MSG_DISCOVER, MSG_REQUEST, MSG_INFORM) and hostname:
        name = hostname.rstrip(b"\x00").decode("utf-8", "replace").strip().lower()
        if name:
            yield observe(FactKind.DHCP_HOSTNAME, chaddr, name=name)
            requested = opts.get(OPT_REQUESTED_IP, b"")
            client_ip = _ip_list(requested)[0] if len(requested) >= 4 else _int_ip(msg.ciaddr)
            if is_usable_unicast(client_ip):
                yield observe(FactKind.NAME, client_ip, name=name, source="dhcp")
