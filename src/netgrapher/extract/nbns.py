"""Names from NetBIOS Name Service (UDP 137): responses, registrations and refreshes."""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator

import dpkt

from netgrapher.decode.decoder import PROTO_UDP
from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

PORT_NBNS = 137
_GROUP_FLAG = 0x8000
# Name suffixes that identify a machine (workstation, server service), not a domain or user.
_MACHINE_SUFFIXES = frozenset({0x00, 0x20})


def _decode_name(encoded: str) -> bytes | None:
    """RFC 1001 first-level decoding of the 32-letter form into 16 raw bytes.

    dpkt.netbios.decode_name strips the trailing suffix byte when it is 0x00, so it is not used.
    """
    label = encoded.split(".", 1)[0].upper()
    if len(label) != 32 or any(not "A" <= c <= "P" for c in label):
        return None
    return bytes(((ord(label[i]) - 65) << 4) | (ord(label[i + 1]) - 65) for i in range(0, 32, 2))


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    if pkt.proto != PROTO_UDP or pkt.sport != PORT_NBNS or not pkt.payload:
        return
    try:
        msg = dpkt.netbios.NS(pkt.payload)
    except (dpkt.UnpackError, struct.error, ValueError, IndexError):
        return
    for rr in [*msg.an, *msg.ar]:
        if rr.type != dpkt.netbios.NS_NB:
            continue
        decoded = _decode_name(rr.name)
        if decoded is None or decoded[15] not in _MACHINE_SUFFIXES:
            continue
        name = decoded[:15].decode("ascii", "replace").rstrip().lower()
        if not name or not name.isprintable():
            continue
        rdata = rr.rdata
        for off in range(0, len(rdata) - len(rdata) % 6, 6):
            (flags,) = struct.unpack_from("!H", rdata, off)
            ip = socket.inet_ntoa(rdata[off + 2 : off + 6])
            if not flags & _GROUP_FLAG and is_usable_unicast(ip):
                yield observe(FactKind.NAME, ip, name=name, source="nbns")
