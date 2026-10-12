"""IPv4 header facts: addresses, IP-to-MAC co-occurrence, TTLs."""

from __future__ import annotations

from collections.abc import Iterator

from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_group_mac, is_usable_unicast


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    src, dst = pkt.ip_src, pkt.ip_dst
    if src is None or dst is None:
        return
    dst_is_group = pkt.dst_mac is not None and is_group_mac(pkt.dst_mac)
    if is_usable_unicast(src):
        yield observe(FactKind.IP_SEEN, src, dir="src")
        if pkt.src_mac is not None and not is_group_mac(pkt.src_mac):
            yield observe(FactKind.IP_MAC, src, mac=pkt.src_mac, vlan=pkt.vlan, dir="src")
        # TTLs of multicast/broadcast packets are often protocol-specific (1, 255): skip them.
        if not dst_is_group and is_usable_unicast(dst):
            yield observe(FactKind.TTL_OBSERVED, src, ttl=pkt.ttl)
    if not dst_is_group and is_usable_unicast(dst):
        yield observe(FactKind.IP_SEEN, dst, dir="dst")
        if pkt.dst_mac is not None:
            yield observe(FactKind.IP_MAC, dst, mac=pkt.dst_mac, vlan=pkt.vlan, dir="dst")
