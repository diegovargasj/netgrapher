"""ARP facts: IP-to-MAC bindings and on-link queries."""

from __future__ import annotations

from collections.abc import Iterator

from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_group_mac, is_usable_unicast

ARP_REQUEST = 1
ARP_REPLY = 2


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    arp = pkt.arp
    if arp is None or arp.op not in (ARP_REQUEST, ARP_REPLY):
        return
    if is_usable_unicast(arp.spa) and not is_group_mac(arp.sha):
        yield observe(FactKind.ARP_BINDING, arp.spa, mac=arp.sha, vlan=pkt.vlan)
        yield observe(FactKind.IP_SEEN, arp.spa, dir="src")
    if arp.op == ARP_REQUEST and arp.tpa != arp.spa and is_usable_unicast(arp.tpa):
        yield observe(FactKind.ARP_QUERY, arp.tpa, vlan=pkt.vlan)
