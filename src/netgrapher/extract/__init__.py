"""Per-protocol fact extractors. Stateless: each turns one decoded packet into observations.

See design §5.2.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from netgrapher.decode.packet import DecodedPacket
from netgrapher.extract import arp, dhcp, dns, icmp, ipv4, nbns, routing
from netgrapher.facts.model import Observation

Extractor = Callable[[DecodedPacket], Iterable[Observation]]

# (protocol name used in run statistics, extractor)
EXTRACTORS: tuple[tuple[str, Extractor], ...] = (
    ("ipv4", ipv4.extract),
    ("arp", arp.extract),
    ("icmp", icmp.extract),
    ("dhcp", dhcp.extract),
    ("dns", dns.extract),
    ("nbns", nbns.extract),
    ("ospf", routing.extract_ospf),
    ("eigrp", routing.extract_eigrp),
    ("rip", routing.extract_rip),
    ("bgp", routing.extract_bgp),
    ("vrrp", routing.extract_vrrp),
    ("hsrp", routing.extract_hsrp),
)
