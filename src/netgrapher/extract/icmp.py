"""ICMP messages that only routers send."""

from __future__ import annotations

from collections.abc import Iterator

from netgrapher.decode.packet import DecodedPacket
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

ICMP_UNREACHABLE = 3
ICMP_REDIRECT = 5
ICMP_TIME_EXCEEDED = 11

# Net/host unreachable and administratively prohibited come from routers; port unreachable
# (code 3) comes from the destination host itself.
_ROUTER_UNREACHABLE_CODES = frozenset({0, 1, 9, 10, 13})


def extract(pkt: DecodedPacket) -> Iterator[Observation]:
    icmp = pkt.icmp
    src = pkt.ip_src
    if icmp is None or src is None or not is_usable_unicast(src):
        return
    if icmp.type == ICMP_TIME_EXCEEDED and icmp.code == 0:
        yield observe(FactKind.ICMP_TIME_EXCEEDED, src)
    elif icmp.type == ICMP_UNREACHABLE and icmp.code in _ROUTER_UNREACHABLE_CODES:
        yield observe(FactKind.ICMP_UNREACHABLE, src, code=icmp.code)
    elif icmp.type == ICMP_REDIRECT and icmp.gateway and is_usable_unicast(icmp.gateway):
        yield observe(FactKind.ICMP_REDIRECT, src, gateway=icmp.gateway)
