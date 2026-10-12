"""Subnet discovery and IP-to-subnet assignment (R-SUB-*)."""

from __future__ import annotations

import contextlib
import ipaddress
from collections import defaultdict

from netgrapher.facts.model import Fact, FactKind
from netgrapher.graph.ids import subnet_id
from netgrapher.infer.confidence import noisy_or
from netgrapher.infer.context import Context, SubnetInfo, Vlan, vlan_key

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_PREFIXLEN = 24
MIN_INFERRED_PREFIXLEN = 16
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")


def find_onlink(ctx: Context) -> None:
    """IPs proven to share a segment with the capture point, keyed to that segment's VLAN.

    Evidence: an ARP binding, or L2 frames addressed to/from a MAC that is not a router MAC.
    """
    for ip in ctx.internal_ips():
        vlans: set[Vlan] = set()
        for facts in ctx.arp.get(ip, {}).values():
            vlans.update(f.get("vlan") for f in facts)
        for mac, facts in ctx.ip_mac.get(ip, {}).items():
            if mac not in ctx.router_macs:
                vlans.update(f.get("vlan") for f in facts)
        if not vlans and ip not in ctx.ip_mac:
            # No L2 information at all (raw IP capture): zero hops means on-link.
            hops, _, _ = ctx.ttl_info(ip)
            if hops == 0:
                vlans.add(None)
        if vlans:
            ctx.onlink[ip] = min(vlans, key=vlan_key)


def _known_prefixes(ctx: Context) -> dict[Network, list[tuple[str, Fact | None]]]:
    found: defaultdict[Network, list[tuple[str, Fact | None]]] = defaultdict(list)
    for lease in ctx.store.by_kind(FactKind.DHCP_LEASE):
        mask = lease.get("mask")
        if mask:
            with contextlib.suppress(ValueError):
                net = ipaddress.ip_network(f"{lease.subject}/{mask}", strict=False)
                found[net].append(("R-SUB-DHCP", lease))
    for hint in ctx.store.by_kind(FactKind.SUBNET_HINT):
        try:
            net = ipaddress.ip_network(f"{hint.subject}/{hint.get('mask')}", strict=False)
        except ValueError:
            continue
        found[net].append(("R-SUB-OSPF", hint))
    if any(ipaddress.ip_address(ip) in _LINK_LOCAL for ip in ctx.all_ips):
        found[_LINK_LOCAL].append(("R-SUB-WELLKNOWN", None))
    return found


_SUMMARIES = {
    "R-SUB-DHCP": "DHCP lease with subnet mask ({n} message types/clients)",
    "R-SUB-OSPF": "OSPF Hello network mask ({n} speakers)",
    "R-SUB-WELLKNOWN": "IPv4 link-local range (RFC 3927)",
}


def _fit(ip: str, prefixlen: int, taken: list[Network]) -> Network:
    """Largest prefix around ip, no shorter than prefixlen, that overlaps no taken network."""
    for plen in range(prefixlen, 33):
        net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
        if not any(net.overlaps(t) for t in taken):
            return net
    return ipaddress.ip_network(f"{ip}/32")


def _common_prefixlen(ips: list[str]) -> int:
    values = [int(ipaddress.ip_address(ip)) for ip in ips]
    return 32 - (min(values) ^ max(values)).bit_length()


def assign(ctx: Context) -> None:
    known = _known_prefixes(ctx)
    infos: dict[Network, SubnetInfo] = {}
    for net in sorted(known, key=lambda n: (n.network_address, n.prefixlen)):
        by_rule: defaultdict[str, list[Fact]] = defaultdict(list)
        for rule, fact in known[net]:
            by_rule[rule].extend([fact] if fact else [])
        evidence = [
            ctx.evidence(rule, str(net), facts, _SUMMARIES[rule].format(n=len(facts)))
            for rule, facts in sorted(by_rule.items())
        ]
        infos[net] = SubnetInfo(net, "local", evidence, noisy_or(ctx.weight_of(evidence)))

    members: defaultdict[Network, list[str]] = defaultdict(list)
    unassigned: list[str] = []
    for ip in ctx.internal_ips():
        addr = ipaddress.ip_address(ip)
        candidates = [n for n in infos if addr in n]
        if candidates:
            best = max(candidates, key=lambda n: (infos[n].confidence, n.prefixlen))
            members[best].append(ip)
        else:
            unassigned.append(ip)

    taken: list[Network] = list(infos)
    inferred: dict[Network, str] = {}  # network -> rule

    def place(ip: str, prefixlen: int, rule: str) -> None:
        addr = ipaddress.ip_address(ip)
        existing = next((n for n in inferred if addr in n), None)
        net = existing or _fit(ip, prefixlen, taken)
        if existing is None:
            taken.append(net)
            inferred[net] = rule
        members[net].append(ip)

    # On-link addresses: one segment per VLAN, sized to cover the observed addresses.
    segments: defaultdict[Vlan, list[str]] = defaultdict(list)
    for ip in unassigned:
        if ip in ctx.onlink:
            segments[ctx.onlink[ip]].append(ip)
    for vlan in sorted(segments, key=vlan_key):
        ips = segments[vlan]
        plen = min(DEFAULT_PREFIXLEN, _common_prefixlen(ips))
        if plen < MIN_INFERRED_PREFIXLEN:
            plen = DEFAULT_PREFIXLEN  # probably several subnets on one segment
        for ip in ips:
            place(ip, plen, "R-SUB-ONLINK")
    # Off-link private addresses: assume /24.
    for ip in unassigned:
        if ip not in ctx.onlink:
            place(ip, DEFAULT_PREFIXLEN, "R-SUB-HEUR")

    for net in sorted(inferred, key=lambda n: (n.network_address, n.prefixlen)):
        rule = inferred[net]
        ips = members[net]
        facts = [f for ip in ips for f in ctx.facts_about(ip)]
        if rule == "R-SUB-ONLINK":
            summary = f"{len(ips)} on-link addresses; prefix length is an estimate"
        else:
            summary = f"{len(ips)} off-link private addresses; /{net.prefixlen} assumed"
        evidence = [ctx.evidence(rule, str(net), facts, summary)]
        infos[net] = SubnetInfo(net, "local", evidence, noisy_or(ctx.weight_of(evidence)))

    for net, info in infos.items():
        sid = subnet_id(str(net))
        if not any(ip in ctx.onlink for ip in members[net]) and not any(
            rule == "R-SUB-DHCP" for rule, _ in known.get(net, [])
        ):
            info.kind = "remote"
        ctx.subnets[sid] = info
        for ip in members[net]:
            ctx.subnet_of[ip] = sid
