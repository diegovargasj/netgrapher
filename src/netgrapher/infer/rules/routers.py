"""Router identification (R-RTR-*), alias resolution (R-ALIAS-*) and router entities."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from netgrapher.facts.model import Fact, FactKind
from netgrapher.graph.ids import link_id, router_id
from netgrapher.graph.model import Entity, EntityType, Link, LinkType
from netgrapher.infer.confidence import noisy_or
from netgrapher.infer.context import Context
from netgrapher.net import ip_sort_key, is_virtual_mac

# A MAC that carries traffic for this many addresses other than its own is a router MAC.
ROUTER_MAC_MIN_IPS = 3

_SUMMARIES = {
    "R-RTR-DHCP": "Announced as router (DHCP option 3) in {n} lease(s)",
    "R-RTR-ICMP": "Sent {n} kind(s) of router-only ICMP (time exceeded, unreachable, redirect)",
    "R-RTR-PROTO": "Routing/redundancy protocol speaker ({n} observation(s))",
    "R-RTR-MAC": "Its MAC forwards traffic for many other addresses",
}


def detect_router_macs(ctx: Context) -> None:
    for mac, ips in ctx.ips_by_mac.items():
        foreign = ips - ctx.arp_ips_by_mac.get(mac, set())
        if len(foreign) >= ROUTER_MAC_MIN_IPS:
            ctx.router_macs[mac] = foreign


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb, key=ip_sort_key)] = min(ra, rb, key=ip_sort_key)


def build(ctx: Context) -> None:
    claims: defaultdict[str, defaultdict[str, list[Fact]]] = defaultdict(lambda: defaultdict(list))

    for lease in ctx.store.by_kind(FactKind.DHCP_LEASE):
        for ip in lease.get("routers", ()):
            claims[ip]["R-RTR-DHCP"].append(lease)
            ctx.dhcp_router_ips.add(ip)
    for kind in (FactKind.ICMP_TIME_EXCEEDED, FactKind.ICMP_UNREACHABLE, FactKind.ICMP_REDIRECT):
        for f in ctx.store.by_kind(kind):
            claims[f.subject]["R-RTR-ICMP"].append(f)
            if kind is FactKind.ICMP_REDIRECT:
                claims[f.get("gateway")]["R-RTR-ICMP"].append(f)
    router_ids: defaultdict[str, set[str]] = defaultdict(set)
    protocols: defaultdict[str, set[str]] = defaultdict(set)
    for f in ctx.store.by_kind(FactKind.ROUTING_SPEAKER):
        claims[f.subject]["R-RTR-PROTO"].append(f)
        protocols[f.subject].add(f.get("proto"))
        if f.get("router_id"):
            router_ids[f.subject].add(f.get("router_id"))
    vip_advertisers: defaultdict[str, set[str]] = defaultdict(set)
    for f in ctx.store.by_kind(FactKind.REDUNDANCY_SPEAKER):
        claims[f.subject]["R-RTR-PROTO"].append(f)
        protocols[f.subject].add(f.get("proto"))
        for vip in f.get("vips", ()):
            claims[vip]["R-RTR-PROTO"].append(f)
            if vip != f.subject:
                vip_advertisers[vip].add(f.subject)

    own_ips_by_mac: dict[str, set[str]] = {}
    for mac in sorted(ctx.router_macs):
        own = ctx.arp_ips_by_mac.get(mac, set()) | (
            ctx.ips_by_mac.get(mac, set()) & ctx.dhcp_router_ips
        )
        own_ips_by_mac[mac] = own
        for ip in own:
            claims[ip]["R-RTR-MAC"].extend(ctx.arp.get(ip, {}).get(mac, []))
            claims[ip]["R-RTR-MAC"].extend(ctx.ip_mac.get(ip, {}).get(mac, []))

    evidence_of: dict[str, list[str]] = {}
    for ip in ctx.sorted_ips(claims):
        evidence_of[ip] = [
            ctx.evidence(rule, ip, facts, _SUMMARIES[rule].format(n=len(facts)))
            for rule, facts in sorted(claims[ip].items())
        ]

    vips = set(vip_advertisers)
    real = ctx.sorted_ips(ip for ip in claims if ip not in vips)
    uf = _UnionFind(real)
    alias_evidence: defaultdict[str, list[str]] = defaultdict(list)

    by_router_id: defaultdict[str, list[str]] = defaultdict(list)
    for ip in real:
        for rid in router_ids.get(ip, ()):
            by_router_id[rid].append(ip)
    for rid, ips in sorted(by_router_id.items()):
        if len(ips) > 1:
            facts = [
                f
                for f in ctx.store.by_kind(FactKind.ROUTING_SPEAKER)
                if f.subject in ips and f.get("router_id") == rid
            ]
            ev = ctx.evidence("R-ALIAS-ID", rid, facts, f"Same router ID {rid}")
            for ip in ips[1:]:
                uf.union(ips[0], ip)
            for ip in ips:
                alias_evidence[ip].append(ev)
    for mac, ips_set in sorted(ctx.arp_ips_by_mac.items()):
        ips = ctx.sorted_ips(ip for ip in ips_set if ip in uf.parent)
        if len(ips) > 1 and not is_virtual_mac(mac):
            facts = [f for ip in ips for f in ctx.arp[ip][mac]]
            ev = ctx.evidence("R-ALIAS-MAC", mac, facts, f"Addresses share MAC {mac}")
            for ip in ips[1:]:
                uf.union(ips[0], ip)
            for ip in ips:
                alias_evidence[ip].append(ev)

    groups: defaultdict[str, list[str]] = defaultdict(list)
    for ip in real:
        groups[uf.find(ip)].append(ip)

    for group in groups.values():
        canonical = min(group, key=lambda ip: (ctx.first_seen(ip), ip_sort_key(ip)))
        rid = router_id(canonical)
        interfaces = []
        evidence: list[str] = []
        for ip in group:
            interfaces.append(_interface(ctx, ip, evidence_of[ip], virtual=False))
            evidence.extend(evidence_of[ip])
        group_vips = ctx.sorted_ips(v for v in vips if vip_advertisers[v] & set(group))
        for vip in group_vips:
            interfaces.append(_interface(ctx, vip, evidence_of[vip], virtual=True))
            evidence.extend(evidence_of[vip])
        confidence = noisy_or(ctx.weight_of(dict.fromkeys(evidence)))
        aliases = sorted({e for ip in group for e in alias_evidence[ip]})
        macs = sorted({mac for ip in group for mac in ctx.arp.get(ip, {})})
        hops = [h for ip in group if (h := ctx.ttl_info(ip)[0]) is not None]
        names = sorted(
            {(n["name"], n["source"]) for ip in [*group, *group_vips] for n in ctx.names(ip)}
        )
        roles = {r for ip in [*group, *group_vips] for r in ctx.roles(ip)}
        if ctx.dhcp_router_ips & {*group, *group_vips}:
            roles.add("default-gateway")
        ctx.graph.add_entity(
            Entity(
                rid,
                EntityType.ROUTER,
                confidence,
                {
                    "interfaces": interfaces,
                    "router_ids": sorted({r for ip in group for r in router_ids.get(ip, ())}),
                    "names": [{"name": n, "source": s} for n, s in names],
                    "protocols": sorted({p for ip in group for p in protocols.get(ip, ())}),
                    "roles": sorted(roles),
                    "hop_distance": min(hops) if hops else None,
                    "l2_evidence": {"macs": macs},
                },
                sorted(dict.fromkeys(evidence)) + aliases,
            )
        )
        ctx.router_ips.update(group)
        ctx.router_ips.update(group_vips)
        for mac in macs:
            ctx.router_of_mac.setdefault(mac, rid)
        for mac, own in own_ips_by_mac.items():
            if own & set(group):
                ctx.router_of_mac.setdefault(mac, rid)
        for vip in group_vips:
            for mac in ctx.arp.get(vip, {}):
                ctx.router_of_mac.setdefault(mac, rid)
        for iface in interfaces:
            if iface["subnet"]:
                ctx.graph.add_link(
                    Link(
                        link_id(LinkType.INTERFACE, rid, iface["subnet"]) + f"#{iface['ip']}",
                        LinkType.INTERFACE,
                        rid,
                        iface["subnet"],
                        iface["confidence"],
                        {"ip": iface["ip"], "virtual": iface["virtual"]},
                        evidence_of[iface["ip"]],
                    )
                )

    _unknown_routers(ctx, own_ips_by_mac)


def _interface(ctx: Context, ip: str, evidence: list[str], *, virtual: bool) -> dict[str, Any]:
    return {
        "ip": ip,
        "subnet": ctx.subnet_of.get(ip),
        "confidence": noisy_or(ctx.weight_of(evidence)),
        "virtual": virtual,
    }


def _unknown_routers(ctx: Context, own_ips_by_mac: dict[str, set[str]]) -> None:
    """Router MACs whose IP address was never observed."""
    for mac in sorted(ctx.router_macs):
        if own_ips_by_mac.get(mac) or mac in ctx.router_of_mac:
            continue
        uid = "unk:" + hashlib.sha1(mac.encode()).hexdigest()[:10]
        carried = ctx.router_macs[mac]
        facts = [f for ip in ctx.sorted_ips(carried) for f in ctx.ip_mac[ip][mac]]
        ev = ctx.evidence(
            "R-RTR-MAC",
            mac,
            facts,
            f"MAC {mac} forwards traffic for {len(carried)} addresses; its IP is unknown",
        )
        ctx.graph.add_entity(
            Entity(
                uid,
                EntityType.UNKNOWN_ROUTER,
                noisy_or(ctx.weight_of([ev])),
                {"reason": "gateway-mac-without-ip", "l2_evidence": {"macs": [mac]}},
                [ev],
            )
        )
        ctx.router_of_mac[mac] = uid
        vlans = ctx.vlans_by_mac.get(mac, set())
        local = sorted(
            {
                ctx.subnet_of[ip]
                for ip, vlan in ctx.onlink.items()
                if vlan in vlans and ip in ctx.subnet_of
            }
        )
        for sid in local:
            ctx.graph.add_link(
                Link(
                    link_id(LinkType.INTERFACE, uid, sid),
                    LinkType.INTERFACE,
                    uid,
                    sid,
                    noisy_or(ctx.weight_of([ev])),
                    {"ip": None, "virtual": False},
                    [ev],
                )
            )
