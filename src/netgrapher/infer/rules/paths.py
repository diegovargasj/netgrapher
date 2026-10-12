"""Paths to remote subnets and the Internet (R-PATH-GW, R-HOP-TTL)."""

from __future__ import annotations

from collections import defaultdict

from netgrapher.facts.model import Fact
from netgrapher.graph.ids import link_id
from netgrapher.graph.model import Link, LinkType
from netgrapher.infer.confidence import noisy_or
from netgrapher.infer.context import Context
from netgrapher.infer.rules.hosts import EXTERNAL_ID


def _gateways(ctx: Context, ips: list[str]) -> dict[str, list[Fact]]:
    """Router entity -> IP_MAC facts showing it forwarded traffic for these addresses."""
    found: defaultdict[str, list[Fact]] = defaultdict(list)
    for ip in ips:
        for mac, facts in ctx.ip_mac.get(ip, {}).items():
            rid = ctx.router_of_mac.get(mac)
            if rid is not None and mac in ctx.router_macs:
                found[rid].extend(facts)
    return found


def build(ctx: Context) -> None:
    members: defaultdict[str, list[str]] = defaultdict(list)
    for ip, sid in ctx.subnet_of.items():
        members[sid].append(ip)

    for sid in sorted(ctx.subnets):
        if ctx.subnets[sid].kind != "remote":
            continue
        ips = ctx.sorted_ips(members[sid])
        hop_values = []
        ttl_facts: list[Fact] = []
        for ip in ips:
            hops, _, facts = ctx.ttl_info(ip)
            if hops is not None:
                hop_values.append(hops)
                ttl_facts.extend(facts)
        hops = min(hop_values) if hop_values else None
        for rid, facts in sorted(_gateways(ctx, ips).items()):
            evidence = [
                ctx.evidence(
                    "R-PATH-GW", f"{rid}>{sid}", facts, f"{rid} forwards traffic for {sid}"
                )
            ]
            basis = ["gateway-mac"]
            if hops is not None:
                evidence.append(
                    ctx.evidence(
                        "R-HOP-TTL", sid, ttl_facts, f"Closest member is {hops} hop(s) away"
                    )
                )
                basis.append("ttl")
            ctx.graph.add_link(
                Link(
                    link_id(LinkType.INFERRED_PATH, rid, sid),
                    LinkType.INFERRED_PATH,
                    rid,
                    sid,
                    noisy_or(ctx.weight_of(evidence)),
                    {"hops": hops, "basis": basis},
                    evidence,
                )
            )

    if EXTERNAL_ID in ctx.graph.entities:
        for rid, facts in sorted(_gateways(ctx, ctx.external_ips()).items()):
            ev = ctx.evidence(
                "R-PATH-GW", f"{rid}>{EXTERNAL_ID}", facts, f"{rid} forwards Internet traffic"
            )
            ctx.graph.add_link(
                Link(
                    link_id(LinkType.UPLINK, rid, EXTERNAL_ID),
                    LinkType.UPLINK,
                    rid,
                    EXTERNAL_ID,
                    noisy_or(ctx.weight_of([ev])),
                    {},
                    [ev],
                )
            )
