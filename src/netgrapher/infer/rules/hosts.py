"""Host entities (R-HOST-*) and the external-network entity (R-EXT)."""

from __future__ import annotations

from netgrapher.facts.model import FactKind
from netgrapher.graph.ids import host_id, link_id
from netgrapher.graph.model import Entity, EntityType, Link, LinkType
from netgrapher.infer.confidence import noisy_or
from netgrapher.infer.context import Context

EXTERNAL_ID = "ext:internet"
MAX_EXTERNAL_ADDRESSES = 1000


def build(ctx: Context) -> None:
    for ip in ctx.internal_ips():
        sid = ctx.subnet_of.get(ip)
        if sid is None or ip in ctx.router_ips:
            continue
        seen = ctx.seen.get(ip, {})
        if ip in ctx.self_ips:
            ev = ctx.evidence("R-HOST-SELF", ip, ctx.self_ips[ip], "The capture host itself")
        elif ip in ctx.alive:
            facts = [f for f in ctx.store.by_kind(FactKind.PROBE_ALIVE) if f.subject == ip]
            ev = ctx.evidence("R-HOST-PROBE", ip, facts, "Responded to an active probe")
        elif "src" in seen or ip in ctx.arp:
            facts = [seen["src"]] if "src" in seen else []
            for mac_facts in ctx.arp.get(ip, {}).values():
                facts.extend(mac_facts)
            ev = ctx.evidence("R-HOST-OBS", ip, facts, "Sent traffic")
        else:
            facts = list(seen.values())
            ev = ctx.evidence("R-HOST-REF", ip, facts, "Only seen as a destination or reference")
        hops, os_family, _ = ctx.ttl_info(ip)
        macs = {mac for mac in ctx.arp.get(ip, {})}
        macs.update(mac for mac in ctx.ip_mac.get(ip, {}) if mac not in ctx.router_macs)
        hid = host_id(ip)
        ctx.graph.add_entity(
            Entity(
                hid,
                EntityType.HOST,
                noisy_or(ctx.weight_of([ev])),
                {
                    "ip": ip,
                    "subnet_id": sid,
                    "is_self": ip in ctx.self_ips,
                    "names": ctx.names(ip),
                    "hop_distance": hops,
                    "os_family_guess": os_family,
                    "roles": ctx.roles(ip),
                    "first_seen": _finite(ctx.first_seen(ip)),
                    "last_seen": ctx.last_seen(ip),
                    "l2_evidence": {"macs": sorted(macs)},
                },
                [ev],
            )
        )
        subnet = ctx.subnets[sid]
        ctx.graph.add_link(
            Link(
                link_id(LinkType.MEMBER, hid, sid),
                LinkType.MEMBER,
                hid,
                sid,
                subnet.confidence,
                {},
                list(subnet.evidence),
            )
        )

    external = ctx.external_ips()
    if external:
        facts = [f for ip in external for f in ctx.facts_about(ip)]
        ev = ctx.evidence(
            "R-EXT", EXTERNAL_ID, facts, f"{len(external)} globally routable addresses"
        )
        ctx.graph.add_entity(
            Entity(
                EXTERNAL_ID,
                EntityType.EXTERNAL,
                noisy_or(ctx.weight_of([ev])),
                {
                    "asn": None,
                    "as_name": None,
                    "host_count": len(external),
                    "addresses": external[:MAX_EXTERNAL_ADDRESSES],
                },
                [ev],
            )
        )


def _finite(value: float) -> float | None:
    return None if value == float("inf") else value
