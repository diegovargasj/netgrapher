"""Runs the inference stages over a fact-store snapshot and produces the graph. See design §7.

Stage order matters: router MACs decide which addresses are on-link, on-link addresses shape
the subnets, subnets locate router interfaces, and everything else hangs off routers and
subnets.
"""

from __future__ import annotations

from netgrapher.facts.model import FactKind
from netgrapher.facts.store import FactStore
from netgrapher.graph.ids import subnet_id
from netgrapher.graph.model import Entity, EntityType, Graph, LinkType
from netgrapher.infer.context import Context
from netgrapher.infer.rules import hosts, paths, routers, subnets


def infer(store: FactStore) -> Graph:
    ctx = Context(store)
    routers.detect_router_macs(ctx)
    subnets.find_onlink(ctx)
    subnets.assign(ctx)
    routers.build(ctx)
    hosts.build(ctx)
    paths.build(ctx)
    _add_subnet_entities(ctx)
    return _sorted(ctx.graph)


def _add_subnet_entities(ctx: Context) -> None:
    gateways: dict[str, set[str]] = {sid: set() for sid in ctx.subnets}
    for link in ctx.graph.links.values():
        if link.type is LinkType.INTERFACE:
            gateways[link.b].add(link.a)
    dhcp_servers: dict[str, set[str]] = {sid: set() for sid in ctx.subnets}
    for lease in ctx.store.by_kind(FactKind.DHCP_LEASE):
        sid = ctx.subnet_of.get(lease.subject)
        if sid and lease.get("server"):
            dhcp_servers[sid].add(lease.get("server"))
    for sid, info in ctx.subnets.items():
        assert sid == subnet_id(str(info.network))
        ctx.graph.add_entity(
            Entity(
                sid,
                EntityType.SUBNET,
                info.confidence,
                {
                    "prefix": str(info.network),
                    "version": info.network.version,
                    "prefix_confidence": info.confidence,
                    "kind": info.kind,
                    "gateway_ids": sorted(gateways[sid]),
                    "dhcp_servers": ctx.sorted_ips(dhcp_servers[sid]),
                },
                list(info.evidence),
            )
        )


def _sorted(graph: Graph) -> Graph:
    return Graph(
        entities=dict(sorted(graph.entities.items())),
        links=dict(sorted(graph.links.items())),
        evidence=dict(sorted(graph.evidence.items())),
    )
