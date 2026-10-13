from netgrapher.graph.diff import diff_graphs, migrate_annotations
from netgrapher.graph.model import Entity, EntityType, Graph, Link, LinkType


def host(ip: str, subnet: str = "net:10.0.0.0/24") -> Entity:
    return Entity(f"host:{ip}", EntityType.HOST, 1.0, {"ip": ip, "subnet_id": subnet}, [])


def router(rid: str, *ips: str) -> Entity:
    interfaces = [{"ip": ip, "subnet": None, "confidence": 0.9, "virtual": False} for ip in ips]
    return Entity(rid, EntityType.ROUTER, 0.9, {"interfaces": interfaces}, [])


def subnet(prefix: str) -> Entity:
    return Entity(f"net:{prefix}", EntityType.SUBNET, 0.4, {"prefix": prefix}, [])


def graph(*entities: Entity, links: tuple[Link, ...] = ()) -> Graph:
    return Graph({e.id: e for e in entities}, {lk.id: lk for lk in links}, {})


def test_added_updated_removed() -> None:
    old = graph(subnet("10.0.0.0/24"), host("10.0.0.5"), host("10.0.0.6"))
    changed = host("10.0.0.5")
    changed.confidence = 0.5
    link = Link("lnk:x", LinkType.UPLINK, "net:10.0.0.0/24", "host:10.0.0.7", 1.0)
    new = graph(subnet("10.0.0.0/24"), changed, host("10.0.0.7"), links=(link,))
    d = diff_graphs(old, new)
    assert (d.added, d.updated, d.removed) == (
        ["host:10.0.0.7"],
        ["host:10.0.0.5"],
        ["host:10.0.0.6"],
    )
    assert d.links_added == ["lnk:x"] and not d.aliases
    assert not diff_graphs(new, new)


def test_host_promoted_to_router_is_an_alias() -> None:
    d = diff_graphs(graph(host("10.0.0.1")), graph(router("rtr:10.0.0.1", "10.0.0.1")))
    assert d.aliases == {"host:10.0.0.1": "rtr:10.0.0.1"}


def test_router_merge_is_an_alias() -> None:
    old = graph(router("rtr:10.0.1.1", "10.0.1.1"), router("rtr:10.0.2.1", "10.0.2.1"))
    new = graph(router("rtr:10.0.1.1", "10.0.1.1", "10.0.2.1"))
    assert diff_graphs(old, new).aliases == {"rtr:10.0.2.1": "rtr:10.0.1.1"}


def test_subnet_growth_is_an_alias() -> None:
    d = diff_graphs(graph(subnet("10.0.1.0/24")), graph(subnet("10.0.0.0/23")))
    assert d.aliases == {"net:10.0.1.0/24": "net:10.0.0.0/23"}


def test_annotations_follow_aliases() -> None:
    annotations = {
        "host:10.0.0.1": {"label": "Gateway", "note": "seen first", "hidden": True},
        "rtr:10.0.2.1": {"label": "Branch"},
        "rtr:10.0.1.1": {"label": "Core", "note": "main"},
    }
    conflicts = migrate_annotations(
        annotations, {"host:10.0.0.1": "rtr:10.0.0.1", "rtr:10.0.2.1": "rtr:10.0.1.1"}
    )
    assert annotations["rtr:10.0.0.1"] == {"label": "Gateway", "note": "seen first", "hidden": True}
    assert annotations["rtr:10.0.1.1"]["label"] == "Core"
    assert "Also labelled: Branch" in annotations["rtr:10.0.1.1"]["note"]
    assert "host:10.0.0.1" not in annotations and "rtr:10.0.2.1" not in annotations
    assert len(conflicts) == 1


def test_volatile_last_seen_is_not_a_change() -> None:
    a = host("10.0.0.5")
    a.attrs.update(last_seen=100.0, names=[])
    b = host("10.0.0.5")
    b.attrs.update(last_seen=999.0, names=[])
    # Only last_seen advanced -> not an update, nothing to send.
    assert not diff_graphs(graph(a), graph(b))

    enriched = host("10.0.0.5")
    enriched.attrs.update(last_seen=999.0, names=[{"name": "nas", "source": "dns"}])
    d = diff_graphs(graph(a), graph(enriched))
    assert d.updated == ["host:10.0.0.5"]  # a genuinely new name counts
