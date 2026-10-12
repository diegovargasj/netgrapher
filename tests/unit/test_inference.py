import struct

from synthetic import (
    BROADCAST,
    GW,
    LAPTOP,
    PRINTER,
    arp,
    eth,
    graph_from_frames,
    ip4,
    ipv4,
    office_frames,
    ospf_hello,
    tcp,
)

from netgrapher.graph.model import EntityType, LinkType

GW_MAC, A_MAC, B_MAC = "02:00:00:00:00:01", "02:00:00:00:00:0a", "02:00:00:00:00:0b"


def office():  # type: ignore[no-untyped-def]
    return graph_from_frames([frame for _, frame in office_frames()])


def test_office_subnets() -> None:
    g = office()
    lan = g.entities["net:192.168.1.0/24"]
    assert lan.attrs["kind"] == "local"
    assert lan.attrs["gateway_ids"] == ["rtr:192.168.1.1"]
    assert lan.attrs["dhcp_servers"] == [GW]
    assert lan.confidence > 0.99  # DHCP + OSPF masks agree
    remote = g.entities["net:10.20.0.0/24"]
    assert remote.attrs["kind"] == "remote"
    assert remote.confidence == 0.2  # /24 is only assumed


def test_office_gateway() -> None:
    g = office()
    gw = g.entities["rtr:192.168.1.1"]
    assert gw.type is EntityType.ROUTER
    assert gw.attrs["roles"] == ["default-gateway", "dhcp-server", "dns-server"]
    assert gw.attrs["protocols"] == ["ospf"]
    assert gw.attrs["router_ids"] == ["10.255.0.1"]
    rules = {g.evidence[e].rule for e in gw.evidence}
    assert rules == {"R-RTR-DHCP", "R-RTR-MAC", "R-RTR-PROTO"}


def test_office_hosts_and_paths() -> None:
    g = office()
    laptop = g.entities[f"host:{LAPTOP}"]
    assert laptop.attrs["names"] == [{"name": "alice-laptop", "source": "dhcp"}]
    assert laptop.attrs["hop_distance"] == 0
    assert g.entities[f"host:{PRINTER}"].attrs["names"][0]["name"] == "printer.local"
    win = g.entities["host:10.20.0.5"]
    assert (win.attrs["hop_distance"], win.attrs["os_family_guess"]) == (3, "windows")

    path = g.links["lnk:inferred-path:rtr:192.168.1.1|net:10.20.0.0/24"]
    assert path.type is LinkType.INFERRED_PATH
    assert path.attrs == {"hops": 3, "basis": ["gateway-mac", "ttl"]}
    assert "lnk:uplink:rtr:192.168.1.1|ext:internet" in g.links
    assert g.entities["ext:internet"].attrs["addresses"] == ["8.8.8.8", "93.184.215.14"]
    # The router that sent ICMP time exceeded sits in an assumed remote /24.
    assert "lnk:interface:rtr:10.0.0.2|net:10.0.0.0/24#10.0.0.2" in g.links
    # No entity for the gateway as a host, nor for the quoted traceroute destination.
    assert f"host:{GW}" not in g.entities
    assert not any("10.30.0.9" in eid for eid in g.entities)


def test_gateway_without_ip_becomes_unknown_router() -> None:
    frames = [eth(A_MAC, B_MAC, tcp("10.1.0.10", "10.1.0.11", 1, 2))]
    for i, remote in enumerate(["8.8.8.8", "1.1.1.1", "9.9.9.9"]):
        frames.append(eth(A_MAC, GW_MAC, tcp("10.1.0.10", remote, 1000 + i, 443)))
    g = graph_from_frames(frames)
    unknown = [e for e in g.entities.values() if e.type is EntityType.UNKNOWN_ROUTER]
    assert len(unknown) == 1
    uid = unknown[0].id
    assert unknown[0].attrs["l2_evidence"] == {"macs": [GW_MAC]}
    assert f"lnk:interface:{uid}|net:10.1.0.0/24" in g.links
    assert f"lnk:uplink:{uid}|ext:internet" in g.links
    # On-link hosts get an estimated subnet.
    assert g.entities["net:10.1.0.0/24"].attrs["kind"] == "local"


def test_router_aliases_merge_by_ospf_router_id() -> None:
    frames = [
        eth(
            GW_MAC,
            "01:00:5e:00:00:05",
            ipv4("10.0.1.1", "224.0.0.5", ospf_hello("9.9.9.9", "255.255.255.0"), 89, 1),
        ),
        eth(
            "02:00:00:00:00:02",
            "01:00:5e:00:00:05",
            ipv4("10.0.2.1", "224.0.0.5", ospf_hello("9.9.9.9", "255.255.255.0"), 89, 1),
        ),
    ]
    g = graph_from_frames(frames)
    routers = [e for e in g.entities.values() if e.type is EntityType.ROUTER]
    assert [r.id for r in routers] == ["rtr:10.0.1.1"]
    assert [i["ip"] for i in routers[0].attrs["interfaces"]] == ["10.0.1.1", "10.0.2.1"]
    assert any(g.evidence[e].rule == "R-ALIAS-ID" for e in routers[0].evidence)


def test_vrrp_virtual_address_is_an_interface_of_its_advertiser() -> None:
    vrrp = struct.pack("!BBBBBBH", 0x21, 1, 100, 1, 0, 1, 0) + ip4("10.0.0.254") + b"\x00" * 8
    frames = [
        eth(
            "02:00:00:00:00:02", "01:00:5e:00:00:12", ipv4("10.0.0.2", "224.0.0.18", vrrp, 112, 255)
        )
    ]
    g = graph_from_frames(frames)
    router = g.entities["rtr:10.0.0.2"]
    assert [(i["ip"], i["virtual"]) for i in router.attrs["interfaces"]] == [
        ("10.0.0.2", False),
        ("10.0.0.254", True),
    ]
    assert "host:10.0.0.254" not in g.entities


def test_arp_scan_targets_do_not_become_hosts() -> None:
    frames = [
        eth(
            A_MAC, BROADCAST, arp(1, A_MAC, "10.2.0.10", "00:00:00:00:00:00", f"10.2.0.{i}"), 0x0806
        )
        for i in range(20, 30)
    ]
    g = graph_from_frames(frames)
    assert [e for e in g.entities if e.startswith("host:")] == ["host:10.2.0.10"]


def test_inferred_subnets_do_not_overlap_known_ones() -> None:
    import ipaddress

    from netgrapher.infer.rules.subnets import _fit

    taken = [ipaddress.ip_network("10.0.0.0/25")]
    assert str(_fit("10.0.0.200", 24, taken)) == "10.0.0.128/25"


def test_inference_is_deterministic() -> None:
    first, second = office(), office()
    assert list(first.entities) == list(second.entities)
    assert list(first.evidence) == list(second.evidence)


def graph_from_observations(observations):  # type: ignore[no-untyped-def]
    """Build a graph from probe observations (provenance probe)."""
    from netgrapher.facts.model import Provenance
    from netgrapher.facts.store import FactStore
    from netgrapher.infer.engine import infer

    store = FactStore()
    for i, obs in enumerate(observations):
        store.add(obs, ts=1_760_000_000.0 + i, frame=None, run_id="r1", provenance=Provenance.PROBE)
    return infer(store)


def test_trace_hops_become_routers_and_a_chain() -> None:
    from netgrapher.facts.model import FactKind, observe

    obs = [
        observe(FactKind.TRACE_HOP, "10.0.0.1", ttl=1, target="10.20.0.5", reached=False),
        observe(FactKind.TRACE_HOP, "10.0.1.1", ttl=2, target="10.20.0.5", reached=False),
        observe(FactKind.PROBE_ALIVE, "10.20.0.5", method="icmp", port=None),
    ]
    g = graph_from_observations(obs)
    assert g.entities["rtr:10.0.0.1"].type is EntityType.ROUTER
    assert g.entities["rtr:10.0.1.1"].type is EntityType.ROUTER
    assert any(g.evidence[e].rule == "R-RTR-TRACE" for e in g.entities["rtr:10.0.0.1"].evidence)
    # Consecutive hops are chained.
    assert "lnk:inferred-path:rtr:10.0.0.1|rtr:10.0.1.1" in g.links
    chain = g.links["lnk:inferred-path:rtr:10.0.0.1|rtr:10.0.1.1"]
    assert chain.attrs["basis"] == ["traceroute"]
    # The alive target is a host.
    assert g.entities["host:10.20.0.5"].type is EntityType.HOST


def test_probe_alive_upgrades_a_reference_to_a_host() -> None:
    from netgrapher.facts.model import FactKind, observe

    g = graph_from_observations(
        [observe(FactKind.PROBE_ALIVE, "192.168.5.20", method="tcp", port=443)]
    )
    host = g.entities["host:192.168.5.20"]
    assert host.type is EntityType.HOST
    assert any(g.evidence[e].rule == "R-HOST-PROBE" for e in host.evidence)
    assert host.confidence == 1.0
