import struct

from synthetic import (
    BROADCAST,
    dns_response,
    eth,
    icmp_time_exceeded,
    ip4,
    ospf_hello,
    tcp,
    udp,
)
from synthetic import (
    arp as arp_pkt,
)
from synthetic import (
    dhcp as dhcp_msg,
)
from synthetic import (
    ipv4 as ip_pkt,
)

from netgrapher.capture.source import RawPacket
from netgrapher.decode.decoder import decode
from netgrapher.extract import arp, dhcp, dns, icmp, ipv4, routing
from netgrapher.facts.model import FactKind, Observation, observe

A, B, GW = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:01"


def dec(frame: bytes):  # type: ignore[no-untyped-def]
    return decode(RawPacket(1, 0.0, 0, 1, frame, len(frame)))


def kinds(observations: list[Observation]) -> set[tuple[FactKind, str]]:
    return {(o.kind, o.subject) for o in observations}


def test_ipv4_unicast() -> None:
    obs = list(ipv4.extract(dec(eth(A, GW, tcp("10.0.0.10", "8.8.8.8", 1, 2, ttl=64)))))
    assert observe(FactKind.IP_SEEN, "10.0.0.10", dir="src") in obs
    assert observe(FactKind.IP_MAC, "8.8.8.8", mac=GW, vlan=None, dir="dst") in obs
    assert observe(FactKind.TTL_OBSERVED, "10.0.0.10", ttl=64) in obs


def test_ipv4_broadcast_destination_is_not_a_host() -> None:
    obs = list(ipv4.extract(dec(eth(A, BROADCAST, udp("10.0.0.10", "10.0.0.255", 1, 2, b"")))))
    assert kinds(obs) == {(FactKind.IP_SEEN, "10.0.0.10"), (FactKind.IP_MAC, "10.0.0.10")}


def test_arp_request_and_probe() -> None:
    obs = list(
        arp.extract(
            dec(
                eth(
                    A,
                    BROADCAST,
                    arp_pkt(1, A, "10.0.0.10", "00:00:00:00:00:00", "10.0.0.1"),
                    0x0806,
                )
            )
        )
    )
    assert observe(FactKind.ARP_BINDING, "10.0.0.10", mac=A, vlan=None) in obs
    assert observe(FactKind.ARP_QUERY, "10.0.0.1", vlan=None) in obs
    probe = list(
        arp.extract(
            dec(
                eth(
                    A, BROADCAST, arp_pkt(1, A, "0.0.0.0", "00:00:00:00:00:00", "10.0.0.10"), 0x0806
                )
            )
        )
    )
    assert kinds(probe) == {(FactKind.ARP_QUERY, "10.0.0.10")}


def test_dhcp_ack_and_hostname() -> None:
    ack = dhcp_msg(
        2,
        5,
        A,
        yiaddr="10.0.0.10",
        options=[(1, ip4("255.255.254.0")), (3, ip4("10.0.0.1")), (54, ip4("10.0.0.2"))],
    )
    obs = list(dhcp.extract(dec(eth(GW, A, udp("10.0.0.2", "10.0.0.10", 67, 68, ack)))))
    lease = next(o for o in obs if o.kind is FactKind.DHCP_LEASE)
    data = dict(lease.data)
    assert lease.subject == "10.0.0.10"
    assert (data["mask"], data["routers"], data["server"]) == (
        "255.255.254.0",
        ("10.0.0.1",),
        "10.0.0.2",
    )
    assert observe(FactKind.SERVICE, "10.0.0.2", service="dhcp") in obs

    req = dhcp_msg(1, 3, A, options=[(12, b"Bob-PC"), (50, ip4("10.0.0.10"))])
    obs = list(dhcp.extract(dec(eth(A, BROADCAST, udp("0.0.0.0", "255.255.255.255", 68, 67, req)))))
    assert observe(FactKind.NAME, "10.0.0.10", name="bob-pc", source="dhcp") in obs
    assert observe(FactKind.DHCP_HOSTNAME, A, name="bob-pc") in obs


def test_dns_answers_ptr_and_mdns() -> None:
    resp = dns_response([("www.Example.com", "93.184.215.14")], ptr=[("10.0.0.5", "nas.lan")])
    obs = list(dns.extract(dec(eth(GW, A, udp("10.0.0.1", "10.0.0.10", 53, 5000, resp)))))
    assert observe(FactKind.NAME, "93.184.215.14", name="www.example.com", source="dns") in obs
    assert observe(FactKind.NAME, "10.0.0.5", name="nas.lan", source="dns-ptr") in obs
    assert observe(FactKind.SERVICE, "10.0.0.1", service="dns") in obs
    mdns = dns_response([("printer.local", "10.0.0.20")])
    obs = list(
        dns.extract(
            dec(eth(B, "01:00:5e:00:00:fb", udp("10.0.0.20", "224.0.0.251", 5353, 5353, mdns)))
        )
    )
    assert obs == [observe(FactKind.NAME, "10.0.0.20", name="printer.local", source="mdns")]
    query = list(dns.extract(dec(eth(A, GW, udp("10.0.0.10", "10.0.0.1", 5000, 53, resp)))))
    assert query == []


def test_icmp_router_messages() -> None:
    inner = udp("10.0.0.10", "10.9.9.9", 1, 2, b"")
    te = list(icmp.extract(dec(eth(GW, A, icmp_time_exceeded("10.0.0.1", "10.0.0.10", inner, 64)))))
    assert te == [observe(FactKind.ICMP_TIME_EXCEEDED, "10.0.0.1")]


def test_ospf_hello() -> None:
    frame = eth(
        GW,
        "01:00:5e:00:00:05",
        ip_pkt("10.0.0.1", "224.0.0.5", ospf_hello("1.1.1.1", "255.255.255.0"), 89, 1),
    )
    obs = list(routing.extract_ospf(dec(frame)))
    assert observe(FactKind.ROUTING_SPEAKER, "10.0.0.1", proto="ospf", router_id="1.1.1.1") in obs
    assert observe(FactKind.SUBNET_HINT, "10.0.0.1", mask="255.255.255.0", source="ospf") in obs


def test_vrrp_and_hsrp_virtual_addresses() -> None:
    vrrp = struct.pack("!BBBBBBH", 0x21, 7, 100, 1, 0, 1, 0) + ip4("10.0.0.254") + b"\x00" * 8
    frame = eth(
        "00:00:5e:00:01:07", "01:00:5e:00:00:12", ip_pkt("10.0.0.2", "224.0.0.18", vrrp, 112, 255)
    )
    assert list(routing.extract_vrrp(dec(frame))) == [
        observe(
            FactKind.REDUNDANCY_SPEAKER, "10.0.0.2", proto="vrrp", group=7, vips=("10.0.0.254",)
        )
    ]
    hsrp = bytes([0, 0, 16, 3, 10, 100, 5, 0]) + b"cisco\x00\x00\x00" + ip4("10.0.0.253")
    frame = eth(GW, "01:00:5e:00:00:02", udp("10.0.0.3", "224.0.0.2", 1985, 1985, hsrp, ttl=1))
    assert list(routing.extract_hsrp(dec(frame))) == [
        observe(
            FactKind.REDUNDANCY_SPEAKER, "10.0.0.3", proto="hsrp", group=5, vips=("10.0.0.253",)
        )
    ]


def test_nbns_registration_and_group_names() -> None:
    import dpkt

    from netgrapher.extract import nbns

    def nb_rr(name: str, suffix: int, flags: int, ip: str) -> dpkt.netbios.NS.RR:
        encoded = dpkt.netbios.encode_name(name.ljust(15) + chr(suffix))
        return dpkt.netbios.NS.RR(
            name=encoded,
            type=dpkt.netbios.NS_NB,
            cls=1,
            ttl=300,
            rdata=struct.pack("!H", flags) + ip4(ip),
        )

    msg = dpkt.netbios.NS(
        id=1,
        op=0x2910,
        qd=[],
        an=[],
        ar=[
            nb_rr("DESKTOP-42", 0x00, 0, "10.0.0.42"),
            nb_rr("WORKGROUP", 0x00, 0x8000, "10.0.0.42"),
            nb_rr("DESKTOP-42", 0x03, 0, "10.0.0.42"),
        ],
    )
    frame = eth(A, BROADCAST, udp("10.0.0.42", "10.0.0.255", 137, 137, bytes(msg)))
    assert list(nbns.extract(dec(frame))) == [
        observe(FactKind.NAME, "10.0.0.42", name="desktop-42", source="nbns")
    ]
