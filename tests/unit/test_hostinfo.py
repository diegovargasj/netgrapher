from netgrapher.capture.hostinfo import HostConfig, HostRoute
from netgrapher.capture.hostinfo.linux import (
    parse_addresses,
    parse_neighbors,
    parse_resolv_conf,
    parse_routes,
)

ADDR = [
    {
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP"],
        "link_type": "loopback",
        "address": "00:00:00:00:00:00",
        "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}],
    },
    {
        "ifname": "eth0",
        "flags": ["BROADCAST", "UP", "LOWER_UP"],
        "link_type": "ether",
        "address": "02:00:00:00:00:0a",
        "addr_info": [
            {"family": "inet", "local": "192.168.1.10", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
        ],
    },
    {
        "ifname": "wlan0",
        "flags": ["BROADCAST"],
        "link_type": "ether",
        "address": "02:00:00:00:00:0b",
        "addr_info": [],
    },
]
ROUTES = [
    {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0", "protocol": "dhcp", "metric": 100},
    {"dst": "default", "gateway": "10.9.0.1", "dev": "wlan0", "metric": 600},
    {"dst": "192.168.1.0/24", "dev": "eth0", "scope": "link"},
    {"type": "local", "dst": "192.168.1.10", "dev": "eth0", "table": "local"},
    {"type": "broadcast", "dst": "192.168.1.255", "dev": "eth0", "table": "local"},
    {"dst": "10.8.0.5", "gateway": "192.168.1.1", "dev": "eth0"},
]
NEIGH = [
    {"dst": "192.168.1.1", "dev": "eth0", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]},
    {"dst": "192.168.1.77", "dev": "eth0", "state": ["FAILED"]},
]


def test_parse_addresses() -> None:
    ifaces = parse_addresses(ADDR)
    eth0 = ifaces[1]
    assert (eth0.name, eth0.mac, eth0.up, eth0.loopback) == (
        "eth0",
        "02:00:00:00:00:0a",
        True,
        False,
    )
    assert [(a.ip, a.prefixlen) for a in eth0.addresses] == [("192.168.1.10", 24), ("fe80::1", 64)]
    assert ifaces[0].loopback and ifaces[0].mac is None
    assert not ifaces[2].up


def test_parse_routes_and_default_interface() -> None:
    routes = parse_routes(ROUTES)
    assert [r.dst for r in routes] == ["default", "default", "192.168.1.0/24", "10.8.0.5/32"]
    assert HostConfig(routes=routes).default_interface() == "eth0"
    assert HostConfig(routes=[HostRoute("10.0.0.0/8", None, "eth0")]).default_interface() is None


def test_parse_neighbors_skips_failed_entries() -> None:
    assert [(n.ip, n.mac) for n in parse_neighbors(NEIGH)] == [("192.168.1.1", "02:00:00:00:00:01")]


def test_parse_resolv_conf() -> None:
    text = "# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver 192.168.1.1\n"
    assert parse_resolv_conf(text) == ["127.0.0.53", "192.168.1.1"]
