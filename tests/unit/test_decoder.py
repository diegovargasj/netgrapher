import struct

import pytest
from synthetic import eth, icmp_time_exceeded, ip4, mac, tcp, udp

from netgrapher.capture.source import RawPacket
from netgrapher.decode.decoder import DecodeError, UnsupportedLinktype, decode


def raw(data: bytes, linktype: int = 1) -> RawPacket:
    return RawPacket(1, 0.0, 0, linktype, data, len(data))


def test_ethernet_vlan_tcp() -> None:
    frame = eth(
        "02:00:00:00:00:01", "02:00:00:00:00:02", tcp("10.0.0.1", "10.0.0.2", 1, 2, ttl=63), vlan=42
    )
    p = decode(raw(frame))
    assert (p.src_mac, p.dst_mac, p.vlan) == ("02:00:00:00:00:01", "02:00:00:00:00:02", 42)
    assert (p.ip_src, p.ip_dst, p.ttl, p.proto, p.sport, p.dport) == (
        "10.0.0.1",
        "10.0.0.2",
        63,
        6,
        1,
        2,
    )


def test_linux_sll_and_sll2() -> None:
    ip = bytes(udp("10.0.0.1", "10.0.0.2", 1, 2, b"x"))
    sll = struct.pack("!HHH", 0, 1, 6) + mac("02:00:00:00:00:09") + b"\x00\x00" + b"\x08\x00"
    p = decode(raw(sll + ip, 113))
    assert (p.src_mac, p.ip_src) == ("02:00:00:00:00:09", "10.0.0.1")
    sll2 = struct.pack("!HHIHBB", 0x0800, 0, 1, 1, 0, 6) + mac("02:00:00:00:00:09") + b"\x00\x00"
    p = decode(raw(sll2 + ip, 276))
    assert (p.src_mac, p.ip_dst, p.payload) == ("02:00:00:00:00:09", "10.0.0.2", b"x")


def test_raw_and_loopback() -> None:
    ip = bytes(udp("10.0.0.1", "10.0.0.2", 1, 2, b""))
    assert decode(raw(ip, 101)).ip_src == "10.0.0.1"
    assert decode(raw(b"\x02\x00\x00\x00" + ip, 0)).ip_dst == "10.0.0.2"


def test_icmp_error_quotes_inner_header() -> None:
    inner = udp("192.168.1.10", "10.30.0.9", 1, 2, b"", ttl=1)
    p = decode(raw(bytes(icmp_time_exceeded("10.0.0.2", "192.168.1.10", inner, 254)), 101))
    assert p.icmp is not None
    assert (p.icmp.type, p.icmp.inner_src, p.icmp.inner_dst) == (11, "192.168.1.10", "10.30.0.9")


def test_ipv6_is_flagged() -> None:
    assert decode(raw(b"\x60" + b"\x00" * 39, 101)).is_ipv6


@pytest.mark.parametrize(
    "data",
    [b"\x45\x00", b"\x46" + b"\x00" * 19, b"\x45\x00\x00\x05" + b"\x00" * 16, b"\x70" * 20],
)
def test_malformed_ip(data: bytes) -> None:
    with pytest.raises(DecodeError):
        decode(raw(data, 101))


def test_unsupported_linktype() -> None:
    with pytest.raises(UnsupportedLinktype):
        decode(raw(b"\x00" * 30, 127))


def test_non_first_fragment_has_no_ports() -> None:
    header = struct.pack("!BBHHHBBH", 0x45, 0, 28, 1, 0x0010, 64, 17, 0)
    data = header + ip4("10.0.0.1") + ip4("10.0.0.2") + b"\x00" * 8
    p = decode(raw(data, 101))
    assert p.sport is None
