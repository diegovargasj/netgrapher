"""Builders for synthetic packets and capture files used by the tests."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import dpkt

BROADCAST = "ff:ff:ff:ff:ff:ff"


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def ip4(text: str) -> bytes:
    return socket.inet_aton(text)


def ip_int(text: str) -> int:
    return int.from_bytes(ip4(text), "big")


def eth(
    src: str,
    dst: str,
    payload: bytes | dpkt.Packet,
    ethertype: int = 0x0800,
    vlan: int | None = None,
) -> bytes:
    body = bytes(payload)
    if vlan is not None:
        header = mac(dst) + mac(src) + struct.pack("!HHH", 0x8100, vlan, ethertype)
        return header + body
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + body


def ipv4(src: str, dst: str, payload: dpkt.Packet | bytes, proto: int, ttl: int = 64) -> dpkt.ip.IP:
    return dpkt.ip.IP(src=ip4(src), dst=ip4(dst), p=proto, ttl=ttl, data=payload)


def udp(src: str, dst: str, sport: int, dport: int, data: bytes, ttl: int = 64) -> dpkt.ip.IP:
    return ipv4(src, dst, dpkt.udp.UDP(sport=sport, dport=dport, data=data), 17, ttl)


def tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    ttl: int = 64,
    flags: int = dpkt.tcp.TH_ACK,
    data: bytes = b"",
) -> dpkt.ip.IP:
    return ipv4(src, dst, dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=data), 6, ttl)


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> dpkt.arp.ARP:
    return dpkt.arp.ARP(op=op, sha=mac(sha), spa=ip4(spa), tha=mac(tha), tpa=ip4(tpa))


def icmp_time_exceeded(router: str, dst: str, quoted: dpkt.ip.IP, ttl: int) -> dpkt.ip.IP:
    msg = dpkt.icmp.ICMP(type=11, code=0, data=dpkt.icmp.ICMP.TimeExceed(data=bytes(quoted)[:28]))
    return ipv4(router, dst, msg, 1, ttl)


def dhcp(
    op: int,
    msg_type: int,
    client_mac: str,
    *,
    yiaddr: str = "0.0.0.0",
    options: list[tuple[int, bytes]] | None = None,
) -> bytes:
    msg = dpkt.dhcp.DHCP(
        op=op,
        chaddr=mac(client_mac) + b"\x00" * 10,
        yiaddr=ip_int(yiaddr),
        opts=[(53, bytes([msg_type])), *(options or [])],
    )
    return bytes(msg)


def dns_response(answers: list[tuple[str, str]], ptr: list[tuple[str, str]] | None = None) -> bytes:
    rrs = [dpkt.dns.DNS.RR(name=name, type=1, cls=1, ttl=60, ip=ip4(ip)) for name, ip in answers]
    for ip, name in ptr or []:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        rrs.append(dpkt.dns.DNS.RR(name=rev, type=12, cls=1, ttl=60, ptrname=name))
    msg = dpkt.dns.DNS(id=1, op=0x8180, an=rrs, qd=[])  # dpkt names the flags word "op"
    return bytes(msg)


def ospf_hello(router_id: str, mask: str) -> bytes:
    body = ip4(mask) + struct.pack("!HBBI", 10, 2, 1, 40) + ip4("0.0.0.0") + ip4("0.0.0.0")
    header = struct.pack("!BBH", 2, 1, 24 + len(body)) + ip4(router_id) + ip4("0.0.0.0")
    header += struct.pack("!HH", 0, 0) + b"\x00" * 8
    return header + body


def write_pcap(path: Path, frames: list[tuple[float, bytes]], linktype: int = 1) -> None:
    with path.open("wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=linktype, snaplen=65535)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)


def pcapng_bytes(
    interfaces: list[int],
    packets: list[tuple[int, float, bytes]],
    drops: dict[int, int] | None = None,
) -> bytes:
    """Minimal little-endian pcapng: one SHB, IDBs, EPBs and optional ISBs."""

    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", btype, length) + body + struct.pack("<I", length)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for linktype in interfaces:
        out += block(1, struct.pack("<HHI", linktype, 0, 65535))
    for iface, ts, data in packets:
        units = int(ts * 1_000_000)
        epb = struct.pack("<IIIII", iface, units >> 32, units & 0xFFFFFFFF, len(data), len(data))
        out += block(6, epb + data + b"\x00" * (-len(data) % 4))
    for iface, count in (drops or {}).items():
        opt = struct.pack("<HHQ", 5, 8, count) + struct.pack("<HH", 0, 0)
        out += block(5, struct.pack("<III", iface, 0, 0) + opt)
    return out


# --- Scenario: a small office LAN -------------------------------------------------------------
#
#   192.168.1.0/24 (DHCP, OSPF): gateway .1, laptop .10 (DHCP client "alice-laptop"),
#   printer .20 (mDNS "printer.local").
#   Behind the gateway: 10.20.0.0/24 (3 hops), router 10.0.0.2 (sent ICMP time exceeded),
#   and the Internet.

GW_MAC = "02:00:00:00:00:01"
LAPTOP_MAC = "02:00:00:00:00:0a"
PRINTER_MAC = "02:00:00:00:00:14"
GW, LAPTOP, PRINTER = "192.168.1.1", "192.168.1.10", "192.168.1.20"


def office_frames() -> list[tuple[float, bytes]]:
    frames: list[bytes] = []
    add = frames.append
    # DHCP: request with hostname, then ACK from the gateway.
    add(
        eth(
            LAPTOP_MAC,
            BROADCAST,
            udp(
                "0.0.0.0",
                "255.255.255.255",
                68,
                67,
                dhcp(1, 3, LAPTOP_MAC, options=[(12, b"alice-laptop"), (50, ip4(LAPTOP))]),
            ),
        )
    )
    add(
        eth(
            GW_MAC,
            LAPTOP_MAC,
            udp(
                GW,
                LAPTOP,
                67,
                68,
                dhcp(
                    2,
                    5,
                    LAPTOP_MAC,
                    yiaddr=LAPTOP,
                    options=[(1, ip4("255.255.255.0")), (3, ip4(GW)), (6, ip4(GW)), (54, ip4(GW))],
                ),
            ),
        )
    )
    # ARP for the gateway.
    add(eth(LAPTOP_MAC, BROADCAST, arp(1, LAPTOP_MAC, LAPTOP, "00:00:00:00:00:00", GW), 0x0806))
    add(eth(GW_MAC, LAPTOP_MAC, arp(2, GW_MAC, GW, LAPTOP_MAC, LAPTOP), 0x0806))
    # DNS through the gateway, then HTTPS to the Internet.
    add(eth(LAPTOP_MAC, GW_MAC, udp(LAPTOP, "8.8.8.8", 5000, 53, b"\x00" * 12)))
    add(
        eth(
            GW_MAC,
            LAPTOP_MAC,
            udp(
                "8.8.8.8",
                LAPTOP,
                53,
                5000,
                dns_response([("example.com", "93.184.215.14")]),
                ttl=117,
            ),
        )
    )
    for _ in range(3):
        add(eth(LAPTOP_MAC, GW_MAC, tcp(LAPTOP, "93.184.215.14", 40000, 443)))
        add(eth(GW_MAC, LAPTOP_MAC, tcp("93.184.215.14", LAPTOP, 443, 40000, ttl=52)))
    # Remote private subnet, 3 hops away (Windows TTL 128 -> 125; Linux 64 -> 61).
    add(eth(LAPTOP_MAC, GW_MAC, tcp(LAPTOP, "10.20.0.5", 40001, 445)))
    add(eth(GW_MAC, LAPTOP_MAC, tcp("10.20.0.5", LAPTOP, 445, 40001, ttl=125)))
    add(eth(LAPTOP_MAC, GW_MAC, tcp(LAPTOP, "10.20.0.6", 40002, 22)))
    add(eth(GW_MAC, LAPTOP_MAC, tcp("10.20.0.6", LAPTOP, 22, 40002, ttl=61)))
    # A traceroute-like packet expires at 10.0.0.2, one hop past the gateway.
    probe = udp(LAPTOP, "10.30.0.9", 33434, 33434, b"", ttl=2)
    add(eth(GW_MAC, LAPTOP_MAC, icmp_time_exceeded("10.0.0.2", LAPTOP, probe, ttl=254)))
    # Local traffic and mDNS from the printer.
    add(eth(LAPTOP_MAC, PRINTER_MAC, tcp(LAPTOP, PRINTER, 40003, 631)))
    add(eth(PRINTER_MAC, LAPTOP_MAC, tcp(PRINTER, LAPTOP, 631, 40003)))
    add(
        eth(
            PRINTER_MAC,
            "01:00:5e:00:00:fb",
            udp(
                PRINTER,
                "224.0.0.251",
                5353,
                5353,
                dns_response([("printer.local", PRINTER)]),
                ttl=255,
            ),
        )
    )
    # OSPF Hello from the gateway.
    add(
        eth(
            GW_MAC,
            "01:00:5e:00:00:05",
            ipv4(GW, "224.0.0.5", ospf_hello("10.255.0.1", "255.255.255.0"), 89, ttl=1),
        )
    )
    # Noise: an IPv6 frame and a malformed IPv4 frame.
    add(eth(LAPTOP_MAC, "33:33:00:00:00:01", b"\x60" + b"\x00" * 39, 0x86DD))
    add(eth(LAPTOP_MAC, GW_MAC, b"\x45\x00\x00"))
    return [(1_760_000_000.0 + i, frame) for i, frame in enumerate(frames)]


def graph_from_frames(frames: list[bytes], linktype: int = 1):  # type: ignore[no-untyped-def]
    """Run ingestion and inference over in-memory frames."""
    from netgrapher.capture.source import RawPacket
    from netgrapher.facts.store import FactStore
    from netgrapher.infer.engine import infer
    from netgrapher.pipeline import ingest

    store = FactStore()
    raws = [
        RawPacket(i + 1, 1_760_000_000.0 + i, 0, linktype, f, len(f)) for i, f in enumerate(frames)
    ]
    ingest(raws, store, "r1")
    return infer(store)
