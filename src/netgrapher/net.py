"""Address classification helpers shared by extractors and inference."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Virtual router MACs (VRRP IPv4, VRRP IPv6, HSRPv1, HSRPv2). Shared by several routers,
# so they must not be used to merge router aliases.
_VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01:", "00:00:5e:00:02:", "00:00:0c:07:ac:", "00:00:0c:9f:f")


def is_group_mac(mac: str) -> bool:
    """Broadcast or multicast MAC (I/G bit set)."""
    return int(mac[:2], 16) & 1 == 1


def is_virtual_mac(mac: str) -> bool:
    return mac.startswith(_VIRTUAL_MAC_PREFIXES)


@lru_cache(maxsize=65536)
def is_usable_unicast(ip: str) -> bool:
    """True for addresses that can identify a host or interface."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or addr.is_reserved
        or (addr.version == 4 and ip == "255.255.255.255")
    )


@lru_cache(maxsize=65536)
def is_external(ip: str) -> bool:
    """Globally routable address (not RFC1918, CGNAT, link-local, ...)."""
    return ipaddress.ip_address(ip).is_global


@lru_cache(maxsize=65536)
def is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def ip_sort_key(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))
