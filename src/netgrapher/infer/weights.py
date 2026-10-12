"""Base weights of the inference rules (design §7.1), kept in one place for tuning."""

from __future__ import annotations

WEIGHTS: dict[str, float] = {
    # Subnets
    "R-SUB-HOSTCFG": 1.00,
    "R-SUB-DHCP": 0.95,
    "R-SUB-OSPF": 0.95,
    "R-SUB-ROUTE": 0.90,
    "R-SUB-WELLKNOWN": 1.00,
    "R-SUB-ONLINK": 0.40,
    "R-SUB-HEUR": 0.20,
    # Routers
    "R-RTR-HOSTCFG": 1.00,
    "R-RTR-DHCP": 0.90,
    "R-RTR-PROTO": 0.95,
    "R-RTR-ICMP": 0.90,
    "R-RTR-TRACE": 0.95,
    "R-RTR-MAC": 0.80,
    # Router aliases
    "R-ALIAS-ID": 0.95,
    "R-ALIAS-MAC": 0.70,
    "R-ALIAS-MERCATOR": 0.85,
    "R-ALIAS-PTR": 0.30,
    # Paths
    "R-HOP-TTL": 0.60,
    "R-PATH-GW": 0.80,
    "R-PATH-TRACE": 0.90,
    "R-PATH-ROUTE": 1.00,
    # Hosts and external
    "R-HOST-SELF": 1.00,
    "R-HOST-OBS": 1.00,
    "R-HOST-REF": 0.50,
    "R-EXT": 1.00,
}
