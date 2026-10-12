"""Probe scope: which addresses a run is allowed to probe. See design §8.3, FR-DM-7/8/13.

Scope is the single gate every probe target passes through. Passive observation is never gated;
only outgoing probes are.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from netgrapher.config import (
    DEFAULT_REACTIVE_SCOPE,
    MAX_ACTIVE_PREFIXLEN_V4,
    ScopeConfig,
)
from netgrapher.net import is_external

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _networks(cidrs: tuple[str, ...]) -> list[Network]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


@dataclass
class Scope:
    allow: list[Network]
    deny: list[Network]
    allow_public: bool

    @classmethod
    def from_config(cls, config: ScopeConfig, local_subnets: tuple[str, ...] = ()) -> Scope:
        allow = _networks(config.allow or DEFAULT_REACTIVE_SCOPE) + _networks(local_subnets)
        return cls(allow=allow, deny=_networks(config.deny), allow_public=config.allow_public)

    @classmethod
    def for_active(cls, cidrs: tuple[str, ...], deny: tuple[str, ...]) -> Scope:
        # Active probes only the user's CIDRs. Public CIDRs are allowed because they are in the
        # allow list (the user asked for them), not via allow_public.
        return cls(allow=_networks(cidrs), deny=_networks(deny), allow_public=False)

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in self.deny):
            return False
        if any(addr in net for net in self.allow):
            return True
        # allow_public (reactive opt-in) additionally permits any public address.
        return self.allow_public and is_external(ip)

    def clip(self, cidr: str) -> list[Network]:
        """The parts of a CIDR that are in allow and not in deny (deny splits it)."""
        net = ipaddress.ip_network(cidr, strict=False)
        inside = [net] if any(net.subnet_of(a) or a.subnet_of(net) for a in self.allow) else []  # type: ignore[arg-type]
        result: list[Network] = []
        for candidate in inside:
            result.extend(_subtract(candidate, self.deny))
        return result


def _subtract(net: Network, holes: list[Network]) -> list[Network]:
    remaining = [net]
    for hole in holes:
        nxt: list[Network] = []
        for piece in remaining:
            if piece.overlaps(hole):
                if piece.subnet_of(hole):  # type: ignore[arg-type]
                    continue
                nxt.extend(piece.address_exclude(hole))  # type: ignore[arg-type]
            else:
                nxt.append(piece)
        remaining = nxt
    return remaining


def active_cidr_too_large(cidr: str) -> bool:
    net = ipaddress.ip_network(cidr, strict=False)
    return net.version == 4 and net.prefixlen < MAX_ACTIVE_PREFIXLEN_V4
