"""Stable entity/link IDs and the alias table. See design §6.3."""

from __future__ import annotations

import ipaddress


def subnet_id(prefix: str) -> str:
    return f"net:{ipaddress.ip_network(prefix, strict=False)}"


def host_id(ip: str) -> str:
    return f"host:{ipaddress.ip_address(ip)}"


def router_id(canonical_ip: str) -> str:
    return f"rtr:{ipaddress.ip_address(canonical_ip)}"


def link_id(link_type: str, a: str, b: str) -> str:
    return f"lnk:{link_type}:{a}|{b}"


class AliasTable:
    """Maps retired IDs to their replacements. Lookups resolve chains transitively."""

    def __init__(self, aliases: dict[str, str] | None = None) -> None:
        self._aliases: dict[str, str] = dict(aliases or {})

    def add(self, old: str, new: str) -> None:
        if self.resolve(new) == old:
            raise ValueError(f"alias {old} -> {new} would create a cycle")
        self._aliases[old] = new

    def resolve(self, entity_id: str) -> str:
        seen: set[str] = set()
        while entity_id in self._aliases:
            if entity_id in seen:
                raise ValueError(f"alias cycle at {entity_id}")
            seen.add(entity_id)
            entity_id = self._aliases[entity_id]
        return entity_id

    def to_dict(self) -> dict[str, str]:
        return dict(self._aliases)
