"""Diffs between inference passes, streamed to the UI in live mode. See design §5.2, §6.3.

Besides plain added/updated/removed changes, a diff detects *aliases*: an entity that vanished
because it became, or merged into, another one. Annotations follow aliases, so a label put on a
host survives that host turning out to be a router interface.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from netgrapher.graph.model import Entity, EntityType, Graph


@dataclass
class GraphDiff:
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    links_added: list[str] = field(default_factory=list)
    links_updated: list[str] = field(default_factory=list)
    links_removed: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)  # removed id -> surviving id

    def __bool__(self) -> bool:
        return any(
            (
                self.added,
                self.updated,
                self.removed,
                self.links_added,
                self.links_updated,
                self.links_removed,
            )
        )


def _addresses(entity: Entity) -> set[str]:
    if entity.type is EntityType.HOST:
        return {entity.attrs["ip"]}
    if entity.type is EntityType.ROUTER:
        return {i["ip"] for i in entity.attrs.get("interfaces", []) if not i.get("virtual")}
    return set()


def _alias_target(old: Entity, new: Graph, candidates: list[str]) -> str | None:
    if old.type is EntityType.SUBNET:
        net = ipaddress.ip_network(old.attrs["prefix"])
        containing = [
            c
            for c in candidates
            if new.entities[c].type is EntityType.SUBNET
            and net.subnet_of(ipaddress.ip_network(new.entities[c].attrs["prefix"]))  # type: ignore[arg-type]
        ]
        return min(containing, default=None)
    addresses = _addresses(old)
    if not addresses:
        return None
    routers = [
        c
        for c in candidates
        if new.entities[c].type is EntityType.ROUTER and addresses & _addresses(new.entities[c])
    ]
    return min(routers, default=None)


# Attributes that change constantly without being new information. Excluding them from the
# "updated" test means an active host is not re-sent every tick just because it kept sending
# traffic — only genuine enrichment (a new name, role, interface, confidence change, …) counts.
_VOLATILE_ATTRS = ("last_seen",)


def _significant(entity: Entity) -> dict[str, Any]:
    d = entity.to_dict()
    for key in _VOLATILE_ATTRS:
        d.pop(key, None)
    return d


def diff_graphs(old: Graph, new: Graph) -> GraphDiff:
    d = GraphDiff()
    for eid, entity in new.entities.items():
        previous = old.entities.get(eid)
        if previous is None:
            d.added.append(eid)
        elif _significant(previous) != _significant(entity):
            d.updated.append(eid)
    d.removed = [eid for eid in old.entities if eid not in new.entities]
    for lid, link in new.links.items():
        previous_link = old.links.get(lid)
        if previous_link is None:
            d.links_added.append(lid)
        elif previous_link.to_dict() != link.to_dict():
            d.links_updated.append(lid)
    d.links_removed = [lid for lid in old.links if lid not in new.links]

    candidates = sorted(set(d.added) | set(d.updated) | set(new.entities))
    for eid in d.removed:
        target = _alias_target(old.entities[eid], new, candidates)
        if target is not None:
            d.aliases[eid] = target
    return d


def migrate_annotations(
    annotations: dict[str, dict[str, Any]], aliases: dict[str, str]
) -> list[str]:
    """Move annotations from aliased IDs to their targets. Returns conflict messages.

    When both carry a label, the surviving entity keeps its own and the other one is appended
    to its note (design §6.3).
    """
    conflicts = []
    for old, new in sorted(aliases.items()):
        moved = annotations.pop(old, None)
        if not moved:
            continue
        target = annotations.setdefault(new, {})
        for key, value in moved.items():
            if key == "label" and target.get("label") and target["label"] != value:
                note = target.get("note", "")
                target["note"] = (note + "\n" if note else "") + f"Also labelled: {value}"
                conflicts.append(f"{old} merged into {new}: kept label {target['label']!r}")
            elif key == "note" and target.get("note"):
                target["note"] = f"{target['note']}\n{value}"
            elif key not in target:
                target[key] = value
    return conflicts
