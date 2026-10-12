"""Compose the rendered graph from the discovered graph plus the user overlay.

rendered = (discovered entities/links + user-created) minus deleted. This is the single
definition of "what the graph shows", used by the API payload, exports and the report.

Compose never mutates the discovered (engine) graph: a discovered entity that needs adjusting
(e.g. a host whose subnet was deleted) is returned as a shallow copy. The `origin` marker
("user" vs "discovered") is added by the payload layer, not stored on engine entities, so that
live inference diffs stay stable. See design §11.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from netgrapher.graph.model import Entity, EntityType, Link, LinkType
from netgrapher.project.format import Project


def _conf(d: dict[str, Any]) -> float:
    try:
        return float(d.get("confidence", 1.0))
    except (TypeError, ValueError):
        return 1.0


def _user_entity(eid: str, d: dict[str, Any]) -> Entity:
    attrs = {k: v for k, v in d.items() if k not in ("type", "confidence", "evidence", "origin")}
    attrs["origin"] = "user"
    return Entity(eid, EntityType(str(d["type"])), _conf(d), attrs, [])


def _user_link(lid: str, d: dict[str, Any]) -> Link:
    reserved = ("type", "a", "b", "confidence", "evidence", "origin")
    attrs = {k: v for k, v in d.items() if k not in reserved}
    attrs["origin"] = "user"
    return Link(lid, LinkType(str(d["type"])), str(d["a"]), str(d["b"]), _conf(d), attrs, [])


def rendered_entities(project: Project) -> dict[str, Entity]:
    deleted = set(project.deleted)
    out: dict[str, Entity] = {
        eid: entity for eid, entity in project.graph.entities.items() if eid not in deleted
    }
    for eid, d in project.user_entities.items():
        if eid not in deleted:
            out[eid] = _user_entity(eid, d)
    # A host whose subnet is gone must not keep a dangling parent (copy, don't mutate the engine).
    for eid, entity in list(out.items()):
        if entity.type is EntityType.HOST and entity.attrs.get("subnet_id") not in out:
            out[eid] = dataclasses.replace(entity, attrs={**entity.attrs, "subnet_id": None})
    return out


def rendered_links(project: Project, entities: dict[str, Entity] | None = None) -> dict[str, Link]:
    present = set(entities if entities is not None else rendered_entities(project))
    deleted = set(project.deleted)
    out: dict[str, Link] = {}
    for lid, link in project.graph.links.items():
        if lid not in deleted and link.a in present and link.b in present:
            out[lid] = link
    for lid, d in project.user_links.items():
        if lid in deleted:
            continue
        link = _user_link(lid, d)
        if link.a in present and link.b in present:
            out[lid] = link
    return out
