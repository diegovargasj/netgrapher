"""User annotations applied on top of discovered data: labels and hiding. See design §6.3, §11.4."""

from __future__ import annotations

from netgrapher.graph.model import Entity, EntityType, Link, LinkType
from netgrapher.project.format import Project


def default_label(entity: Entity) -> str:
    if entity.type is EntityType.SUBNET:
        return str(entity.attrs["prefix"])
    if entity.type is EntityType.HOST:
        return str(entity.attrs["ip"])
    if entity.type is EntityType.ROUTER:
        return entity.id.removeprefix("rtr:")
    if entity.type is EntityType.EXTERNAL:
        return "Internet"
    return "?"


def label_of(project: Project, entity_or_link_id: str, default: str) -> str:
    label = project.annotations.get(entity_or_link_id, {}).get("label")
    return label if label else default


def is_hidden(project: Project, item_id: str) -> bool:
    return bool(project.annotations.get(item_id, {}).get("hidden"))


def visible_entities(project: Project) -> set[str]:
    """Entities left after manual hiding, with cascade: a hidden subnet hides its hosts."""
    entities = project.graph.entities
    visible = {eid for eid in entities if not is_hidden(project, eid)}
    for eid, entity in entities.items():
        if entity.type is EntityType.HOST and entity.attrs.get("subnet_id") not in visible:
            visible.discard(eid)
    return visible


def visible_links(project: Project, entities: set[str]) -> list[Link]:
    return [
        link
        for link in project.graph.links.values()
        if link.a in entities and link.b in entities and not is_hidden(project, link.id)
    ]


def link_default_label(link: Link) -> str:
    if link.type is LinkType.INTERFACE:
        return str(link.attrs.get("ip") or "")
    if link.type is LinkType.INFERRED_PATH:
        hops = link.attrs.get("hops")
        if hops is None:
            return "path"
        return f"~{hops} hop" if hops == 1 else f"~{hops} hops"
    return ""
