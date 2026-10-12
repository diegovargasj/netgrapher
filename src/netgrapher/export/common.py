"""Format-independent view of a project for exporters."""

from __future__ import annotations

from dataclasses import dataclass

from netgrapher.graph.model import EntityType
from netgrapher.project.annotations import (
    default_label,
    label_of,
    link_default_label,
    visible_entities,
    visible_links,
)
from netgrapher.project.compose import rendered_entities, rendered_links
from netgrapher.project.format import Project


@dataclass(frozen=True)
class ExportNode:
    id: str
    label: str
    type: str
    confidence: float
    parent: str | None  # subnet of a host


@dataclass(frozen=True)
class ExportEdge:
    id: str
    source: str
    target: str
    type: str
    label: str
    confidence: float


@dataclass(frozen=True)
class ExportGraph:
    nodes: list[ExportNode]
    edges: list[ExportEdge]


def build_export_graph(project: Project, *, include_hidden: bool = False) -> ExportGraph:
    entities = rendered_entities(project)
    all_links = rendered_links(project, entities)
    keep = set(entities) if include_hidden else visible_entities(project, entities)
    nodes = [
        ExportNode(
            eid,
            label_of(project, eid, default_label(e)),
            str(e.type),
            round(e.confidence, 4),
            e.attrs.get("subnet_id") if e.type is EntityType.HOST else None,
        )
        for eid, e in sorted(entities.items())
        if eid in keep
    ]
    links = list(all_links.values()) if include_hidden else visible_links(project, keep, all_links)
    edges = [
        ExportEdge(
            lk.id,
            lk.a,
            lk.b,
            str(lk.type),
            label_of(project, lk.id, link_default_label(lk)),
            round(lk.confidence, 4),
        )
        for lk in sorted(links, key=lambda lk: lk.id)
    ]
    return ExportGraph(nodes, edges)
