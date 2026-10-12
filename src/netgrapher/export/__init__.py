"""Exporters: GraphML, GEXF, JSON node-link, DOT. Annotations (labels, hiding) are applied;
layout and evidence are not exported."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from netgrapher.export import dot, gexf, graphml, jsonlink
from netgrapher.export.common import ExportGraph, build_export_graph
from netgrapher.project.format import Project


class ExportFormat(StrEnum):
    GRAPHML = "graphml"
    GEXF = "gexf"
    JSON = "json"
    DOT = "dot"


_WRITERS: dict[ExportFormat, Callable[[ExportGraph], str]] = {
    ExportFormat.GRAPHML: graphml.render,
    ExportFormat.GEXF: gexf.render,
    ExportFormat.JSON: jsonlink.render,
    ExportFormat.DOT: dot.render,
}


def export_project(project: Project, fmt: ExportFormat, *, include_hidden: bool = False) -> str:
    return _WRITERS[fmt](build_export_graph(project, include_hidden=include_hidden))
