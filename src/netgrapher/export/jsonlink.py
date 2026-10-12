"""JSON node-link format (compatible with networkx.node_link_graph)."""

from __future__ import annotations

import json
from dataclasses import asdict

from netgrapher.export.common import ExportGraph


def render(graph: ExportGraph) -> str:
    doc = {
        "directed": False,
        "multigraph": True,
        "graph": {},
        "nodes": [asdict(n) for n in graph.nodes],
        "links": [
            {"key": e.id, **{k: v for k, v in asdict(e).items() if k != "id"}} for e in graph.edges
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"
