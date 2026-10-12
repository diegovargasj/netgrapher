"""GraphML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from netgrapher.export.common import ExportGraph

_NS = "http://graphml.graphdrawing.org/xmlns"
_NODE_KEYS = (
    ("label", "string"),
    ("type", "string"),
    ("confidence", "double"),
    ("parent", "string"),
)
_EDGE_KEYS = (("label", "string"), ("type", "string"), ("confidence", "double"))


def render(graph: ExportGraph) -> str:
    root = ET.Element("graphml", xmlns=_NS)
    for name, kind in _NODE_KEYS:
        ET.SubElement(
            root,
            "key",
            id=f"n_{name}",
            attrib={"for": "node", "attr.name": name, "attr.type": kind},
        )
    for name, kind in _EDGE_KEYS:
        ET.SubElement(
            root,
            "key",
            id=f"e_{name}",
            attrib={"for": "edge", "attr.name": name, "attr.type": kind},
        )
    g = ET.SubElement(root, "graph", id="netgrapher", edgedefault="undirected")
    for n in graph.nodes:
        node = ET.SubElement(g, "node", id=n.id)
        for key, value in (
            ("label", n.label),
            ("type", n.type),
            ("confidence", n.confidence),
            ("parent", n.parent),
        ):
            if value is not None:
                ET.SubElement(node, "data", key=f"n_{key}").text = str(value)
    for e in graph.edges:
        edge = ET.SubElement(g, "edge", id=e.id, source=e.source, target=e.target)
        for key, value in (("label", e.label), ("type", e.type), ("confidence", e.confidence)):
            ET.SubElement(edge, "data", key=f"e_{key}").text = str(value)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, "unicode") + "\n"
