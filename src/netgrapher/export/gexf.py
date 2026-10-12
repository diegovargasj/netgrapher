"""GEXF 1.3 (Gephi)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from netgrapher.export.common import ExportGraph

_NS = "http://gexf.net/1.3"


def render(graph: ExportGraph) -> str:
    root = ET.Element("gexf", xmlns=_NS, version="1.3")
    g = ET.SubElement(root, "graph", defaultedgetype="undirected", mode="static")
    node_attrs = ET.SubElement(g, "attributes", attrib={"class": "node"})
    for i, (name, kind) in enumerate(
        (("type", "string"), ("confidence", "double"), ("parent", "string"))
    ):
        ET.SubElement(node_attrs, "attribute", id=str(i), title=name, type=kind)
    edge_attrs = ET.SubElement(g, "attributes", attrib={"class": "edge"})
    for i, (name, kind) in enumerate((("type", "string"), ("confidence", "double"))):
        ET.SubElement(edge_attrs, "attribute", id=str(i), title=name, type=kind)

    nodes = ET.SubElement(g, "nodes")
    for n in graph.nodes:
        node = ET.SubElement(nodes, "node", id=n.id, label=n.label)
        values = ET.SubElement(node, "attvalues")
        for i, value in enumerate((n.type, n.confidence, n.parent)):
            if value is not None:
                ET.SubElement(values, "attvalue", attrib={"for": str(i), "value": str(value)})
    edges = ET.SubElement(g, "edges")
    for e in graph.edges:
        edge = ET.SubElement(
            edges, "edge", id=e.id, source=e.source, target=e.target, label=e.label
        )
        values = ET.SubElement(edge, "attvalues")
        for i, edge_value in enumerate((e.type, e.confidence)):
            ET.SubElement(values, "attvalue", attrib={"for": str(i), "value": str(edge_value)})
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, "unicode") + "\n"
