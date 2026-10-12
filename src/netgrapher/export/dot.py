"""Graphviz DOT. Hosts are drawn inside a cluster per subnet."""

from __future__ import annotations

from collections import defaultdict

from netgrapher.export.common import ExportGraph, ExportNode

_SHAPES = {
    "subnet": "box",
    "router": "doubleoctagon",
    "host": "ellipse",
    "external": "egg",
    "unknown_router": "octagon",
}


def _q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _node(n: ExportNode, indent: str) -> str:
    style = ', style="dashed"' if n.type == "unknown_router" or n.confidence < 0.5 else ""
    return (
        f"{indent}{_q(n.id)} [label={_q(n.label)}, shape={_SHAPES.get(n.type, 'ellipse')}{style}];"
    )


def render(graph: ExportGraph) -> str:
    lines = ["graph netgrapher {", "  compound=true;", '  node [fontname="Helvetica"];']
    hosts_by_subnet: defaultdict[str, list[ExportNode]] = defaultdict(list)
    for n in graph.nodes:
        if n.type == "host" and n.parent:
            hosts_by_subnet[n.parent].append(n)
        else:
            lines.append(_node(n, "  "))
    for i, (subnet, hosts) in enumerate(sorted(hosts_by_subnet.items())):
        lines.append(f"  subgraph cluster_{i} {{")
        lines.append(f'    label={_q(subnet.removeprefix("net:"))}; style="rounded,dotted";')
        lines.extend(_node(h, "    ") for h in hosts)
        lines.append("  }")
    for e in graph.edges:
        if e.type == "member":
            continue  # drawn as cluster membership
        style = ', style="dashed"' if e.type == "inferred-path" else ""
        label = f", label={_q(e.label)}" if e.label else ""
        lines.append(f"  {_q(e.source)} -- {_q(e.target)} [id={_q(e.id)}{label}{style}];")
    lines.append("}")
    return "\n".join(lines) + "\n"
