"""Summary and coverage report. See design §7.3."""

from __future__ import annotations

from collections import Counter

from netgrapher.graph.model import EntityType, LinkType
from netgrapher.project.format import Project

LOW_CONFIDENCE = 0.5


def build_report(project: Project) -> str:
    g = project.graph
    lines: list[str] = []

    for run in project.runs:
        stats = run.get("stats", {})
        where = run.get("input") or ", ".join(i["name"] or "?" for i in run.get("interfaces", []))
        lines.append(
            f"Run {run['id']}: {run['mode']} from {run['source']} ({where}), "
            f"stopped: {run.get('stop_reason')}"
        )
        hostcfg = (run.get("hostcfg") or {}).get("start")
        if hostcfg:
            addrs = [
                f"{a['ip']}/{a['prefixlen']}"
                for i in hostcfg["interfaces"]
                if not i["loopback"]
                for a in i["addresses"]
                if ":" not in a["ip"]
            ]
            lines.append(f"  capture host {hostcfg['hostname']}: {', '.join(addrs) or 'no IPv4'}")
            lines.extend(f"  warning: {w}" for w in hostcfg.get("warnings", []))
        lines.append(
            f"  packets {stats.get('packets', 0)}, IPv4 {stats.get('ipv4', 0)}, "
            f"malformed {stats.get('malformed', 0)}, "
            f"IPv6 skipped {stats.get('ipv6_skipped', 0)}, "
            f"unsupported link type {stats.get('unsupported_linktype', 0)}"
        )
        drops = sum(stats.get("if_dropped", {}).values()) + sum(
            stats.get("os_dropped", {}).values()
        )
        if drops:
            lines.append(f"  capture drops: {drops}")
        if stats.get("truncated_tail"):
            lines.append("  warning: the capture file ends with a truncated record")
        protocols = stats.get("protocols", {})
        if protocols:
            seen = ", ".join(f"{p} ({n})" for p, n in sorted(protocols.items()))
            lines.append(f"  protocols with useful data: {seen}")

    by_type = Counter(e.type for e in g.entities.values())
    lines.append("")
    lines.append(
        "Graph: "
        + ", ".join(
            f"{by_type.get(t, 0)} {label}"
            for t, label in (
                (EntityType.SUBNET, "subnets"),
                (EntityType.ROUTER, "routers"),
                (EntityType.UNKNOWN_ROUTER, "unknown routers"),
                (EntityType.HOST, "hosts"),
                (EntityType.EXTERNAL, "external networks"),
            )
        )
    )

    rules = Counter(ev.rule for ev in g.evidence.values())
    if rules:
        lines.append("Evidence by rule: " + ", ".join(f"{r} {n}" for r, n in sorted(rules.items())))

    gaps: list[str] = []
    path_targets = {lk.b for lk in g.links.values() if lk.type is LinkType.INFERRED_PATH}
    for e in g.entities.values():
        if e.type is EntityType.SUBNET:
            if e.attrs["prefix_confidence"] < LOW_CONFIDENCE:
                gaps.append(f"{e.id}: prefix length is a guess (confidence {e.confidence:.2f})")
            if e.attrs["kind"] == "remote" and e.id not in path_targets:
                gaps.append(f"{e.id}: remote subnet with no known path from here")
        elif e.type is EntityType.ROUTER and len(e.attrs["interfaces"]) == 1:
            gaps.append(f"{e.id}: only one interface known")
        elif e.type is EntityType.UNKNOWN_ROUTER:
            gaps.append(f"{e.id}: router seen only by its MAC; IP address unknown")
        elif e.confidence < LOW_CONFIDENCE:
            gaps.append(f"{e.id}: low confidence ({e.confidence:.2f})")
    if gaps:
        lines.append("")
        lines.append(f"Gaps ({len(gaps)}):")
        lines.extend(f"  - {gap}" for gap in sorted(gaps))

    suggestions: list[str] = []
    all_protocols: Counter[str] = Counter()
    for run in project.runs:
        all_protocols.update(run.get("stats", {}).get("protocols", {}))
    if not any(all_protocols.get(p) for p in ("ospf", "eigrp", "rip", "bgp", "vrrp", "hsrp")):
        suggestions.append(
            "No routing or redundancy protocols observed; reactive mode (milestone 0.5) can "
            "fill in router paths."
        )
    guessed = [
        e
        for e in g.entities.values()
        if e.type is EntityType.SUBNET and e.attrs["prefix_confidence"] < LOW_CONFIDENCE
    ]
    if guessed and not all_protocols.get("dhcp"):
        suggestions.append(
            f"No DHCP observed; {len(guessed)} subnet mask(s) are estimates. Capturing while "
            "a client joins the network gives exact masks."
        )
    if any(r.get("stats", {}).get("ipv6_skipped") for r in project.runs):
        suggestions.append("IPv6 traffic was present but IPv6 inference is not implemented yet.")
    if suggestions:
        lines.append("")
        lines.append("Suggestions:")
        lines.extend(f"  - {s}" for s in suggestions)
    return "\n".join(lines)
