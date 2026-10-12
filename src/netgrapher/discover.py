"""Discovery runs: source -> facts -> graph -> project."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netgrapher.capture.source import FileSource
from netgrapher.config import Mode
from netgrapher.facts.store import FactStore
from netgrapher.flows import FlowTable
from netgrapher.infer.engine import infer
from netgrapher.pipeline import IngestStats, ingest
from netgrapher.project.format import Project, utc_now


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_file(path: Path, *, record_flows: bool = True, run_id: str = "r1") -> Project:
    """Passive analysis of a pcap/pcapng file (FR-IN-2, FR-IN-3)."""
    source = FileSource(path)
    store = FactStore()
    flows = FlowTable() if record_flows else None
    analyzed = utc_now()
    stats = ingest(source, store, run_id, flows=flows)
    graph = infer(store)
    run = {
        "id": run_id,
        "mode": str(Mode.PASSIVE),
        "source": "file",
        "input": str(path),
        "interfaces": [
            {"name": i.name, "linktype": i.linktype, "snaplen": i.snaplen}
            for i in source.interfaces
        ],
        "cidrs": [],
        "scope": None,
        "started": _iso(stats.first_ts),
        "ended": _iso(stats.last_ts),
        "analyzed": analyzed,
        "stop_reason": "end-of-file",
        "stats": _stats_dict(stats, source),
        "facts": len(store),
    }
    return Project(graph=graph, runs=[run], flows=flows.to_list() if flows else [])


def _stats_dict(stats: IngestStats, source: FileSource) -> dict[str, Any]:
    capture = asdict(source.stats)
    return {
        "packets": stats.packets,
        "ipv4": stats.ipv4,
        "malformed": stats.malformed,
        "extractor_errors": stats.extractor_errors,
        "unsupported_linktype": stats.unsupported_linktype,
        "ipv6_skipped": stats.ipv6_skipped,
        "linktypes": sorted(stats.linktypes),
        "protocols": dict(sorted(stats.protocols.items())),
        "truncated_tail": capture["truncated_tail"],
        "if_received": {str(k): v for k, v in capture["if_received"].items()},
        "if_dropped": {str(k): v for k, v in capture["if_dropped"].items()},
        "os_dropped": {str(k): v for k, v in capture["os_dropped"].items()},
    }
