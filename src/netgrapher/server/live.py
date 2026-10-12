"""Bridges a running discovery to the UI: graph diffs, aliases and run statistics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netgrapher.discover import Status
from netgrapher.graph.diff import diff_graphs, migrate_annotations
from netgrapher.graph.model import Graph
from netgrapher.project.format import Project
from netgrapher.server.api import entity_payload
from netgrapher.server.state import AppState


class LiveSession:
    def __init__(self, state: AppState) -> None:
        self.state = state
        with state.lock:
            state.live = {"running": True, "packets": 0, "elapsed": 0.0, "entities": 0}

    def publish_graph(self, graph: Graph) -> None:
        """Replace the project's graph with a new inference result and stream the changes."""
        state = self.state
        with state.lock:
            old = state.project.graph
            d = diff_graphs(old, graph)
            if not d and not d.aliases:
                return
            state.project.graph = graph
            conflicts: list[str] = []
            if d.aliases:
                state.project.aliases.update(d.aliases)
                conflicts = migrate_annotations(state.project.annotations, d.aliases)
                if any(old_id in state.project.annotations for old_id in d.aliases) or conflicts:
                    state.dirty = True
            state.seq += 1
            # User-tombstoned ids must never be re-added by an engine update.
            tombstoned = set(state.project.deleted)
            event: dict[str, Any] = {
                "type": "graph",
                "seq": state.seq,
                "entities": {
                    eid: entity_payload(graph, eid)
                    for eid in d.added + d.updated
                    if eid not in tombstoned
                },
                "removed": d.removed,
                "links": {
                    lid: graph.links[lid].to_dict()
                    for lid in d.links_added + d.links_updated
                    if lid not in tombstoned
                },
                "links_removed": d.links_removed,
                "aliases": d.aliases,
                "annotations": {
                    new: state.project.annotations.get(new, {}) for new in d.aliases.values()
                },
                "conflicts": conflicts,
            }
        state.bus.publish(event)

    def publish_status(self, status: Status) -> None:
        with self.state.lock:
            self.state.live = {
                "running": True,
                "packets": status.packets,
                "elapsed": round(status.elapsed, 1),
                "entities": status.entities,
                "stopping": status.stopping,
            }
            live = dict(self.state.live)
        self.state.bus.publish({"type": "run_stats", **live})

    def finish(self, project: Project, path: Path) -> None:
        """The run is over: keep the user's edits, adopt the final graph and the saved file."""
        state = self.state
        self.publish_graph(project.graph)
        with state.lock:
            project.annotations = state.project.annotations
            project.view = state.project.view
            project.aliases = {**state.project.aliases, **project.aliases}
            project.user_entities = state.project.user_entities
            project.user_links = state.project.user_links
            project.deleted = state.project.deleted
            state.project = project
            state.path = path.resolve()
            state.live = {**(state.live or {}), "running": False}
            state.seq += 1
            seq = state.seq
        state.save()
        state.bus.publish({"type": "run_ended", "seq": seq, "path": str(state.path)})
