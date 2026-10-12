"""Project file schema (.ngraph). See design §10."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netgrapher import __version__
from netgrapher.graph.model import Entity, Evidence, Graph, Link

FORMAT_NAME = "netgrapher-project"
FORMAT_VERSION = 1


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Project:
    graph: Graph = field(default_factory=Graph)
    runs: list[dict[str, Any]] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)
    annotations: dict[str, dict[str, Any]] = field(default_factory=dict)
    view: dict[str, Any] = field(default_factory=dict)
    # User overlay (written only by the UI, like annotations): manually added entities/links and
    # ids the user removed. Rendered graph = (discovered + user) minus deleted. See compose.py.
    user_entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_links: dict[str, dict[str, Any]] = field(default_factory=dict)
    deleted: list[str] = field(default_factory=list)
    created: str = field(default_factory=utc_now)
    modified: str = field(default_factory=utc_now)
    tool_version: str = __version__

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "tool_version": self.tool_version,
            "created": self.created,
            "modified": self.modified,
            "runs": self.runs,
            "entities": {k: e.to_dict() for k, e in self.graph.entities.items()},
            "links": {k: lk.to_dict() for k, lk in self.graph.links.items()},
            "evidence": {k: ev.to_dict() for k, ev in self.graph.evidence.items()},
            "aliases": self.aliases,
            "flows": self.flows,
            "annotations": self.annotations,
            "view": self.view,
            "user_entities": self.user_entities,
            "user_links": self.user_links,
            "deleted": self.deleted,
        }

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> Project:
        graph = Graph(
            entities={k: Entity.from_dict(k, v) for k, v in doc["entities"].items()},
            links={k: Link.from_dict(k, v) for k, v in doc["links"].items()},
            evidence={k: Evidence.from_dict(k, v) for k, v in doc["evidence"].items()},
        )
        return cls(
            graph=graph,
            runs=doc.get("runs", []),
            aliases=doc.get("aliases", {}),
            flows=doc.get("flows", []),
            annotations=doc.get("annotations", {}),
            view=doc.get("view", {}),
            user_entities=doc.get("user_entities", {}),
            user_links=doc.get("user_links", {}),
            deleted=list(doc.get("deleted", [])),
            created=doc.get("created", utc_now()),
            modified=doc.get("modified", utc_now()),
            tool_version=doc.get("tool_version", "unknown"),
        )
