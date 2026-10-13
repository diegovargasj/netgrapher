"""Entities, links and evidence of the L3 graph. See design §6."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# An entity/link is "confirmed" when there is solid evidence for it (vs weak inference such as a
# host only seen as a reference, or a heuristic subnet). Used by the UI's "unconfirmed" tag.
CONFIRMED_THRESHOLD = 0.7


def is_confirmed(confidence: float) -> bool:
    return confidence >= CONFIRMED_THRESHOLD


class EntityType(StrEnum):
    SUBNET = "subnet"
    ROUTER = "router"
    HOST = "host"
    EXTERNAL = "external"
    UNKNOWN_ROUTER = "unknown_router"


class LinkType(StrEnum):
    MEMBER = "member"
    INTERFACE = "interface"
    INFERRED_PATH = "inferred-path"
    UPLINK = "uplink"


@dataclass
class Evidence:
    id: str
    rule: str
    weight: float
    provenance: str
    run: str
    summary: str
    frames: list[int] = field(default_factory=list)
    probe_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "weight": self.weight,
            "provenance": self.provenance,
            "run": self.run,
            "summary": self.summary,
            "frames": self.frames,
            "probe_id": self.probe_id,
        }

    @classmethod
    def from_dict(cls, evidence_id: str, d: dict[str, Any]) -> Evidence:
        return cls(
            evidence_id,
            d["rule"],
            d["weight"],
            d["provenance"],
            d["run"],
            d["summary"],
            list(d.get("frames", [])),
            d.get("probe_id"),
        )


@dataclass
class Entity:
    id: str
    type: EntityType
    confidence: float
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            **self.attrs,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, entity_id: str, d: dict[str, Any]) -> Entity:
        attrs = {k: v for k, v in d.items() if k not in ("type", "confidence", "evidence")}
        return cls(entity_id, EntityType(d["type"]), d["confidence"], attrs, list(d["evidence"]))


@dataclass
class Link:
    id: str
    type: LinkType
    a: str
    b: str
    confidence: float
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "a": self.a,
            "b": self.b,
            **self.attrs,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, link_id: str, d: dict[str, Any]) -> Link:
        reserved = ("type", "a", "b", "confidence", "evidence")
        attrs = {k: v for k, v in d.items() if k not in reserved}
        return cls(
            link_id,
            LinkType(d["type"]),
            d["a"],
            d["b"],
            d["confidence"],
            attrs,
            list(d["evidence"]),
        )


@dataclass
class Graph:
    entities: dict[str, Entity] = field(default_factory=dict)
    links: dict[str, Link] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)

    def add_entity(self, entity: Entity) -> None:
        self.entities[entity.id] = entity

    def add_link(self, link: Link) -> None:
        self.links[link.id] = link
