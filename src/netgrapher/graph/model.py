"""Entities and links of the L3 graph. See design §6.1 and §6.2."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


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
class Entity:
    id: str
    type: EntityType
    confidence: float
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


@dataclass
class Link:
    id: str
    type: LinkType
    a: str
    b: str
    confidence: float
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
