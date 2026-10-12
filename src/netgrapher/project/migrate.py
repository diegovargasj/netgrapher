"""Migrations from older project format versions."""

from __future__ import annotations

from typing import Any

from netgrapher.project.format import FORMAT_NAME, FORMAT_VERSION


class ProjectError(Exception):
    pass


def migrate(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("format") != FORMAT_NAME:
        raise ProjectError("not a netgrapher project file")
    version = doc.get("version")
    if not isinstance(version, int) or version < 1:
        raise ProjectError(f"invalid project format version: {version!r}")
    if version > FORMAT_VERSION:
        raise ProjectError(
            f"project format version {version} is newer than supported ({FORMAT_VERSION}); "
            "upgrade netgrapher"
        )
    # Version 1 is the first format: nothing to migrate yet.
    return doc
