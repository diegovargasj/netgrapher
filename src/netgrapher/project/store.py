"""Atomic load/save of project files."""

from __future__ import annotations

import gzip
import json
import os
import tempfile
from pathlib import Path

from netgrapher.project.format import Project, utc_now
from netgrapher.project.migrate import ProjectError, migrate

__all__ = ["ProjectError", "load", "save"]


def save(project: Project, path: Path) -> None:
    project.modified = utc_now()
    data = json.dumps(project.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(data)
            gz.flush()
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load(path: Path) -> Project:
    try:
        with gzip.open(path, "rb") as f:
            doc = json.loads(f.read())
    except (OSError, EOFError, json.JSONDecodeError) as exc:
        raise ProjectError(f"cannot read {path}: {exc}") from exc
    try:
        return Project.from_dict(migrate(doc))
    except (KeyError, TypeError, ValueError) as exc:
        raise ProjectError(f"corrupt project file {path}: {exc}") from exc
