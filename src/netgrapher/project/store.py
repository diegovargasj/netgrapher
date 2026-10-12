"""Atomic load/save of project files."""

from __future__ import annotations

import gzip
import io
import json
import os
import tempfile
from pathlib import Path

from netgrapher.project.format import Project, utc_now
from netgrapher.project.migrate import ProjectError, migrate

__all__ = ["ProjectError", "dumps", "load", "loads", "save"]

MAX_PROJECT_BYTES = 512 * 1024 * 1024  # decompressed


def dumps(project: Project) -> bytes:
    """Serialize to the gzipped .ngraph format."""
    data = json.dumps(project.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    return gzip.compress(data, mtime=0)


def save(project: Project, path: Path) -> None:
    project.modified = utc_now()
    data = dumps(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def loads(data: bytes, name: str = "project") -> Project:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            raw = gz.read(MAX_PROJECT_BYTES + 1)
        if len(raw) > MAX_PROJECT_BYTES:
            raise ProjectError(f"{name} is too large")
        doc = json.loads(raw)
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProjectError(f"cannot read {name}: {exc}") from exc
    try:
        return Project.from_dict(migrate(doc))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ProjectError(f"corrupt project file {name}: {exc}") from exc


def load(path: Path) -> Project:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProjectError(f"cannot read {path}: {exc}") from exc
    return loads(data, str(path))
