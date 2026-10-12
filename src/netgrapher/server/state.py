"""Server-side state: the open project, its file, unsaved changes, recent files, autosave."""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from netgrapher.project.format import Project
from netgrapher.project.store import save

AUTOSAVE_INTERVAL_S = 30.0
MAX_RECENT = 10


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "netgrapher"


def autosave_path(path: Path) -> Path:
    return path.with_name(path.name + ".autosave")


@dataclass
class AppState:
    project: Project = field(default_factory=Project)
    path: Path | None = None
    dirty: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock)

    def open(self, project: Project, path: Path | None) -> None:
        with self.lock:
            self.project = project
            self.path = path.resolve() if path else None
            self.dirty = False
            if self.path:
                remember_recent(self.path)

    def save(self) -> None:
        with self.lock:
            if self.path is None:
                raise ValueError("this project has no file yet; use Save as")
            save(self.project, self.path)
            self.dirty = False
            autosave_path(self.path).unlink(missing_ok=True)

    def autosave(self) -> bool:
        """Write unsaved changes next to the project file. Returns True if it wrote."""
        with self.lock:
            if not self.dirty or self.path is None:
                return False
            save(self.project, autosave_path(self.path))
            return True

    def autosave_forever(
        self, stop: threading.Event, interval: float = AUTOSAVE_INTERVAL_S
    ) -> None:
        while not stop.wait(interval):
            # A failing autosave is not fatal; the next explicit save reports the problem.
            with contextlib.suppress(OSError):
                self.autosave()


def _recent_file() -> Path:
    return config_dir() / "recent.json"


def recent_projects() -> list[dict[str, object]]:
    try:
        entries = json.loads(_recent_file().read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(entries, list):
        return []
    return [
        e
        for e in entries
        if isinstance(e, dict) and isinstance(e.get("path"), str) and Path(e["path"]).is_file()
    ][:MAX_RECENT]


def remember_recent(path: Path) -> None:
    entries = [e for e in recent_projects() if e["path"] != str(path)]
    entries.insert(0, {"path": str(path), "opened": time.time()})
    target = _recent_file()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(entries[:MAX_RECENT], indent=2))
    except OSError:
        pass
