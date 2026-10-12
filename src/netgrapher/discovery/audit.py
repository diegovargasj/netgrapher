"""Per-run JSON Lines audit log of every probe sent. See design §8.5, FR-DM-12."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO


class AuditLog:
    """Append-only JSONL. Also usable as a context manager."""

    def __init__(self, path: Path | None, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self.count = 0
        self._file: TextIO | None = None

    def __enter__(self) -> AuditLog:
        if self.path is not None:
            self._file = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def record(self, **fields: Any) -> None:
        self.count += 1
        if self._file is None:
            return
        line = {"run": self.run_id, **fields}
        self._file.write(json.dumps(line, separators=(",", ":")) + "\n")
        self._file.flush()

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
