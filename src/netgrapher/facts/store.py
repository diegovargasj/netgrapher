"""Deduplicated, time-aware fact store."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Hashable, Iterator

from netgrapher.facts.model import MAX_FRAMES, Fact, FactKind, Observation, Provenance

_Key = tuple[FactKind, str, tuple[tuple[str, Hashable], ...], Provenance, str]


class FactStore:
    def __init__(self) -> None:
        self._facts: dict[_Key, Fact] = {}
        self._by_kind: defaultdict[FactKind, list[Fact]] = defaultdict(list)

    def add(
        self,
        obs: Observation,
        *,
        ts: float,
        frame: int | None,
        run_id: str,
        provenance: Provenance = Provenance.PASSIVE,
        probe_id: str | None = None,
    ) -> Fact:
        key = (obs.kind, obs.subject, obs.data, provenance, run_id)
        fact = self._facts.get(key)
        if fact is None:
            fact = Fact(
                obs.kind, obs.subject, obs.data, provenance, run_id, ts, ts, 0, [], probe_id
            )
            self._facts[key] = fact
            self._by_kind[obs.kind].append(fact)
        fact.count += 1
        fact.first_seen = min(fact.first_seen, ts)
        fact.last_seen = max(fact.last_seen, ts)
        if frame is not None and len(fact.frames) < MAX_FRAMES:
            fact.frames.append(frame)
        return fact

    def by_kind(self, kind: FactKind) -> list[Fact]:
        return self._by_kind.get(kind, [])

    def __iter__(self) -> Iterator[Fact]:
        return iter(self._facts.values())

    def __len__(self) -> int:
        return len(self._facts)
