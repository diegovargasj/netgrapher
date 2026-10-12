"""Target planners. See design §8.2, §8.3."""

from __future__ import annotations

from collections.abc import Callable

from netgrapher.discovery.scope import Scope
from netgrapher.discovery.target import Target

TCP_LIVENESS_PORTS = (443, 80, 22, 445, 3389)


class Planner:
    """Shared gate: scope, per-(kind,dst) dedup, generation limit and probe budget.

    Accepted targets are handed to `submit`, which the prober fills from.
    """

    def __init__(
        self,
        scope: Scope,
        submit: Callable[[Target], None],
        *,
        max_generation: int = 2,
        budget: int = 10_000,
    ) -> None:
        self.scope = scope
        self._submit = submit
        self.max_generation = max_generation
        self.budget = budget
        self._seen: set[tuple[str, str]] = set()
        self._seq = 0
        self.accepted = 0
        self.dropped_scope = 0
        self.dropped_generation = 0
        self.dropped_budget = 0

    def offer(self, target: Target) -> bool:
        if target.dedup_key() in self._seen:
            return False
        if not self.scope.contains(target.dst):
            self.dropped_scope += 1
            return False
        if target.generation > self.max_generation:
            self.dropped_generation += 1
            return False
        if self.accepted >= self.budget:
            self.dropped_budget += 1
            return False
        self._seen.add(target.dedup_key())
        target.seq = self._seq
        self._seq += 1
        self.accepted += 1
        self._submit(target)
        return True

    # Hooks the prober calls; subclasses override what they need.
    def start(self) -> None: ...
    def on_entities(self, entities: list[tuple[str, str]]) -> None: ...
    def on_outcome(self, target: Target, outcome: object) -> None: ...
