"""Evidence combination. See design §6.4."""

from __future__ import annotations

from collections.abc import Iterable


def noisy_or(weights: Iterable[float]) -> float:
    """Combine independent evidence weights: 1 - prod(1 - w)."""
    disbelief = 1.0
    for w in weights:
        if not 0.0 <= w <= 1.0:
            raise ValueError(f"weight out of range: {w}")
        disbelief *= 1.0 - w
    return round(1.0 - disbelief, 6)  # avoid float noise such as 0.19999999999999996
