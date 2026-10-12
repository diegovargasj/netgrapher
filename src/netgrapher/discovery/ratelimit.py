"""Token-bucket rate limiting, global and per destination. See design §8.4.

async-only: acquire() waits until both the global and the per-destination bucket have a token,
and only then consumes one from each. A pluggable monotonic clock keeps it testable.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable


class TokenBucket:
    def __init__(
        self,
        rate_per_s: float,
        *,
        burst: float | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if rate_per_s <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate_per_s
        self.capacity = burst if burst is not None else max(1.0, rate_per_s)
        self._tokens = self.capacity
        self._clock = clock or time.monotonic
        self._updated = self._clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    def wait_time(self) -> float:
        """Seconds until a token is available (0 if one is ready now). Does not consume."""
        self._refill()
        return 0.0 if self._tokens >= 1 else (1 - self._tokens) / self.rate

    def consume(self) -> None:
        self._tokens -= 1


class RateLimiter:
    """A global bucket plus one bucket per destination."""

    def __init__(
        self, global_pps: float, per_host_pps: float, clock: Callable[[], float] | None = None
    ) -> None:
        self._clock = clock
        self._global = TokenBucket(global_pps, clock=clock)
        self._per_host_rate = per_host_pps
        self._hosts: dict[str, TokenBucket] = {}

    def _host_bucket(self, host: str) -> TokenBucket:
        bucket = self._hosts.get(host)
        if bucket is None:
            bucket = TokenBucket(self._per_host_rate, clock=self._clock)
            self._hosts[host] = bucket
        return bucket

    async def acquire(self, host: str) -> None:
        bucket = self._host_bucket(host)
        while True:
            wait = max(self._global.wait_time(), bucket.wait_time())
            if wait <= 0:
                self._global.consume()
                bucket.consume()
                return
            await asyncio.sleep(wait)
