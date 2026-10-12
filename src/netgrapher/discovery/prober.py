"""Rate-limited probe sender. Runs its own asyncio loop in a dedicated thread.

The prober only sends probes and turns their results into facts; it never writes the fact store
directly. Facts go to the main run loop through `emit_facts` (thread-safe), keeping the store
single-writer. The planner feeds it targets (`submit`) and, for reactive mode, graph entities
(`feed_entities`); both are thread-safe. See design §5.2, §8.4.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

from netgrapher.discovery.audit import AuditLog
from netgrapher.discovery.planner import Planner
from netgrapher.discovery.probes import ProbeOutcome, run_probe
from netgrapher.discovery.ratelimit import RateLimiter
from netgrapher.discovery.target import Target
from netgrapher.discovery.transport import ProbeTransport, UnsupportedTransport
from netgrapher.facts.model import Observation


class _TransportUnavailable(Exception):
    def __init__(self, target: Target) -> None:
        super().__init__(f"probing unavailable for {target.kind}")


EmitFacts = Callable[[list[Observation], str], None]
PlannerFactory = Callable[[Callable[[Target], None]], Planner]


class Prober:
    def __init__(
        self,
        make_planner: PlannerFactory,
        transport: ProbeTransport,
        rate_limiter: RateLimiter,
        audit: AuditLog,
        emit_facts: EmitFacts,
        *,
        max_in_flight: int = 256,
        probe_kwargs: dict[str, object] | None = None,
    ) -> None:
        self.transport = transport
        self.rate = rate_limiter
        self.audit = audit
        self.emit_facts = emit_facts
        self.max_in_flight = max_in_flight
        self._probe_kwargs = probe_kwargs or {}
        self.planner = make_planner(self._submit)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.PriorityQueue[Target] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self._in_flight = 0
        self._pending = 0  # queued but not yet taken
        self._feed_pending = 0  # entity batches scheduled but not yet processed
        self._lock = threading.Lock()
        self.sent = 0
        self.error: BaseException | None = None

    # -- lifecycle (called from the main thread) --------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="prober", daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)

    def request_stop(self) -> None:
        self._stop.set()
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(lambda: None)  # wake the loop

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def is_idle(self) -> bool:
        with self._lock:
            return (
                self._started.is_set()
                and self._pending == 0
                and self._in_flight == 0
                and self._feed_pending == 0
            )

    def feed_entities(self, entities: list[tuple[str, str]]) -> None:
        loop = self._loop
        if loop is None or self._stop.is_set():
            return
        with self._lock:
            self._feed_pending += 1

        def process() -> None:
            try:
                self.planner.on_entities(entities)
            finally:
                with self._lock:
                    self._feed_pending -= 1

        loop.call_soon_threadsafe(process)

    # -- internals (prober thread) ----------------------------------------------------------

    def _submit(self, target: Target) -> None:
        # Called from the prober loop (planner runs there).
        assert self._queue is not None
        with self._lock:
            self._pending += 1
        self._queue.put_nowait(target)

    def _run(self) -> None:
        try:
            asyncio.run(self._main())
        except BaseException as exc:  # surfaced to the main thread after join
            self.error = exc

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.PriorityQueue()
        self.planner.start()
        self._started.set()
        workers = [asyncio.create_task(self._worker()) for _ in range(self.max_in_flight)]
        while not self._stop.is_set():
            await asyncio.sleep(0.05)
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            target = await self._queue.get()
            with self._lock:
                self._pending -= 1
                self._in_flight += 1
            try:
                await self.rate.acquire(target.dst)
                if self._stop.is_set():
                    return
                outcome = await run_probe(target, self.transport, **self._probe_kwargs)  # type: ignore[arg-type]
                self.sent += 1
                self._audit(target)
                if outcome.observations:
                    self.emit_facts(outcome.observations, target.dedup_key()[0])
                self.planner.on_outcome(target, outcome)
            except asyncio.CancelledError:
                with self._lock:
                    self._in_flight -= 1
                raise
            except UnsupportedTransport:
                self._stop.set()
                self.error = self.error or _TransportUnavailable(target)
                with self._lock:
                    self._in_flight -= 1
                return
            except OSError:
                self.planner.on_outcome(target, ProbeOutcome())
                with self._lock:
                    self._in_flight -= 1
                continue
            with self._lock:
                self._in_flight -= 1

    def _audit(self, target: Target) -> None:
        self.audit.record(
            type=str(target.kind),
            dst=target.dst,
            reason=target.reason,
            trigger=target.trigger,
            generation=target.generation,
        )
