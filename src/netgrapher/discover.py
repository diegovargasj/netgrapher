"""Discovery runs: source -> facts -> graph -> project."""

from __future__ import annotations

import contextlib
import queue
import signal
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Protocol

from netgrapher.capture.hostinfo import HostConfig, add_host_facts, read_host_config
from netgrapher.capture.live import LiveSource
from netgrapher.capture.source import CaptureStats, FileSource, RawPacket
from netgrapher.config import Mode
from netgrapher.facts.model import Observation, Provenance
from netgrapher.facts.store import FactStore
from netgrapher.flows import FlowTable
from netgrapher.graph.model import EntityType, Graph
from netgrapher.infer.engine import infer
from netgrapher.pipeline import Ingestor, IngestStats
from netgrapher.project.format import Project, utc_now

PROGRESS_INTERVAL_S = 0.5
TICK_INTERVAL_S = 2.0
DRAIN_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class Status:
    elapsed: float
    packets: int
    entities: int | None = None
    fraction: float | None = None  # file progress
    stopping: str | None = None  # stop reason once stopping


StatusCallback = Callable[[Status], None]
MessageCallback = Callable[[str], None]


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _stats_dict(
    stats: IngestStats, capture: CaptureStats, prober: ProbeController | None = None
) -> dict[str, Any]:
    return {
        "packets": stats.packets,
        "ipv4": stats.ipv4,
        "malformed": stats.malformed,
        "extractor_errors": stats.extractor_errors,
        "unsupported_linktype": stats.unsupported_linktype,
        "ipv6_skipped": stats.ipv6_skipped,
        "tunneled": stats.tunneled,
        "linktypes": sorted(stats.linktypes),
        "protocols": dict(sorted(stats.protocols.items())),
        "truncated_tail": capture.truncated_tail,
        "if_received": {str(k): v for k, v in capture.if_received.items()},
        "if_dropped": {str(k): v for k, v in capture.if_dropped.items()},
        "os_dropped": {str(k): v for k, v in capture.os_dropped.items()},
        "probes_sent": prober.sent if prober is not None else 0,
    }


def run_file(
    path: Path,
    *,
    record_flows: bool = True,
    run_id: str = "r1",
    on_status: StatusCallback | None = None,
) -> Project:
    """Passive analysis of a pcap/pcapng file (FR-IN-2, FR-IN-3)."""
    source = FileSource(path)
    store = FactStore()
    flows = FlowTable() if record_flows else None
    ingestor = Ingestor(store, run_id, flows=flows)
    analyzed = utc_now()
    start = time.monotonic()
    next_progress = start + PROGRESS_INTERVAL_S
    for raw in source:
        ingestor.add(raw)
        if on_status and ingestor.stats.packets % 1000 == 0:
            now = time.monotonic()
            if now >= next_progress:
                on_status(Status(now - start, ingestor.stats.packets, fraction=source.progress()))
                next_progress = now + PROGRESS_INTERVAL_S
    stats = ingestor.stats
    run = {
        "id": run_id,
        "mode": str(Mode.PASSIVE),
        "source": "file",
        "input": str(path),
        "interfaces": [
            {"name": i.name, "linktype": i.linktype, "snaplen": i.snaplen}
            for i in source.interfaces
        ],
        "cidrs": [],
        "scope": None,
        "started": _iso(stats.first_ts),
        "ended": _iso(stats.last_ts),
        "analyzed": analyzed,
        "stop_reason": "end-of-file",
        "stats": _stats_dict(stats, source.stats),
        "hostcfg": None,
        "capture_file": None,
        "facts": len(store),
    }
    return Project(graph=infer(store), runs=[run], flows=flows.to_list() if flows else [])


@dataclass(frozen=True)
class LiveOptions:
    duration_s: float | None = None
    packets: int | None = None
    until_converged_s: float | None = None
    tick_s: float = TICK_INTERVAL_S
    drain_timeout_s: float = DRAIN_TIMEOUT_S


class _StopRequests:
    """First Ctrl-C/SIGTERM asks for a clean stop; a second one forces it (FR-ST-4, FR-ST-5)."""

    def __init__(self, on_message: MessageCallback | None) -> None:
        self.requested = False
        self.forced = False
        self._on_message = on_message

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        if self.requested:
            self.forced = True
            if self._on_message:
                self._on_message("Forcing stop; saving what was collected...")
        else:
            self.requested = True
            if self._on_message:
                self._on_message("Stopping cleanly (press Ctrl-C again to force)...")

    @contextlib.contextmanager
    def installed(self) -> Iterator[None]:
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        previous = {
            sig: signal.signal(sig, self._handle) for sig in (signal.SIGINT, signal.SIGTERM)
        }
        try:
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


_END = object()


@dataclass
class FactBatch:
    observations: list[Observation]
    kind: str  # probe kind, for statistics


class ProbeController(Protocol):
    sent: int
    error: BaseException | None

    def start(self) -> None: ...
    def feed_entities(self, entities: list[tuple[str, str]]) -> None: ...
    def is_idle(self) -> bool: ...
    def request_stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...


def planner_entities(graph: Graph) -> list[tuple[str, str]]:
    """(entity_type, address-or-prefix) for the reactive planner; routers: one per interface."""
    out: list[tuple[str, str]] = []
    for entity in graph.entities.values():
        if entity.type is EntityType.SUBNET:
            out.append(("subnet", entity.attrs["prefix"]))
        elif entity.type is EntityType.HOST and not entity.attrs.get("is_self"):
            out.append(("host", entity.attrs["ip"]))
        elif entity.type is EntityType.ROUTER:
            for iface in entity.attrs.get("interfaces", []):
                if iface.get("ip"):
                    out.append(("router", iface["ip"]))
    return out


def run_live(
    source: LiveSource,
    options: LiveOptions,
    *,
    record_flows: bool = True,
    run_id: str = "r1",
    host_config: Callable[[], HostConfig] | None = None,
    on_status: StatusCallback | None = None,
    on_message: MessageCallback | None = None,
    on_graph: Callable[[Graph], None] | None = None,
    make_prober: Callable[[Callable[[list[Observation], str], None]], ProbeController]
    | None = None,
    mode: Mode = Mode.PASSIVE,
    cidrs: tuple[str, ...] = (),
    scope_desc: dict[str, object] | None = None,
) -> Project:
    """Live capture. In active/reactive mode a prober (from make_prober) runs alongside.

    on_graph receives every intermediate inference result (every tick_s), e.g. for the live UI.
    """
    store = FactStore()
    flows = FlowTable() if record_flows else None
    ingestor = Ingestor(store, run_id, flows=flows)
    host_config = host_config or read_host_config
    hostcfg_start = host_config()
    add_host_facts(store, hostcfg_start, run_id)
    for warning in hostcfg_start.warnings:
        if on_message:
            on_message(f"warning: {warning}")

    packets: queue.Queue[object] = queue.Queue(maxsize=100_000)
    errors: list[BaseException] = []

    def emit_facts(observations: list[Observation], kind: str) -> None:
        packets.put(FactBatch(observations, kind))

    def absorb(batch: FactBatch) -> None:
        for obs in batch.observations:
            store.add(obs, ts=time.time(), frame=None, run_id=run_id, provenance=Provenance.PROBE)
        ingestor.stats.protocols[f"probe:{batch.kind}"] += 1

    prober = make_prober(emit_facts) if make_prober else None
    probe_fed: set[tuple[str, str]] = set()

    def read_packets() -> None:
        try:
            for raw in source:
                packets.put(raw)
        except BaseException as exc:
            errors.append(exc)
        finally:
            packets.put(_END)

    reader = threading.Thread(target=read_packets, name="capture-reader", daemon=True)
    started_wall = utc_now()
    start = time.monotonic()
    reader.start()
    if prober is not None:
        prober.start()

    stops = _StopRequests(on_message)
    stop_reason: str | None = None
    drain_deadline = float("inf")
    next_tick = start + options.tick_s
    last_new = start
    known: set[str] = set()

    with stops.installed():
        while True:
            if stops.forced:
                stop_reason = stop_reason or "interrupted"
                source.kill()
                break
            try:
                item = packets.get(timeout=0.2)
            except queue.Empty:
                item = None
            if item is _END:
                break
            if isinstance(item, RawPacket) and not (
                options.packets and ingestor.stats.packets >= options.packets
            ):
                ingestor.add(item)
            elif isinstance(item, FactBatch):
                absorb(item)

            now = time.monotonic()
            if prober is not None and prober.error is not None and stop_reason is None:
                stop_reason = "probe-error"
                if on_message:
                    on_message(f"probing stopped: {prober.error}")
                source.stop()
                drain_deadline = now + options.drain_timeout_s
            if stop_reason is None:
                if stops.requested:
                    stop_reason = "interrupted"
                elif options.duration_s and now - start >= options.duration_s:
                    stop_reason = "duration"
                elif options.packets and ingestor.stats.packets >= options.packets:
                    stop_reason = "packet-count"
                elif (
                    options.until_converged_s
                    and now - last_new >= options.until_converged_s
                    and (prober is None or prober.is_idle())
                ):
                    stop_reason = "converged"
                if stop_reason is not None:
                    source.stop()
                    drain_deadline = now + options.drain_timeout_s
            elif now >= drain_deadline:
                source.kill()
                drain_deadline = float("inf")

            if now >= next_tick:
                graph = infer(store)
                if on_graph:
                    on_graph(graph)
                if prober is not None:
                    fresh = [e for e in planner_entities(graph) if e not in probe_fed]
                    if fresh:
                        probe_fed.update(fresh)
                        prober.feed_entities(fresh)
                current = set(graph.entities)
                if current - known:
                    last_new = now
                    known |= current
                if on_status:
                    on_status(
                        Status(
                            now - start, ingestor.stats.packets, len(current), stopping=stop_reason
                        )
                    )
                next_tick = now + options.tick_s

    if prober is not None:
        prober.request_stop()
        prober.join(timeout=options.drain_timeout_s)
        while True:  # absorb facts emitted just before the prober stopped
            try:
                item = packets.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, FactBatch):
                absorb(item)
    reader.join(timeout=options.drain_timeout_s)
    if errors and stop_reason is None:
        raise errors[0]
    stop_reason = stop_reason or "capture-ended"

    hostcfg_end = host_config()
    add_host_facts(store, hostcfg_end, run_id)
    stats = ingestor.stats
    run = {
        "id": run_id,
        "mode": str(mode),
        "source": "live",
        "input": None,
        "interfaces": [
            {"name": i.name, "linktype": i.linktype, "snaplen": i.snaplen}
            for i in source.interfaces
        ]
        or [
            {"name": n, "linktype": None, "snaplen": source.snaplen} for n in source.interface_names
        ],
        "cidrs": list(cidrs),
        "scope": scope_desc,
        "started": started_wall,
        "ended": utc_now(),
        "analyzed": utc_now(),
        "stop_reason": stop_reason,
        "stats": _stats_dict(stats, source.stats, prober),
        "hostcfg": {"start": hostcfg_start.to_dict(), "end": hostcfg_end.to_dict()},
        "capture_file": str(source.write_path) if source.write_path else None,
        "facts": len(store),
    }
    return Project(graph=infer(store), runs=[run], flows=flows.to_list() if flows else [])
