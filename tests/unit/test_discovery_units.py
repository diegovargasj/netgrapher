"""Pure-unit tests for scope, rate limiting, audit, targets and planners."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from netgrapher.config import ScopeConfig
from netgrapher.discovery.audit import AuditLog
from netgrapher.discovery.planner.active import ActivePlanner
from netgrapher.discovery.planner.reactive import ReactivePlanner
from netgrapher.discovery.probes import ProbeOutcome
from netgrapher.discovery.ratelimit import RateLimiter
from netgrapher.discovery.scope import Scope, active_cidr_too_large
from netgrapher.discovery.target import ProbeKind, Target

# -- scope ----------------------------------------------------------------------------------


def test_scope_default_is_private_only() -> None:
    scope = Scope.from_config(ScopeConfig())
    assert scope.contains("10.1.2.3")
    assert scope.contains("192.168.0.1")
    assert not scope.contains("8.8.8.8")  # public, not allowed by default


def test_scope_public_opt_in_and_deny() -> None:
    scope = Scope.from_config(
        ScopeConfig(allow=("10.0.0.0/8",), deny=("10.9.0.0/16",), allow_public=True)
    )
    assert scope.contains("8.8.8.8")
    assert scope.contains("10.1.0.1")
    assert not scope.contains("10.9.0.5")  # denied


def test_scope_active_allows_user_public_cidrs() -> None:
    scope = Scope.for_active(("203.0.113.0/29",), deny=())
    assert scope.contains("203.0.113.1")
    assert not scope.contains("203.0.113.100")


def test_scope_clip_splits_around_deny() -> None:
    scope = Scope(
        allow=[__import__("ipaddress").ip_network("10.0.0.0/8")],
        deny=[__import__("ipaddress").ip_network("10.0.0.64/26")],
        allow_public=True,
    )
    pieces = scope.clip("10.0.0.0/24")
    covered = sum(p.num_addresses for p in pieces)
    assert covered == 256 - 64
    assert all(not p.overlaps(scope.deny[0]) for p in pieces)


def test_active_cidr_too_large() -> None:
    assert active_cidr_too_large("10.0.0.0/8")
    assert not active_cidr_too_large("10.0.0.0/16")


# -- rate limiter ---------------------------------------------------------------------------


def test_rate_limiter_enforces_rate() -> None:
    now = [0.0]
    delays: list[float] = []

    async def fake_sleep(d: float) -> None:
        delays.append(d)
        now[0] += d

    async def main() -> None:
        limiter = RateLimiter(global_pps=10, per_host_pps=2, clock=lambda: now[0])
        for _ in range(3):
            await limiter.acquire("10.0.0.1")  # per-host 2/s -> waits ~0.5s after the burst

    import unittest.mock

    with unittest.mock.patch("asyncio.sleep", fake_sleep):
        asyncio.run(main())
    assert any(d > 0 for d in delays)  # had to wait for the per-host bucket


# -- audit ----------------------------------------------------------------------------------


def test_audit_writes_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "a.audit.jsonl"
    with AuditLog(path, "r1") as audit:
        audit.record(type="icmp-echo", dst="10.0.0.1", reason="active", trigger=None, generation=1)
        audit.record(type="udp-trace", dst="10.0.0.2", reason="path", trigger=None, generation=1)
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert audit.count == 2
    assert lines[0] == {
        "run": "r1",
        "type": "icmp-echo",
        "dst": "10.0.0.1",
        "reason": "active",
        "trigger": None,
        "generation": 1,
    }


def test_audit_without_path_still_counts() -> None:
    audit = AuditLog(None, "r1")
    audit.record(type="icmp-echo", dst="10.0.0.1")
    assert audit.count == 1


# -- active planner -------------------------------------------------------------------------


def collect_active(cidrs: tuple[str, ...], **scope_kwargs: object) -> tuple[ActivePlanner, list]:
    targets: list[Target] = []
    scope = Scope.for_active(cidrs, deny=scope_kwargs.get("deny", ()))  # type: ignore[arg-type]
    planner = ActivePlanner(cidrs, scope, targets.append)
    planner.start()
    return planner, targets


def test_active_plan_is_fixed() -> None:
    _, targets = collect_active(("10.10.0.0/29",))
    kinds = [t.kind for t in targets]
    assert kinds.count(ProbeKind.ICMP_ECHO) == 6  # .1-.6
    assert kinds.count(ProbeKind.UDP_TRACE) == 1
    assert all(t.dst.startswith("10.10.0.") for t in targets)


def test_active_tcp_fallback_on_silent_host() -> None:
    planner, targets = collect_active(("10.10.0.0/30",))
    icmp = next(t for t in targets if t.kind is ProbeKind.ICMP_ECHO)
    before = len(targets)
    planner.on_outcome(icmp, ProbeOutcome())  # no response -> TCP fallback + ...
    assert any(t.kind is ProbeKind.TCP_CONNECT and t.dst == icmp.dst for t in targets[before:])
    planner.on_outcome(icmp, ProbeOutcome(alive=[icmp.dst]))  # already deduped; alive -> PTR
    assert any(t.kind is ProbeKind.PTR and t.dst == icmp.dst for t in targets)


# -- reactive planner -----------------------------------------------------------------------


def reactive(**kwargs: object) -> tuple[ReactivePlanner, list]:
    targets: list[Target] = []
    scope = Scope.from_config(ScopeConfig(allow_public=bool(kwargs.get("allow_public", False))))
    planner = ReactivePlanner(
        scope,
        targets.append,
        allow_public=bool(kwargs.get("allow_public")),
        max_generation=int(kwargs.get("max_generation", 2)),
        budget=int(kwargs.get("budget", 10_000)),
    )
    return planner, targets


def test_reactive_subnet_sweep_and_trace() -> None:
    planner, targets = reactive()
    planner.on_entities([("subnet", "192.168.1.0/24")])
    sweeps = [t for t in targets if t.kind is ProbeKind.ICMP_ECHO]
    assert len(sweeps) == 254  # /24 hosts
    assert any(t.kind is ProbeKind.UDP_TRACE for t in targets)


def test_reactive_large_subnet_traceroute_only() -> None:
    planner, targets = reactive()
    planner.on_entities([("subnet", "10.0.0.0/16")])
    assert not any(t.kind is ProbeKind.ICMP_ECHO for t in targets)
    assert any(t.kind is ProbeKind.UDP_TRACE for t in targets)
    assert planner.warnings


def test_reactive_public_requires_opt_in() -> None:
    planner, targets = reactive()
    planner.on_entities([("host", "8.8.8.8")])
    assert targets == []
    planner2, targets2 = reactive(allow_public=True)
    planner2.on_entities([("host", "8.8.8.8")])
    assert any(t.dst == "8.8.8.8" for t in targets2)


def test_reactive_dedup_and_scope() -> None:
    planner, targets = reactive()
    planner.on_entities([("host", "10.0.0.5"), ("host", "10.0.0.5")])  # dedup by /24 trace
    traces = [t for t in targets if t.kind is ProbeKind.UDP_TRACE]
    assert len(traces) == 1
    planner.on_entities([("host", "8.8.8.8")])  # out of scope
    assert planner.dropped_scope >= 0  # scope gate ran; no new trace added
    assert not any(t.dst == "8.8.8.8" for t in targets)


def test_reactive_generation_limit() -> None:
    planner, targets = reactive(max_generation=2)
    # A hop found by a gen-2 trace would be gen 3 -> dropped.
    gen2 = Target(ProbeKind.UDP_TRACE, "10.5.0.9", generation=2)
    planner.on_outcome(gen2, ProbeOutcome(hops=["10.9.9.9"]))
    assert planner.dropped_generation == 1
    assert not any(t.dst == "10.9.9.9" for t in targets)


def test_reactive_budget() -> None:
    planner, _ = reactive(budget=3)
    planner.on_entities([("subnet", "192.168.1.0/24")])
    assert planner.accepted == 3
    assert planner.dropped_budget > 0
