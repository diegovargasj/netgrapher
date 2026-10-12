"""Probe logic and the prober, using FakeTransport (never touches the network)."""

from __future__ import annotations

import asyncio

from netgrapher.config import ScopeConfig
from netgrapher.discovery.audit import AuditLog
from netgrapher.discovery.planner.reactive import ReactivePlanner
from netgrapher.discovery.prober import Prober
from netgrapher.discovery.probes import run_probe
from netgrapher.discovery.ratelimit import RateLimiter
from netgrapher.discovery.scope import Scope
from netgrapher.discovery.target import ProbeKind, Target
from netgrapher.facts.model import FactKind
from tests.fake_transport import FakeTransport


def run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def test_icmp_probe_alive() -> None:
    t = FakeTransport(icmp_alive={"10.0.0.5": True})
    outcome = run(run_probe(Target(ProbeKind.ICMP_ECHO, "10.0.0.5"), t))
    assert outcome.alive == ["10.0.0.5"]
    assert outcome.observations[0].kind is FactKind.PROBE_ALIVE


def test_icmp_probe_silent() -> None:
    outcome = run(run_probe(Target(ProbeKind.ICMP_ECHO, "10.0.0.9"), FakeTransport()))
    assert outcome.alive == [] and outcome.observations == []


def test_tcp_probe_tries_ports_until_response() -> None:
    t = FakeTransport(tcp_state={"10.0.0.5": "closed"})
    target = Target(ProbeKind.TCP_CONNECT, "10.0.0.5", ports=(443, 80, 22))
    outcome = run(run_probe(target, t))
    assert outcome.alive == ["10.0.0.5"]  # closed port still proves the host exists


def test_trace_produces_hops_and_detects_arrival() -> None:
    t = FakeTransport(
        traces={
            "10.20.0.5": [
                ("10.0.0.1", False),
                ("10.0.0.2", False),
                (None, False),
                ("10.20.0.5", True),
            ]
        }
    )
    outcome = run(run_probe(Target(ProbeKind.UDP_TRACE, "10.20.0.5"), t))
    assert outcome.hops == ["10.0.0.1", "10.0.0.2"]  # silent hop and the target excluded
    assert outcome.reached
    hop_facts = [o for o in outcome.observations if o.kind is FactKind.TRACE_HOP]
    assert len(hop_facts) == 2


def test_prober_runs_targets_and_emits_facts() -> None:
    transport = FakeTransport(
        icmp_alive={"192.168.1.1": True}, traces={"192.168.1.1": [("192.168.1.1", True)]}
    )
    scope = Scope.from_config(ScopeConfig())
    emitted: list[tuple[str, str]] = []

    def emit(obs, kind):  # type: ignore[no-untyped-def]
        for o in obs:
            emitted.append((str(o.kind), o.subject))

    def make_planner(submit):  # type: ignore[no-untyped-def]
        return ReactivePlanner(scope, submit, budget=50)

    prober = Prober(
        make_planner,
        transport,
        RateLimiter(1000, 1000),
        AuditLog(None, "r1"),
        emit,
        max_in_flight=4,
    )
    prober.start()
    prober.feed_entities([("subnet", "192.168.1.0/30")])
    # Wait for the queue to drain.
    import time

    for _ in range(200):
        if prober.is_idle():
            break
        time.sleep(0.02)
    prober.request_stop()
    prober.join(timeout=5)
    assert prober.error is None
    assert ("probe_alive", "192.168.1.1") in emitted
    assert prober.sent > 0
