"""End-to-end active/reactive discovery through run_live, with a fake dumpcap and FakeTransport.

No real capture and no real probes. Verifies probe facts reach the graph and the audit log,
and that convergence waits for the prober to go idle.
"""

from __future__ import annotations

from pathlib import Path

from netgrapher.config import DiscoveryConfig, Mode, ProbeConfig, ScopeConfig
from netgrapher.discover import LiveOptions, run_live
from netgrapher.discovery.audit import AuditLog
from netgrapher.discovery.controller import make_prober_factory
from netgrapher.discovery.scope import Scope
from netgrapher.graph.model import EntityType
from tests.fake_transport import FakeTransport
from tests.unit.test_live import (  # noqa: F401
    fake_dumpcap,
    fake_host,
    source,
)


def prober_factory(config: DiscoveryConfig, transport: FakeTransport, audit: AuditLog):  # type: ignore[no-untyped-def]
    if config.mode is Mode.ACTIVE:
        scope = Scope.for_active(config.cidrs, config.scope.deny)
    else:
        scope = Scope.from_config(config.scope)
    return make_prober_factory(config, scope, audit, transport=transport)


def test_reactive_run_probes_and_adds_trace_facts(fake_dumpcap: Path, tmp_path: Path) -> None:  # noqa: F811
    # The office LAN is 192.168.1.0/24; make the gateway answer a traceroute into a remote net.
    transport = FakeTransport(
        icmp_alive={"192.168.1.1": True},
        traces={
            f"192.168.1.{i}": [("192.168.1.1", False), ("10.0.0.2", True)] for i in range(1, 255)
        },
    )
    config = DiscoveryConfig(
        mode=Mode.REACTIVE,
        scope=ScopeConfig(),
        probes=ProbeConfig(rate_pps=10_000, rate_per_host_pps=10_000, budget=400),
    )
    audit_path = tmp_path / "r.audit.jsonl"
    with AuditLog(audit_path, "r1") as audit:
        project = run_live(
            source(),
            LiveOptions(duration_s=1.5, tick_s=0.1, drain_timeout_s=2.0),
            host_config=fake_host,
            mode=Mode.REACTIVE,
            cidrs=(),
            make_prober=prober_factory(config, transport, audit),
        )
    assert project.runs[0]["mode"] == "reactive"
    assert project.runs[0]["stats"]["probes_sent"] > 0
    assert any(k.startswith("probe:") for k in project.runs[0]["stats"]["protocols"])
    # The traceroute hop 10.0.0.2 should appear as a router found by probing.
    assert "rtr:10.0.0.2" in project.graph.entities
    assert project.graph.entities["rtr:10.0.0.2"].type is EntityType.ROUTER
    assert audit_path.exists() and audit_path.read_text().strip()


def test_active_run_only_probes_given_cidrs(fake_dumpcap: Path) -> None:  # noqa: F811
    transport = FakeTransport(icmp_alive={"203.0.113.2": True})
    config = DiscoveryConfig(
        mode=Mode.ACTIVE,
        cidrs=("203.0.113.0/30",),
        probes=ProbeConfig(rate_pps=10_000, rate_per_host_pps=10_000),
    )
    project = run_live(
        source(),
        LiveOptions(duration_s=1.0, tick_s=0.1, drain_timeout_s=2.0),
        host_config=fake_host,
        mode=Mode.ACTIVE,
        cidrs=("203.0.113.0/30",),
        make_prober=prober_factory(config, transport, AuditLog(None, "r1")),
    )
    # Only the user's CIDR was probed (plus the office LAN seen passively, never probed).
    probed = {dst for _, dst in transport.sent}
    assert probed <= {"203.0.113.1", "203.0.113.2"}
    assert "host:203.0.113.2" in project.graph.entities
    assert not any(dst.startswith("192.168.1.") for _, dst in transport.sent)
