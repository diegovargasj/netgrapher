"""Assemble the probing machinery for a discovery run from the CLI config. See design §8."""

from __future__ import annotations

from collections.abc import Callable

from netgrapher.config import DiscoveryConfig, Mode
from netgrapher.discovery.audit import AuditLog
from netgrapher.discovery.planner import Planner
from netgrapher.discovery.planner.active import ActivePlanner
from netgrapher.discovery.planner.reactive import ReactivePlanner
from netgrapher.discovery.prober import Prober
from netgrapher.discovery.ratelimit import RateLimiter
from netgrapher.discovery.scope import Scope
from netgrapher.discovery.target import Target
from netgrapher.discovery.transport import ProbeTransport, SocketTransport
from netgrapher.facts.model import Observation


def build_scope(config: DiscoveryConfig, local_subnets: tuple[str, ...]) -> Scope:
    if config.mode is Mode.ACTIVE:
        return Scope.for_active(config.cidrs, config.scope.deny)
    return Scope.from_config(config.scope, local_subnets)


def scope_desc(config: DiscoveryConfig, scope: Scope) -> dict[str, object]:
    return {
        "allow": [str(n) for n in scope.allow],
        "deny": [str(n) for n in scope.deny],
        "allow_public": scope.allow_public,
    }


def make_planner_factory(
    config: DiscoveryConfig, scope: Scope
) -> Callable[[Callable[[Target], None]], Planner]:
    probe = config.probes

    def factory(submit: Callable[[Target], None]) -> Planner:
        if config.mode is Mode.ACTIVE:
            return ActivePlanner(
                config.cidrs,
                scope,
                submit,
                max_generation=probe.max_generation,
                budget=probe.budget,
            )
        return ReactivePlanner(
            scope,
            submit,
            allow_public=scope.allow_public,
            max_generation=probe.max_generation,
            budget=probe.budget,
        )

    return factory


def make_prober_factory(
    config: DiscoveryConfig,
    scope: Scope,
    audit: AuditLog,
    *,
    transport: ProbeTransport | None = None,
) -> Callable[[Callable[[list[Observation], str], None]], Prober]:
    probe = config.probes
    planner_factory = make_planner_factory(config, scope)
    transport = transport or SocketTransport()

    def factory(emit_facts: Callable[[list[Observation], str], None]) -> Prober:
        rate = RateLimiter(probe.rate_pps, probe.rate_per_host_pps)
        return Prober(
            planner_factory,
            transport,
            rate,
            audit,
            emit_facts,
            max_in_flight=probe.max_in_flight,
            probe_kwargs={
                "icmp_timeout": probe.icmp_timeout_s,
                "tcp_timeout": probe.tcp_timeout_s,
                "trace_max_ttl": probe.trace_max_ttl,
                "trace_max_silent": probe.trace_max_silent_hops,
            },
        )

    return factory


def plan_active_dry_run(config: DiscoveryConfig, scope: Scope) -> list[Target]:
    """The fixed set of probes active mode would send (host discovery + one trace per /24)."""
    collected: list[Target] = []
    planner = ActivePlanner(
        config.cidrs,
        scope,
        collected.append,
        max_generation=config.probes.max_generation,
        budget=config.probes.budget,
    )
    planner.start()
    return collected


class DryController:
    """Records the targets a reactive run would probe, without sending anything (--dry-run)."""

    sent = 0
    error: BaseException | None = None

    def __init__(self, config: DiscoveryConfig, scope: Scope) -> None:
        self.targets: list[Target] = []
        self.planner = make_planner_factory(config, scope)(self.targets.append)

    def start(self) -> None:
        self.planner.start()

    def feed_entities(self, entities: list[tuple[str, str]]) -> None:
        self.planner.on_entities(entities)

    def is_idle(self) -> bool:
        return True

    def request_stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...
