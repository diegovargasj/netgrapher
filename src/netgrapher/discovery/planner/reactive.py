"""ReactivePlanner: targets derived from observed traffic (and from probe replies), within scope.

Reacts to entities the inference engine produces each tick, plus follow-ups to its own probe
results. Generation tracking, the scope gate and the budget live in the base class. See design §8.3.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from netgrapher.discovery.planner import Planner
from netgrapher.discovery.probes import ProbeOutcome
from netgrapher.discovery.scope import Scope
from netgrapher.discovery.target import ProbeKind, Target
from netgrapher.net import is_external

MAX_SWEEP_PREFIXLEN = 22  # larger prefixes get a traceroute only (design §8.3)


class ReactivePlanner(Planner):
    def __init__(
        self,
        scope: Scope,
        submit: Callable[[Target], None],
        *,
        allow_public: bool = False,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, submit, **kwargs)  # type: ignore[arg-type]
        self.allow_public = allow_public
        self._generation: dict[str, int] = {}  # dst -> generation it was first reached at
        self._traced_24: set[str] = set()
        self._swept: set[str] = set()
        self.warnings: list[str] = []

    def _gen_for(self, ip: str, fallback: int = 1) -> int:
        return self._generation.get(ip, fallback)

    def on_entities(self, entities: list[tuple[str, str]]) -> None:
        """entities: (entity_type, primary_address_or_prefix) for newly seen entities."""
        for etype, value in entities:
            if etype == "subnet":
                self._on_subnet(value)
            elif etype == "host":
                self._on_host(value)
            elif etype == "router":
                self._on_router(value)

    def _on_subnet(self, prefix: str) -> None:
        net = ipaddress.ip_network(prefix, strict=False)
        if net.version != 4:
            return
        gen = 1
        if net.prefixlen >= MAX_SWEEP_PREFIXLEN and str(net) not in self._swept:
            self._swept.add(str(net))
            for host in net.hosts():
                self.offer(
                    Target(
                        ProbeKind.ICMP_ECHO,
                        str(host),
                        reason="reactive:subnet-sweep",
                        trigger=f"net:{net}",
                        generation=gen,
                    )
                )
        elif str(net) not in self._swept:
            self._swept.add(str(net))
            self.warnings.append(f"{net} is larger than /{MAX_SWEEP_PREFIXLEN}; traceroute only")
        self._trace_once(str(net.network_address + 1), f"net:{net}", gen)

    def _on_host(self, ip: str) -> None:
        if is_external(ip) and not self.allow_public:
            return
        self._trace_once(ip, f"host:{ip}", self._gen_for(ip))

    def _on_router(self, ip: str) -> None:
        self.offer(
            Target(
                ProbeKind.PTR,
                ip,
                reason="reactive:router-name",
                trigger=f"rtr:{ip}",
                generation=self._gen_for(ip),
            )
        )

    def _trace_once(self, ip: str, trigger: str, generation: int) -> None:
        key = _net24(ip)
        if key in self._traced_24:
            return
        self._traced_24.add(key)
        self.offer(
            Target(
                ProbeKind.UDP_TRACE,
                ip,
                reason="reactive:path",
                trigger=trigger,
                generation=generation,
            )
        )

    def on_outcome(self, target: Target, outcome: object) -> None:
        assert isinstance(outcome, ProbeOutcome)
        child_gen = target.generation + 1
        for hop in outcome.hops:  # routers found by traceroute are a new generation
            self._generation.setdefault(hop, child_gen)
            self.offer(
                Target(
                    ProbeKind.PTR,
                    hop,
                    reason="reactive:hop-name",
                    trigger=target.trigger,
                    generation=child_gen,
                )
            )
        for ip in outcome.alive:
            self.offer(
                Target(
                    ProbeKind.PTR,
                    ip,
                    reason="reactive:name",
                    trigger=target.trigger,
                    generation=target.generation,
                )
            )


def _net24(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))
