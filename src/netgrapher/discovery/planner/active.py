"""ActivePlanner: probes only the user-provided CIDRs. Never reacts to observed traffic.

The CIDRs (clipped to scope) are the entire source of targets; passive observations are ignored
for planning. ICMP echo goes to every address; non-responders get a TCP connect; one traceroute
per /24; responsive hosts get a PTR lookup.

See design §8.2.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from netgrapher.discovery.planner import TCP_LIVENESS_PORTS, Planner
from netgrapher.discovery.probes import ProbeOutcome
from netgrapher.discovery.scope import Scope
from netgrapher.discovery.target import ProbeKind, Target


class ActivePlanner(Planner):
    def __init__(
        self,
        cidrs: tuple[str, ...],
        scope: Scope,
        submit: Callable[[Target], None],
        **kwargs: object,
    ) -> None:
        super().__init__(scope, submit, **kwargs)  # type: ignore[arg-type]
        self.cidrs = cidrs
        self._traced_24: set[str] = set()

    def _addresses(self) -> list[str]:
        addrs: list[str] = []
        for cidr in self.cidrs:
            for net in self.scope.clip(cidr):
                hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
                addrs.extend(str(h) for h in hosts)
        return addrs

    def start(self) -> None:
        for ip in self._addresses():
            self.offer(Target(ProbeKind.ICMP_ECHO, ip, reason="active:host-discovery"))
        # One traceroute per /24 (to .1), regardless of responses.
        for cidr in self.cidrs:
            for net in self.scope.clip(cidr):
                for sub in _slash24s(net):
                    first = str(next(iter(sub.hosts()), sub.network_address))
                    if _net24(first) not in self._traced_24:
                        self._traced_24.add(_net24(first))
                        self.offer(Target(ProbeKind.UDP_TRACE, first, reason="active:path"))

    def on_outcome(self, target: Target, outcome: object) -> None:
        assert isinstance(outcome, ProbeOutcome)
        if target.kind is ProbeKind.ICMP_ECHO and not outcome.alive:
            self.offer(
                Target(
                    ProbeKind.TCP_CONNECT,
                    target.dst,
                    reason="active:tcp-fallback",
                    ports=TCP_LIVENESS_PORTS,
                )
            )
        if outcome.alive:
            self.offer(Target(ProbeKind.PTR, target.dst, reason="active:name"))


def _slash24s(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list:  # type: ignore[type-arg]
    if net.version != 4 or net.prefixlen >= 24:
        return [net]
    return list(net.subnets(new_prefix=24))


def _net24(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))
