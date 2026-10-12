"""Probe logic: turn a Target plus a transport into facts and follow-up information.

Pure apart from the injected transport, so the whole pipeline is testable with a fake transport.
See design §8.4.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

from netgrapher.discovery.target import ProbeKind, Target
from netgrapher.discovery.transport import ProbeTransport
from netgrapher.facts.model import FactKind, Observation, observe
from netgrapher.net import is_usable_unicast

DEFAULT_ICMP_TIMEOUT = 2.0
DEFAULT_TCP_TIMEOUT = 1.0
DEFAULT_TRACE_MAX_TTL = 30
DEFAULT_TRACE_MAX_SILENT = 3


@dataclass
class ProbeOutcome:
    observations: list[Observation] = field(default_factory=list)
    alive: list[str] = field(default_factory=list)  # hosts confirmed up
    hops: list[str] = field(default_factory=list)  # router interfaces found by traceroute
    reached: bool = False  # a traceroute reached its destination


async def run_probe(
    target: Target,
    transport: ProbeTransport,
    *,
    icmp_timeout: float = DEFAULT_ICMP_TIMEOUT,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    trace_max_ttl: int = DEFAULT_TRACE_MAX_TTL,
    trace_max_silent: int = DEFAULT_TRACE_MAX_SILENT,
) -> ProbeOutcome:
    if target.kind is ProbeKind.ICMP_ECHO:
        return await _icmp(target, transport, icmp_timeout)
    if target.kind is ProbeKind.TCP_CONNECT:
        return await _tcp(target, transport, tcp_timeout)
    if target.kind is ProbeKind.UDP_TRACE:
        return await _trace(target, transport, trace_max_ttl, trace_max_silent, icmp_timeout)
    return await _ptr(target)


async def _icmp(target: Target, transport: ProbeTransport, timeout: float) -> ProbeOutcome:
    alive = await transport.icmp_echo(target.dst, timeout)
    if not alive:
        return ProbeOutcome()
    return ProbeOutcome(
        observations=[observe(FactKind.PROBE_ALIVE, target.dst, method="icmp", port=None)],
        alive=[target.dst],
    )


async def _tcp(target: Target, transport: ProbeTransport, timeout: float) -> ProbeOutcome:
    for port in target.ports:
        state = await transport.tcp_connect(target.dst, port, timeout)
        if state in ("open", "closed"):  # either proves the host exists
            return ProbeOutcome(
                observations=[observe(FactKind.PROBE_ALIVE, target.dst, method="tcp", port=port)],
                alive=[target.dst],
            )
    return ProbeOutcome()


async def _trace(
    target: Target, transport: ProbeTransport, max_ttl: int, max_silent: int, timeout: float
) -> ProbeOutcome:
    replies = await transport.udp_trace(target.dst, max_ttl, max_silent, timeout)
    outcome = ProbeOutcome()
    for reply in replies:
        if reply.hop is None or not is_usable_unicast(reply.hop):
            continue
        if reply.reached:
            continue  # the destination itself, not an intermediate router
        outcome.observations.append(
            observe(FactKind.TRACE_HOP, reply.hop, ttl=reply.ttl, target=target.dst, reached=False)
        )
        outcome.hops.append(reply.hop)
    outcome.reached = any(r.reached for r in replies)
    return outcome


async def _ptr(target: Target) -> ProbeOutcome:
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, target.dst)
    except (OSError, UnicodeError):
        return ProbeOutcome()
    name = name.strip().lower()
    if not name:
        return ProbeOutcome()
    return ProbeOutcome(observations=[observe(FactKind.NAME, target.dst, name=name, source="ptr")])
