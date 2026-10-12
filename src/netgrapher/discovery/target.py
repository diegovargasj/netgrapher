"""Probe targets: what the planner asks the prober to do. See design §8.2, §8.3."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ProbeKind(StrEnum):
    ICMP_ECHO = "icmp-echo"
    TCP_CONNECT = "tcp-connect"
    UDP_TRACE = "udp-trace"
    PTR = "ptr"


# Lower sorts first: traceroutes to new networks, then liveness, then names (design §8.3).
PRIORITY = {
    ProbeKind.UDP_TRACE: 0,
    ProbeKind.ICMP_ECHO: 1,
    ProbeKind.TCP_CONNECT: 1,
    ProbeKind.PTR: 3,
}


@dataclass(order=True)
class Target:
    sort_index: tuple[int, int] = field(init=False)
    kind: ProbeKind = field(compare=False)
    dst: str = field(compare=False)
    reason: str = field(default="", compare=False)
    trigger: str | None = field(default=None, compare=False)
    generation: int = field(default=1, compare=False)
    ports: tuple[int, ...] = field(default=(), compare=False)
    seq: int = field(default=0, compare=False)  # tiebreaker: FIFO within a priority

    def __post_init__(self) -> None:
        self.sort_index = (PRIORITY[self.kind], self.seq)

    def dedup_key(self) -> tuple[str, str]:
        return (str(self.kind), self.dst)
