"""A ProbeTransport that never touches the network. Replies are scripted per destination."""

from __future__ import annotations

from dataclasses import dataclass, field

from netgrapher.discovery.transport import TraceReply


@dataclass
class FakeTransport:
    # dst -> alive?
    icmp_alive: dict[str, bool] = field(default_factory=dict)
    # (dst, port) -> state ; or dst -> state for any port
    tcp_state: dict[str, str] = field(default_factory=dict)
    # dst -> ordered list of (hop_ip_or_None, reached)
    traces: dict[str, list[tuple[str | None, bool]]] = field(default_factory=dict)
    sent: list[tuple[str, str]] = field(default_factory=list)  # (kind, dst)

    async def icmp_echo(self, dst: str, timeout: float) -> bool:
        self.sent.append(("icmp", dst))
        return self.icmp_alive.get(dst, False)

    async def tcp_connect(self, dst: str, port: int, timeout: float) -> str:
        self.sent.append(("tcp", dst))
        return self.tcp_state.get(dst, "filtered")

    async def udp_trace(
        self, dst: str, max_ttl: int, max_silent: int, timeout: float
    ) -> list[TraceReply]:
        self.sent.append(("trace", dst))
        replies = []
        for ttl, (hop, reached) in enumerate(self.traces.get(dst, []), start=1):
            replies.append(TraceReply(ttl, hop, reached))
            if reached:
                break
        return replies
