"""Optional flow overlay: aggregated host-to-host communication (FR-GR-7)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from netgrapher.decode.packet import DecodedPacket
from netgrapher.net import is_usable_unicast

MAX_SAVED_FLOWS = 10_000


@dataclass(slots=True)
class Flow:
    packets: int
    bytes: int
    first_seen: float
    last_seen: float


class FlowTable:
    def __init__(self) -> None:
        self._flows: dict[tuple[str, str, int], Flow] = {}

    def add(self, pkt: DecodedPacket) -> None:
        src, dst = pkt.ip_src, pkt.ip_dst
        if src is None or dst is None or not is_usable_unicast(src) or not is_usable_unicast(dst):
            return
        key = (src, dst, pkt.proto)
        flow = self._flows.get(key)
        if flow is None:
            self._flows[key] = Flow(1, pkt.ip_len, pkt.ts, pkt.ts)
        else:
            flow.packets += 1
            flow.bytes += pkt.ip_len
            flow.last_seen = max(flow.last_seen, pkt.ts)

    def to_list(self, limit: int = MAX_SAVED_FLOWS) -> list[dict[str, Any]]:
        top = sorted(self._flows.items(), key=lambda kv: (-kv[1].bytes, kv[0]))[:limit]
        return [
            {
                "src": src,
                "dst": dst,
                "proto": proto,
                "packets": f.packets,
                "bytes": f.bytes,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
            }
            for (src, dst, proto), f in top
        ]
