"""Ingestion: raw packets -> decoded packets -> facts (and flows)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from netgrapher.capture.source import RawPacket
from netgrapher.decode.decoder import DecodeError, UnsupportedLinktype, decode
from netgrapher.extract import EXTRACTORS
from netgrapher.facts.store import FactStore
from netgrapher.flows import FlowTable


@dataclass
class IngestStats:
    packets: int = 0
    malformed: int = 0
    unsupported_linktype: int = 0
    ipv4: int = 0
    ipv6_skipped: int = 0
    extractor_errors: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    linktypes: set[int] = field(default_factory=set)
    protocols: Counter[str] = field(default_factory=Counter)


def ingest(
    packets: Iterable[RawPacket],
    store: FactStore,
    run_id: str,
    *,
    flows: FlowTable | None = None,
    stats: IngestStats | None = None,
) -> IngestStats:
    stats = stats or IngestStats()
    for raw in packets:
        stats.packets += 1
        stats.linktypes.add(raw.linktype)
        if raw.ts:
            stats.first_ts = raw.ts if stats.first_ts is None else min(stats.first_ts, raw.ts)
            stats.last_ts = raw.ts if stats.last_ts is None else max(stats.last_ts, raw.ts)
        try:
            pkt = decode(raw)
        except UnsupportedLinktype:
            stats.unsupported_linktype += 1
            continue
        except DecodeError:
            stats.malformed += 1
            continue
        if pkt.is_ipv6:
            stats.ipv6_skipped += 1
            continue
        if pkt.ip_src is not None:
            stats.ipv4 += 1
            if flows is not None:
                flows.add(pkt)
        for name, extractor in EXTRACTORS:
            produced = False
            try:
                for obs in extractor(pkt):
                    store.add(obs, ts=pkt.ts, frame=pkt.frame, run_id=run_id)
                    produced = True
            except Exception:  # untrusted input must never stop ingestion (FR-IN-11)
                stats.extractor_errors += 1
            if produced:
                stats.protocols[name] += 1
    return stats
