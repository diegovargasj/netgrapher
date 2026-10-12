"""Ingestion: raw packets -> decoded packets -> facts (and flows)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from netgrapher.capture.source import RawPacket
from netgrapher.decode.decoder import DecodeError, UnsupportedLinktype, decode
from netgrapher.decode.packet import DecodedPacket
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
    tunneled: int = 0
    extractor_errors: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    linktypes: set[int] = field(default_factory=set)
    protocols: Counter[str] = field(default_factory=Counter)


class Ingestor:
    """Feeds packets one at a time into a fact store."""

    def __init__(self, store: FactStore, run_id: str, *, flows: FlowTable | None = None) -> None:
        self.store = store
        self.run_id = run_id
        self.flows = flows
        self.stats = IngestStats()

    def add(self, raw: RawPacket) -> None:
        stats = self.stats
        stats.packets += 1
        stats.linktypes.add(raw.linktype)
        if raw.ts:
            stats.first_ts = raw.ts if stats.first_ts is None else min(stats.first_ts, raw.ts)
            stats.last_ts = raw.ts if stats.last_ts is None else max(stats.last_ts, raw.ts)
        try:
            pkt: DecodedPacket | None = decode(raw)
        except UnsupportedLinktype:
            stats.unsupported_linktype += 1
            return
        except DecodeError:
            stats.malformed += 1
            return
        while pkt is not None:
            self._extract(pkt)
            pkt = pkt.inner
            if pkt is not None:
                stats.tunneled += 1

    def _extract(self, pkt: DecodedPacket) -> None:
        stats = self.stats
        if pkt.is_ipv6:
            stats.ipv6_skipped += 1
            return
        if pkt.ip_src is not None:
            stats.ipv4 += 1
            if self.flows is not None:
                self.flows.add(pkt)
        for name, extractor in EXTRACTORS:
            produced = False
            try:
                for obs in extractor(pkt):
                    self.store.add(obs, ts=pkt.ts, frame=pkt.frame, run_id=self.run_id)
                    produced = True
            except Exception:  # untrusted input must never stop ingestion (FR-IN-11)
                stats.extractor_errors += 1
            if produced:
                stats.protocols[name] += 1


def ingest(
    packets: Iterable[RawPacket],
    store: FactStore,
    run_id: str,
    *,
    flows: FlowTable | None = None,
) -> IngestStats:
    ingestor = Ingestor(store, run_id, flows=flows)
    for raw in packets:
        ingestor.add(raw)
    return ingestor.stats
