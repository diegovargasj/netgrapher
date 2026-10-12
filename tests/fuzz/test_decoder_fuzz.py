"""Untrusted packets must never crash decoding or extraction (NFR-6)."""

from hypothesis import given, settings
from hypothesis import strategies as st
from synthetic import eth, udp

from netgrapher.capture.source import RawPacket
from netgrapher.decode.decoder import SUPPORTED_LINKTYPES
from netgrapher.facts.store import FactStore
from netgrapher.pipeline import ingest

# Seeds that reach the application parsers, so mutations exercise them too.
_SEEDS = [
    eth(
        "02:00:00:00:00:01", "02:00:00:00:00:02", udp("10.0.0.1", "10.0.0.2", 67, 68, b"\x02" * 300)
    ),
    eth(
        "02:00:00:00:00:01", "02:00:00:00:00:02", udp("10.0.0.1", "10.0.0.2", 53, 999, b"\x00" * 40)
    ),
]


@st.composite
def mutated(draw: st.DrawFn) -> bytes:
    data = bytearray(draw(st.sampled_from(_SEEDS)))
    for _ in range(draw(st.integers(0, 8))):
        data[draw(st.integers(0, len(data) - 1))] = draw(st.integers(0, 255))
    return bytes(data[: draw(st.integers(0, len(data)))])


@settings(max_examples=300, deadline=None)
@given(
    data=st.one_of(st.binary(max_size=200), mutated()),
    linktype=st.sampled_from(sorted(SUPPORTED_LINKTYPES)),
)
def test_ingest_never_raises(data: bytes, linktype: int) -> None:
    stats = ingest([RawPacket(1, 0.0, 0, linktype, data, len(data))], FactStore(), "r1")
    assert stats.packets == 1
