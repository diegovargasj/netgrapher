import io
import struct
from pathlib import Path

import dpkt
import pytest
from synthetic import pcapng_bytes

from netgrapher.capture.source import CaptureFormatError, CaptureReader, FileSource


def test_classic_pcap(tmp_path: Path) -> None:
    path = tmp_path / "a.pcap"
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        w.writepkt(b"abc", ts=10.5)
        w.writepkt(b"defg", ts=11.25)
    src = FileSource(path)
    pkts = list(src)
    assert [(p.frame, p.ts, p.data, p.linktype) for p in pkts] == [
        (1, 10.5, b"abc", 1),
        (2, 11.25, b"defg", 1),
    ]
    assert src.stats.packets == 2


def test_classic_pcap_big_endian_nanoseconds() -> None:
    header = struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 101)
    record = struct.pack(">IIII", 5, 500_000_000, 2, 2) + b"\x45\x00"
    pkts = list(CaptureReader(io.BytesIO(header + record)))
    assert pkts[0].ts == 5.5
    assert pkts[0].linktype == 101


def test_truncated_pcap_tail() -> None:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, 10, 10) + b"short"
    reader = CaptureReader(io.BytesIO(header + record))
    assert list(reader) == []
    assert reader.stats.truncated_tail


def test_pcapng_multiple_interfaces_and_drop_stats() -> None:
    data = pcapng_bytes([1, 101], [(0, 1.0, b"eth"), (1, 2.5, b"rawip")], drops={0: 7})
    reader = CaptureReader(io.BytesIO(data))
    pkts = list(reader)
    assert [(p.iface, p.linktype, p.ts, p.data) for p in pkts] == [
        (0, 1, 1.0, b"eth"),
        (1, 101, 2.5, b"rawip"),
    ]
    assert reader.format == "pcapng"
    assert reader.stats.if_dropped == {0: 7}


def test_not_a_capture() -> None:
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(b"hello world, not a pcap")))
