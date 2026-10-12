"""Packet sources. See design §5.2 and §9.1.

The pcap and pcapng readers are implemented here rather than taken from dpkt: dpkt's pcapng
reader only handles one interface, ignores interface statistics and needs a seekable file,
while live capture (milestone 0.2) streams multi-interface pcapng from dumpcap through a pipe.
Both readers only read forward, so they work on pipes as well as files.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D

_BT_IDB = 0x00000001
_BT_PB = 0x00000002
_BT_SPB = 0x00000003
_BT_ISB = 0x00000005
_BT_EPB = 0x00000006

_OPT_END = 0
_IF_NAME = 2
_IF_TSRESOL = 9
_IF_TSOFFSET = 14
_ISB_IFRECV = 4
_ISB_IFDROP = 5
_ISB_OSDROP = 7

_MAX_BLOCK = 64 * 1024 * 1024


class Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


class CaptureFormatError(Exception):
    """The input is not a supported capture file."""


@dataclass(frozen=True, slots=True)
class RawPacket:
    frame: int  # 1-based, like Wireshark
    ts: float
    iface: int
    linktype: int
    data: bytes
    orig_len: int


@dataclass
class InterfaceInfo:
    linktype: int
    snaplen: int
    name: str | None = None
    ts_units_per_s: float = 1e6
    ts_offset: int = 0


@dataclass
class CaptureStats:
    packets: int = 0
    truncated_tail: bool = False
    if_received: dict[int, int] = field(default_factory=dict)
    if_dropped: dict[int, int] = field(default_factory=dict)
    os_dropped: dict[int, int] = field(default_factory=dict)


def _read_exact(stream: Readable, n: int) -> bytes | None:
    """Read exactly n bytes; None on clean EOF; raises EOFError on a partial read."""
    buf = stream.read(n)
    if not buf:
        return None
    while len(buf) < n:
        more = stream.read(n - len(buf))
        if not more:
            raise EOFError
        buf += more
    return buf


class CaptureReader:
    """Reads classic pcap or pcapng from a forward-only binary stream."""

    def __init__(self, stream: Readable) -> None:
        self._stream = stream
        self.interfaces: list[InterfaceInfo] = []
        self.stats = CaptureStats()
        self.format: str | None = None

    def __iter__(self) -> Iterator[RawPacket]:
        head = _read_exact(self._stream, 4)
        if head is None:
            raise CaptureFormatError("empty input")
        if struct.unpack("<I", head)[0] == PCAPNG_SHB:
            self.format = "pcapng"
            yield from self._read_pcapng(head)
            return
        for endian in ("<", ">"):
            magic = struct.unpack(endian + "I", head)[0]
            if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                self.format = "pcap"
                yield from self._read_pcap(endian, 1e9 if magic == PCAP_MAGIC_NS else 1e6)
                return
        raise CaptureFormatError("not a pcap or pcapng file")

    def _next_frame(self) -> int:
        self.stats.packets += 1
        return self.stats.packets

    # -- classic pcap -------------------------------------------------------------------------

    def _read_pcap(self, endian: str, units: float) -> Iterator[RawPacket]:
        try:
            header = _read_exact(self._stream, 20)
        except EOFError:
            header = None
        if header is None:
            raise CaptureFormatError("truncated pcap header")
        _, _, _, _, snaplen, network = struct.unpack(endian + "HHiIII", header)
        self.interfaces.append(InterfaceInfo(network & 0xFFFF, snaplen, ts_units_per_s=units))
        record = struct.Struct(endian + "IIII")
        while True:
            try:
                rec = _read_exact(self._stream, 16)
                if rec is None:
                    return
                ts_sec, ts_frac, incl_len, orig_len = record.unpack(rec)
                if incl_len > _MAX_BLOCK:
                    raise EOFError
                data = _read_exact(self._stream, incl_len) if incl_len else b""
                if data is None:
                    raise EOFError
            except EOFError:
                self.stats.truncated_tail = True
                return
            yield RawPacket(
                self._next_frame(),
                ts_sec + ts_frac / units,
                0,
                self.interfaces[0].linktype,
                data,
                orig_len,
            )

    # -- pcapng -------------------------------------------------------------------------------

    def _read_pcapng(self, first_type: bytes) -> Iterator[RawPacket]:
        endian = "<"
        pending: bytes | None = first_type
        while True:
            try:
                if pending is not None:
                    btype_raw, pending = pending, None
                else:
                    raw = _read_exact(self._stream, 4)
                    if raw is None:
                        return
                    btype_raw = raw
                length_raw = _read_exact(self._stream, 4)
                if length_raw is None:
                    raise EOFError
                if struct.unpack("<I", btype_raw)[0] == PCAPNG_SHB:
                    # A new section: the byte-order magic decides the endianness.
                    bom = _read_exact(self._stream, 4)
                    if bom is None:
                        raise EOFError
                    endian = "<" if struct.unpack("<I", bom)[0] == PCAPNG_BOM else ">"
                    if struct.unpack(endian + "I", bom)[0] != PCAPNG_BOM:
                        raise CaptureFormatError("bad pcapng byte-order magic")
                    length = struct.unpack(endian + "I", length_raw)[0]
                    self._check_length(length, 28)
                    if _read_exact(self._stream, length - 12) is None:
                        raise EOFError
                    self.interfaces = []  # interface IDs are per section
                    continue
                btype = struct.unpack(endian + "I", btype_raw)[0]
                length = struct.unpack(endian + "I", length_raw)[0]
                self._check_length(length, 12)
                body = _read_exact(self._stream, length - 8)
                if body is None:
                    raise EOFError
            except EOFError:
                self.stats.truncated_tail = True
                return
            body = body[:-4]  # trailing block length
            packet = self._handle_block(endian, btype, body)
            if packet is not None:
                yield packet

    @staticmethod
    def _check_length(length: int, minimum: int) -> None:
        if length < minimum or length % 4 or length > _MAX_BLOCK:
            raise CaptureFormatError(f"invalid pcapng block length {length}")

    def _handle_block(self, endian: str, btype: int, body: bytes) -> RawPacket | None:
        try:
            if btype == _BT_IDB:
                self._parse_idb(endian, body)
            elif btype == _BT_EPB:
                iface, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body)
                return self._packet(iface, (ts_hi << 32) | ts_lo, body[20 : 20 + cap_len], orig_len)
            elif btype == _BT_PB:
                iface, _, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(
                    endian + "HHIIII", body
                )
                return self._packet(iface, (ts_hi << 32) | ts_lo, body[20 : 20 + cap_len], orig_len)
            elif btype == _BT_SPB:
                (orig_len,) = struct.unpack_from(endian + "I", body)
                snaplen = self.interfaces[0].snaplen if self.interfaces else 0
                cap_len = min(orig_len, snaplen) if snaplen else orig_len
                return self._packet(0, None, body[4 : 4 + cap_len], orig_len)
            elif btype == _BT_ISB:
                self._parse_isb(endian, body)
        except (struct.error, IndexError):
            pass  # a malformed block is skipped
        return None

    def _packet(self, iface: int, ts_units: int | None, data: bytes, orig_len: int) -> RawPacket:
        info = self.interfaces[iface]
        ts = 0.0 if ts_units is None else info.ts_offset + ts_units / info.ts_units_per_s
        return RawPacket(self._next_frame(), ts, iface, info.linktype, data, orig_len)

    def _parse_idb(self, endian: str, body: bytes) -> None:
        linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
        info = InterfaceInfo(linktype, snaplen)
        for code, value in _options(endian, body[8:]):
            if code == _IF_NAME:
                info.name = value.rstrip(b"\x00").decode("utf-8", "replace")
            elif code == _IF_TSRESOL and value:
                resol = value[0]
                base = 2 if resol & 0x80 else 10
                info.ts_units_per_s = float(base ** (resol & 0x7F))
            elif code == _IF_TSOFFSET and len(value) >= 8:
                info.ts_offset = struct.unpack(endian + "q", value[:8])[0]
        self.interfaces.append(info)

    def _parse_isb(self, endian: str, body: bytes) -> None:
        (iface,) = struct.unpack_from(endian + "I", body)
        targets = {
            _ISB_IFRECV: self.stats.if_received,
            _ISB_IFDROP: self.stats.if_dropped,
            _ISB_OSDROP: self.stats.os_dropped,
        }
        for code, value in _options(endian, body[12:]):
            if code in targets and len(value) >= 8:
                targets[code][iface] = struct.unpack(endian + "Q", value[:8])[0]


def _options(endian: str, buf: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, offset)
        if code == _OPT_END:
            return
        offset += 4
        yield code, buf[offset : offset + length]
        offset += (length + 3) & ~3


class FileSource:
    """Packets from a pcap or pcapng file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._reader: CaptureReader | None = None
        self._stream: BinaryIO | None = None

    def __iter__(self) -> Iterator[RawPacket]:
        with self.path.open("rb") as stream:
            self._stream = stream
            self._reader = CaptureReader(stream)
            yield from self._reader

    def progress(self) -> float | None:
        """Fraction of the file read so far, if known."""
        if self._stream is None or self._stream.closed:
            return None
        size = self.path.stat().st_size
        return self._stream.tell() / size if size else None

    @property
    def stats(self) -> CaptureStats:
        return self._reader.stats if self._reader else CaptureStats()

    @property
    def interfaces(self) -> list[InterfaceInfo]:
        return self._reader.interfaces if self._reader else []
