"""Probe transport: the OS-level send/receive behind each probe.

Separating this interface from the probe logic keeps the probes pure and lets tests run the whole
discovery pipeline without touching the network. See design §8.4.

v1 uses only unprivileged Linux mechanisms:
  - ICMP echo via a SOCK_DGRAM/IPPROTO_ICMP "ping" socket
  - TCP liveness via a normal non-blocking connect()
  - UDP traceroute via a UDP socket with IP_TTL set per probe, reading ICMP errors from IP_RECVERR
A privileged helper (raw SYN, Paris traceroute, ARP) is v2.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import struct
from dataclasses import dataclass
from typing import Protocol

IP_RECVERR = 11  # Linux: not exposed by the socket module on all versions


@dataclass(frozen=True)
class TraceReply:
    ttl: int
    hop: str | None  # router that answered, or None if the hop was silent
    reached: bool  # the probe reached the destination (port-unreachable from the target)


class ProbeTransport(Protocol):
    async def icmp_echo(self, dst: str, timeout: float) -> bool: ...
    async def tcp_connect(self, dst: str, port: int, timeout: float) -> str: ...
    async def udp_trace(
        self, dst: str, max_ttl: int, max_silent: int, timeout: float
    ) -> list[TraceReply]: ...


class UnsupportedTransport(Exception):
    """The OS does not offer the unprivileged mechanism this probe needs."""


class SocketTransport:
    """Real Linux implementation. Each probe runs on its own short-lived socket."""

    base_port = 33434

    async def icmp_echo(self, dst: str, timeout: float) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except PermissionError as exc:
            raise UnsupportedTransport(
                "ICMP ping sockets not permitted; see `netgrapher doctor`"
            ) from exc
        ident = socket.ntohs(sock.getsockname()[1]) if sock.getsockname()[1] else 0
        packet = _icmp_echo_packet(ident or 1, 1)
        loop = asyncio.get_running_loop()
        with sock:
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, packet, (dst, 0))
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout)
            except (TimeoutError, OSError):
                return False
            return len(data) >= 1 and data[0] == 0  # echo reply

    async def tcp_connect(self, dst: str, port: int, timeout: float) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        loop = asyncio.get_running_loop()
        with sock:
            sock.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(sock, (dst, port)), timeout)
                return "open"
            except TimeoutError:
                return "filtered"
            except ConnectionRefusedError:
                return "closed"
            except OSError:
                return "filtered"

    async def udp_trace(
        self, dst: str, max_ttl: int, max_silent: int, timeout: float
    ) -> list[TraceReply]:
        loop = asyncio.get_running_loop()
        replies: list[TraceReply] = []
        silent = 0
        for ttl in range(1, max_ttl + 1):
            reply = await self._trace_hop(loop, dst, ttl, self.base_port + ttl, timeout)
            replies.append(reply)
            if reply.reached:
                break
            silent = silent + 1 if reply.hop is None else 0
            if silent >= max_silent:
                break
        return replies

    async def _trace_hop(
        self, loop: asyncio.AbstractEventLoop, dst: str, ttl: int, port: int, timeout: float
    ) -> TraceReply:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, b"netgrapher", (dst, port))
            except OSError:
                return TraceReply(ttl, None, False)
            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return TraceReply(ttl, None, False)
                try:
                    await asyncio.wait_for(_wait_readable_err(loop, sock), remaining)
                except TimeoutError:
                    return TraceReply(ttl, None, False)
                hop = _read_icmp_error(sock)
                if hop is not None:
                    return TraceReply(ttl, hop.hop, hop.reached)


def _icmp_echo_packet(ident: int, seq: int) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq)
    payload = b"netgrapher"
    checksum = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, ident & 0xFFFF, seq) + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return int(~total) & 0xFFFF


async def _wait_readable_err(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> None:
    future: asyncio.Future[None] = loop.create_future()

    def ready() -> None:
        if not future.done():
            future.set_result(None)

    fd = sock.fileno()
    loop.add_reader(fd, ready)
    try:
        await future
    finally:
        loop.remove_reader(fd)


def _read_icmp_error(sock: socket.socket) -> TraceReply | None:
    """Read one queued ICMP error via MSG_ERRQUEUE and return its source address."""
    try:
        _, ancdata, _, _ = sock.recvmsg(512, 512, socket.MSG_ERRQUEUE)
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return None
        return None
    for level, typ, data in ancdata:
        if level == socket.IPPROTO_IP and typ == IP_RECVERR:
            return _parse_sock_extended_err(data)
    return None


def _parse_sock_extended_err(data: bytes) -> TraceReply | None:
    # struct sock_extended_err (16 bytes) followed by struct sockaddr_in of the offender.
    if len(data) < 16:
        return None
    # struct sock_extended_err: __u32 ee_errno; __u8 ee_origin, ee_type, ee_code, ee_pad; ...
    SO_EE_ORIGIN_ICMP = 2
    origin, icmp_type = data[4], data[5]
    if origin != SO_EE_ORIGIN_ICMP:
        return None
    offender = data[16:]
    if len(offender) < 8:
        return None
    hop = socket.inet_ntoa(offender[4:8])
    reached = icmp_type == 3  # destination unreachable (port unreachable at the target)
    return TraceReply(0, hop, reached)
