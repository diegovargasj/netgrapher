"""Environment checks with fix-it hints (NFR-14)."""

from __future__ import annotations

import grp
import os
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from netgrapher.capture.hostinfo import HostConfig, read_host_config
from netgrapher.capture.live import DUMPCAP_ENV, find_dumpcap

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13
_VFS_CAP_REVISION_MASK = 0xFF000000


class Level(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class Check:
    level: Level
    message: str
    fix: str | None = None


def permitted_capabilities(xattr: bytes) -> set[int]:
    """Decode the permitted set of a security.capability extended attribute."""
    if len(xattr) < 12:
        return set()
    magic, permitted_lo = struct.unpack_from("<II", xattr)
    if not magic & _VFS_CAP_REVISION_MASK:
        return set()
    permitted = permitted_lo
    if len(xattr) >= 20:
        permitted |= struct.unpack_from("<I", xattr, 12)[0] << 32
    return {bit for bit in range(64) if permitted >> bit & 1}


def check_dumpcap(path: str | None = None, *, euid: int | None = None) -> list[Check]:
    path = path or find_dumpcap()
    if path is None:
        return [
            Check(
                Level.FAIL,
                "dumpcap not found (needed for live capture)",
                "sudo apt install wireshark-common   # or set " + DUMPCAP_ENV,
            )
        ]
    if not os.path.isfile(path):
        return [Check(Level.FAIL, f"dumpcap not found at {path}", f"check {DUMPCAP_ENV} or PATH")]
    checks = [Check(Level.OK, f"dumpcap found: {path}")]
    if not os.access(path, os.X_OK):
        checks.append(
            Check(
                Level.FAIL,
                "you are not allowed to run dumpcap",
                'sudo usermod -aG wireshark "$USER"   # then log out and back in',
            )
        )
        return checks
    if (euid if euid is not None else os.geteuid()) == 0:
        checks.append(Check(Level.WARN, "running as root; netgrapher does not need root"))
        return checks
    try:
        caps = permitted_capabilities(os.getxattr(path, "security.capability"))
    except OSError:
        caps = set()
    if {CAP_NET_RAW, CAP_NET_ADMIN} <= caps:
        checks.append(Check(Level.OK, "dumpcap has cap_net_raw and cap_net_admin"))
    else:
        checks.append(
            Check(
                Level.FAIL,
                "dumpcap lacks capture capabilities",
                "sudo dpkg-reconfigure wireshark-common   # answer Yes; or: "
                f"sudo setcap cap_net_raw,cap_net_admin=eip {path}",
            )
        )
    return checks


def check_interfaces(config: HostConfig) -> list[Check]:
    checks = [Check(Level.WARN, w) for w in config.warnings]
    usable = [i for i in config.interfaces if i.up and not i.loopback]
    if not usable:
        checks.append(Check(Level.FAIL, "no network interface is up"))
    else:
        names = ", ".join(i.name for i in usable)
        checks.append(Check(Level.OK, f"interfaces up: {names}"))
    default = config.default_interface()
    if default:
        checks.append(Check(Level.OK, f"default capture interface: {default}"))
    else:
        checks.append(Check(Level.WARN, "no default route; pass -i to choose an interface"))
    return checks


def check_ping_sockets(
    range_text: str | None = None, groups: list[int] | None = None
) -> list[Check]:
    """Unprivileged ICMP echo (used by the probing modes, milestone 0.5)."""
    if range_text is None:
        try:
            range_text = Path("/proc/sys/net/ipv4/ping_group_range").read_text()
        except OSError:
            return [Check(Level.WARN, "cannot read net.ipv4.ping_group_range")]
    low, high = (int(x) for x in range_text.split())
    gids = groups if groups is not None else [os.getgid(), *os.getgroups()]
    if any(low <= g <= high for g in gids):
        return [Check(Level.OK, "unprivileged ICMP (ping sockets) allowed")]
    group = grp.getgrgid(os.getgid()).gr_name if groups is None else "your group"
    return [
        Check(
            Level.WARN,
            f"ping sockets not allowed for {group} (only needed for active/reactive modes)",
            'sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"',
        )
    ]


def run_checks(host_config: Callable[[], HostConfig] = read_host_config) -> list[Check]:
    if not sys.platform.startswith("linux"):
        return [Check(Level.FAIL, f"{sys.platform} is not supported yet (Linux only)")]
    return [*check_dumpcap(), *check_interfaces(host_config()), *check_ping_sockets()]
