"""Discovery modes and default settings. Values come from the design document (§8, §9, §12)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum


class Mode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    REACTIVE = "reactive"


# Default reactive scope (FR-DM-7); the capture host's local subnets are added at runtime.
DEFAULT_REACTIVE_SCOPE: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
)

# Largest IPv4 active-mode CIDR accepted without --force-large (FR-DM-13).
MAX_ACTIVE_PREFIXLEN_V4 = 16
# Largest prefix the reactive planner sweeps; larger ones get a traceroute only (§8.3).
MAX_REACTIVE_SWEEP_PREFIXLEN_V4 = 22


@dataclass(frozen=True)
class CaptureConfig:
    interfaces: tuple[str, ...] = ()
    snaplen: int = 512
    buffer_mib: int = 64
    promiscuous: bool = True
    bpf_filter: str | None = None


@dataclass(frozen=True)
class ProbeConfig:
    rate_pps: float = 50.0
    rate_per_host_pps: float = 5.0
    max_in_flight: int = 256
    budget: int = 10_000
    max_generation: int = 2
    icmp_timeout_s: float = 2.0
    tcp_timeout_s: float = 1.0
    tcp_liveness_ports: tuple[int, ...] = (443, 80, 22, 445, 3389)
    trace_max_ttl: int = 30
    trace_max_silent_hops: int = 3
    grace_period_s: float = 10.0


@dataclass(frozen=True)
class ScopeConfig:
    allow: tuple[str, ...] = DEFAULT_REACTIVE_SCOPE
    deny: tuple[str, ...] = ()
    allow_public: bool = False


@dataclass(frozen=True)
class DiscoveryConfig:
    mode: Mode = Mode.PASSIVE
    cidrs: tuple[str, ...] = ()
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    probes: ProbeConfig = field(default_factory=ProbeConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    force_large: bool = False
    dry_run: bool = False

    def validate(self) -> None:
        """Check mode/option combinations (FR-DM-4, FR-DM-13). Raises ValueError."""
        if self.mode is Mode.ACTIVE and not self.cidrs:
            raise ValueError("active mode requires at least one --cidr")
        if self.mode is not Mode.ACTIVE and self.cidrs:
            raise ValueError("--cidr is only valid with --mode active")
        for cidr in self.cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            if (
                net.version == 4
                and net.prefixlen < MAX_ACTIVE_PREFIXLEN_V4
                and not self.force_large
            ):
                raise ValueError(
                    f"{cidr} is larger than /{MAX_ACTIVE_PREFIXLEN_V4}; "
                    "pass --force-large to allow it"
                )


_DURATION = re.compile(r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?")


def parse_duration(text: str) -> float:
    """Seconds from "90", "45s", "30m", "1h30m". Raises ValueError."""
    text = text.strip().lower()
    try:
        value = float(text)
    except ValueError:
        match = _DURATION.fullmatch(text)
        if not text or match is None or not any(match.groups()):
            raise ValueError(
                f"invalid duration: {text!r} (examples: 90, 45s, 30m, 1h30m)"
            ) from None
        h, m, s = (float(g) if g else 0.0 for g in match.groups())
        value = h * 3600 + m * 60 + s
    if value <= 0:
        raise ValueError(f"duration must be positive: {text!r}")
    return value
