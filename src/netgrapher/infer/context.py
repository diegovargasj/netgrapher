"""Indexes over the fact store and state shared by the inference stages."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netgrapher.facts.model import MAX_FRAMES, Fact, FactKind
from netgrapher.facts.store import FactStore
from netgrapher.graph.model import Evidence, Graph, Link
from netgrapher.infer.confidence import noisy_or
from netgrapher.infer.weights import WEIGHTS
from netgrapher.net import ip_sort_key, is_external, is_ipv4, is_usable_unicast

_INITIAL_TTLS = ((64, "unix-like"), (128, "windows"), (255, "network-device"))

Vlan = int | None


def vlan_key(vlan: Vlan) -> tuple[bool, int]:
    return (vlan is not None, vlan or 0)


@dataclass
class SubnetInfo:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    kind: str  # "local" | "remote"
    evidence: list[str]
    confidence: float


@dataclass
class Context:
    store: FactStore
    graph: Graph = field(default_factory=Graph)

    # Indexes (built in __post_init__)
    seen: dict[str, dict[str, Fact]] = field(default_factory=dict)  # ip -> dir -> fact
    arp: dict[str, dict[str, list[Fact]]] = field(default_factory=dict)  # ip -> mac -> facts
    arp_ips_by_mac: dict[str, set[str]] = field(default_factory=dict)
    ip_mac: dict[str, dict[str, list[Fact]]] = field(default_factory=dict)  # ip -> mac -> facts
    ips_by_mac: dict[str, set[str]] = field(default_factory=dict)
    vlans_by_mac: dict[str, set[Vlan]] = field(default_factory=dict)
    ttls: dict[str, list[Fact]] = field(default_factory=dict)
    traces: dict[str, list[Fact]] = field(default_factory=dict)
    trace_hops: set[str] = field(default_factory=set)
    alive: set[str] = field(default_factory=set)
    all_ips: set[str] = field(default_factory=set)

    # Stage results
    router_macs: dict[str, set[str]] = field(default_factory=dict)  # mac -> carried IPs
    onlink: dict[str, Vlan] = field(default_factory=dict)  # on-link IP -> segment
    subnets: dict[str, SubnetInfo] = field(default_factory=dict)
    subnet_of: dict[str, str] = field(default_factory=dict)  # ip -> subnet id
    router_ips: set[str] = field(default_factory=set)  # interface IPs, including virtual
    router_of_mac: dict[str, str] = field(default_factory=dict)  # mac -> router entity id
    router_of_ip: dict[str, str] = field(default_factory=dict)  # interface ip -> router id
    gateway_ips: set[str] = field(default_factory=set)  # default gateways (DHCP, host routes)
    self_ips: dict[str, list[Fact]] = field(default_factory=dict)  # capture host's addresses

    _names: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    _roles: dict[str, set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        seen: defaultdict[str, dict[str, Fact]] = defaultdict(dict)
        for f in self.store.by_kind(FactKind.IP_SEEN):
            seen[f.subject][f.get("dir")] = f
        self.seen = dict(seen)

        arp: defaultdict[str, defaultdict[str, list[Fact]]] = defaultdict(lambda: defaultdict(list))
        arp_by_mac: defaultdict[str, set[str]] = defaultdict(set)
        vlans: defaultdict[str, set[Vlan]] = defaultdict(set)
        for f in self.store.by_kind(FactKind.ARP_BINDING):
            arp[f.subject][f.get("mac")].append(f)
            arp_by_mac[f.get("mac")].add(f.subject)
            vlans[f.get("mac")].add(f.get("vlan"))
        self.arp = {ip: dict(m) for ip, m in arp.items()}
        self.arp_ips_by_mac = dict(arp_by_mac)

        ip_mac: defaultdict[str, defaultdict[str, list[Fact]]] = defaultdict(
            lambda: defaultdict(list)
        )
        by_mac: defaultdict[str, set[str]] = defaultdict(set)
        for f in self.store.by_kind(FactKind.IP_MAC):
            ip_mac[f.subject][f.get("mac")].append(f)
            by_mac[f.get("mac")].add(f.subject)
            vlans[f.get("mac")].add(f.get("vlan"))
        self.ip_mac = {ip: dict(m) for ip, m in ip_mac.items()}
        self.ips_by_mac = dict(by_mac)
        self.vlans_by_mac = dict(vlans)

        ttls: defaultdict[str, list[Fact]] = defaultdict(list)
        for f in self.store.by_kind(FactKind.TTL_OBSERVED):
            ttls[f.subject].append(f)
        self.ttls = dict(ttls)

        traces: defaultdict[str, list[Fact]] = defaultdict(list)  # target -> hop facts
        for f in self.store.by_kind(FactKind.TRACE_HOP):
            traces[f.get("target")].append(f)
        self.traces = {t: sorted(hs, key=lambda f: f.get("ttl")) for t, hs in traces.items()}
        self.trace_hops = {f.subject for f in self.store.by_kind(FactKind.TRACE_HOP)}
        self.alive = {f.subject for f in self.store.by_kind(FactKind.PROBE_ALIVE)}

        self_ips: defaultdict[str, list[Fact]] = defaultdict(list)
        for f in self.store.by_kind(FactKind.HOST_ADDRESS):
            self_ips[f.subject].append(f)
        self.self_ips = dict(self_ips)

        # IPv6 inference is v2: addresses from host configuration (e.g. an IPv6 resolver)
        # must not leak into the IPv4 rules.
        self.all_ips = {
            ip for ip in self._referenced_ips() if is_ipv4(ip) and is_usable_unicast(ip)
        }
        self._index_names_and_roles()

    def _referenced_ips(self) -> Iterable[str]:
        yield from self.seen
        yield from self.arp
        yield from self.self_ips
        for f in self.store.by_kind(FactKind.HOST_ROUTE):
            if f.get("gateway"):
                yield f.get("gateway")
        for f in self.store.by_kind(FactKind.DHCP_LEASE):
            yield f.subject
            yield from f.get("routers", ())
            yield from f.get("dns", ())
            if f.get("server"):
                yield f.get("server")
        for kind in (
            FactKind.ICMP_TIME_EXCEEDED,
            FactKind.ICMP_UNREACHABLE,
            FactKind.ROUTING_SPEAKER,
            FactKind.SERVICE,
            FactKind.SUBNET_HINT,
            FactKind.HOST_RESOLVER,
        ):
            for f in self.store.by_kind(kind):
                yield f.subject
        for f in self.store.by_kind(FactKind.ICMP_REDIRECT):
            yield f.subject
            yield f.get("gateway")
        for f in self.store.by_kind(FactKind.TRACE_HOP):
            yield f.subject
            yield f.get("target")
        for f in self.store.by_kind(FactKind.PROBE_ALIVE):
            yield f.subject
        for f in self.store.by_kind(FactKind.REDUNDANCY_SPEAKER):
            yield f.subject
            yield from f.get("vips", ())

    # -- queries ------------------------------------------------------------------------------

    def sorted_ips(self, ips: Iterable[str]) -> list[str]:
        return sorted(ips, key=ip_sort_key)

    def internal_ips(self) -> list[str]:
        return self.sorted_ips(ip for ip in self.all_ips if not is_external(ip))

    def external_ips(self) -> list[str]:
        return self.sorted_ips(ip for ip in self.all_ips if is_external(ip))

    def facts_about(self, ip: str) -> list[Fact]:
        facts = list(self.seen.get(ip, {}).values()) + self.self_ips.get(ip, [])
        for mac_facts in self.arp.get(ip, {}).values():
            facts.extend(mac_facts)
        return facts

    def first_seen(self, ip: str) -> float:
        return min((f.first_seen for f in self.facts_about(ip)), default=float("inf"))

    def last_seen(self, ip: str) -> float | None:
        return max((f.last_seen for f in self.facts_about(ip)), default=None)

    def ttl_info(self, ip: str) -> tuple[int | None, str | None, list[Fact]]:
        """Hop distance from the capture point and an OS-family guess, from the highest TTL."""
        facts = self.ttls.get(ip, [])
        if not facts:
            return None, None, []
        max_ttl = max(f.get("ttl") for f in facts)
        for initial, family in _INITIAL_TTLS:
            if max_ttl <= initial:
                return initial - max_ttl, family, facts
        return None, None, facts

    def names(self, ip: str) -> list[dict[str, str]]:
        return [{"name": n, "source": s} for n, s in sorted(self._names.get(ip, ()))]

    def roles(self, ip: str) -> list[str]:
        return sorted(self._roles.get(ip, ()))

    def _index_names_and_roles(self) -> None:
        names: defaultdict[str, set[tuple[str, str]]] = defaultdict(set)
        for f in self.store.by_kind(FactKind.NAME):
            names[f.subject].add((f.get("name"), f.get("source")))
        hostnames = {f.subject: f.get("name") for f in self.store.by_kind(FactKind.DHCP_HOSTNAME)}
        roles: defaultdict[str, set[str]] = defaultdict(set)
        for f in self.store.by_kind(FactKind.SERVICE):
            roles[f.subject].add(f"{f.get('service')}-server")
        for f in self.store.by_kind(FactKind.HOST_RESOLVER):
            roles[f.subject].add("dns-server")
        for lease in self.store.by_kind(FactKind.DHCP_LEASE):
            if lease.get("chaddr") in hostnames:
                names[lease.subject].add((hostnames[lease.get("chaddr")], "dhcp"))
            for dns in lease.get("dns", ()):
                roles[dns].add("dns-server")
        self._names = dict(names)
        self._roles = dict(roles)

    # -- evidence -----------------------------------------------------------------------------

    def evidence(self, rule: str, key: str, facts: Iterable[Fact], summary: str) -> str:
        facts = sorted({f.id: f for f in facts}.values(), key=lambda f: f.id)
        raw = "|".join([rule, key, *(f.id for f in facts)])
        evidence_id = "ev:" + hashlib.sha1(raw.encode()).hexdigest()[:12]
        if evidence_id not in self.graph.evidence:
            frames = sorted({fr for f in facts for fr in f.frames})[:MAX_FRAMES]
            self.graph.evidence[evidence_id] = Evidence(
                id=evidence_id,
                rule=rule,
                weight=WEIGHTS[rule],
                provenance="+".join(sorted({str(f.provenance) for f in facts})) or "inferred",
                run=",".join(sorted({f.run_id for f in facts})),
                summary=summary,
                frames=frames,
            )
        return evidence_id

    def weight_of(self, evidence_ids: Iterable[str]) -> list[float]:
        return [self.graph.evidence[e].weight for e in evidence_ids]

    def add_or_merge_link(self, link: Link) -> None:
        """Add a link; if it exists, merge evidence and attributes and recompute confidence."""
        existing = self.graph.links.get(link.id)
        if existing is None:
            self.graph.add_link(link)
            return
        existing.evidence = sorted(set(existing.evidence) | set(link.evidence))
        existing.confidence = noisy_or(self.weight_of(existing.evidence))
        basis = sorted(set(existing.attrs.get("basis", [])) | set(link.attrs.get("basis", [])))
        for key, value in link.attrs.items():
            if existing.attrs.get(key) is None:
                existing.attrs[key] = value
        if basis:
            existing.attrs["basis"] = basis
