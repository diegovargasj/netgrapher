# netgrapher — Requirements and Design

| | |
|---|---|
| **Status** | Draft v0.1 (design stage, no code yet) |
| **Date** | 2026-10-11 |
| **Author** | diegovargasj |

---

## Table of contents

1. [Introduction](#1-introduction)
2. [Use cases](#2-use-cases)
3. [Functional requirements](#3-functional-requirements)
4. [Non-functional requirements](#4-non-functional-requirements)
5. [Architecture](#5-architecture)
6. [Data model](#6-data-model)
7. [Inference](#7-inference)
8. [Discovery modes and probing](#8-discovery-modes-and-probing)
9. [Capture](#9-capture)
10. [Project file format](#10-project-file-format)
11. [User interface](#11-user-interface)
12. [CLI](#12-cli)
13. [Security, privacy and safety](#13-security-privacy-and-safety)
14. [Repository layout](#14-repository-layout)
15. [Testing strategy](#15-testing-strategy)
16. [Roadmap](#16-roadmap)
17. [Risks](#17-risks)
18. [Open items](#18-open-items)
19. [Decision log](#19-decision-log)

---

## 1. Introduction

### 1.1 Purpose

netgrapher is a Python tool that builds a **best-effort network-layer (L3) topology graph** of a network from the traffic it observes, optionally supplemented by probes it sends itself. It finds subnets, routers and hosts, works out how they connect, and shows the result as an interactive, editable graph.

The tool can only see part of the network, so the graph will usually be incomplete. netgrapher does not hide this. **Every element of the graph records where it came from (provenance) and how confident the tool is about it**, and the tool reports what it could not determine.

### 1.2 Scope

In scope:

- L3 entities: subnets, routers (and their interfaces), hosts, external networks, and routers known to exist but never seen.
- L3 relationships: host membership in a subnet, router interfaces on subnets, inferred paths between networks.
- Input from live capture (primary) and from pcap/pcapng files (secondary).
- Three discovery modes: **passive**, **active** and **reactive**.
- An interactive local UI to view, rename, hide, save, reopen and screenshot graphs.

### 1.3 Non-goals

- **L1/L2 topology** (switches, cables, VLANs, STP trees). L2 headers are read only as *evidence* for L3 conclusions (for example ARP, or one MAC carrying many source IPs). They never appear as graph elements.
- Port scanning, service or version detection, vulnerability assessment.
- Traffic analytics or monitoring dashboards (bandwidth, top talkers) beyond an optional flow overlay.
- Wireless (802.11) analysis.
- Configuration management, or pulling data from network devices (SNMP, SSH).

### 1.4 Glossary

| Term | Meaning |
|---|---|
| **Entity** | A graph element: subnet, router, host, external network or unknown router. |
| **Link** | A relationship between two entities (membership, interface, inferred path). |
| **Fact** | An atomic observation taken from a packet, a probe reply or the local host's configuration. |
| **Evidence** | One or more facts plus the rule that turned them into a conclusion about an entity or link. |
| **Provenance** | Where a piece of evidence came from: `hostcfg`, `passive` or `probe`. |
| **Confidence** | A number in [0, 1] saying how strongly the evidence supports an entity, link or attribute. |
| **Annotation** | A user edit (label, hidden flag, note, position). Stored separately from discovered data. |
| **Scope** | The set of address ranges the tool is allowed to probe. |
| **Generation** | How many steps a reactive probe target is removed from passive observation. |
| **Engine** | The process that captures, probes and runs inference. |

### 1.5 Requirement keywords

**MUST**, **SHOULD** and **MAY** follow RFC 2119. Each requirement lists the release it targets (**v1** or **v2**).

---

## 2. Use cases

| ID | Actor | Scenario |
|---|---|---|
| UC-1 | Network admin | Plugs a laptop into an unfamiliar office network, runs passive discovery for 30 minutes, and gets a map of subnets and gateways without sending a single packet. |
| UC-2 | Pentester (authorized) | Runs active discovery against the CIDRs in the engagement scope and gets a router/subnet map with hop structure. |
| UC-3 | Network admin | Runs reactive discovery so that only networks actually seen in traffic get probed, which fills in gaps while keeping noise low. |
| UC-4 | Analyst | Loads an existing pcap from an incident and gets the L3 topology it reveals. |
| UC-5 | Any user | Renames routers and subnets to meaningful names, hides noise, saves the project, and exports a screenshot for a report. |
| UC-6 | Any user | Reopens a saved project on another machine with no special privileges. |
| UC-7 | Any user | Watches the graph grow live during a discovery run. |

---

## 3. Functional requirements

### 3.1 Input and capture

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-IN-1 | The tool MUST capture live traffic from one or more user-selected interfaces. | MUST | v1 |
| FR-IN-2 | The tool MUST read pcap and pcapng files through the same processing pipeline as live capture. | MUST | v1 |
| FR-IN-3 | File input MUST be passive only. Combining `--read` with active or reactive mode is an error. | MUST | v1 |
| FR-IN-4 | Live capture MUST be able to save the raw capture to a pcapng file (`-w`). | MUST | v1 |
| FR-IN-5 | Live capture MUST use promiscuous mode by default, with an option to disable it. | MUST | v1 |
| FR-IN-6 | The snaplen MUST default to 512 bytes and be configurable. | MUST | v1 |
| FR-IN-7 | The user MAY supply an extra BPF capture filter. | MAY | v1 |
| FR-IN-8 | The tool MUST read the capture host's configuration (interface addresses and prefixes, routes, default gateways, neighbor cache, DNS resolvers) at the start of a live run and record it as `hostcfg` facts. | MUST | v1 |
| FR-IN-9 | The tool MUST record packet counts and kernel/interface drop statistics for each run. | MUST | v1 |
| FR-IN-10 | Supported link types MUST include Ethernet, Linux cooked capture (SLL and SLL2), raw IPv4/IPv6, and loopback/null. Unsupported link types MUST be reported and skipped. | MUST | v1 |
| FR-IN-11 | Malformed or truncated packets MUST be counted and skipped, never cause a crash. | MUST | v1 |
| FR-IN-12 | The decoder MUST handle 802.1Q/QinQ tags (stripped, VLAN ID kept as an attribute only), GRE, and IP-in-IP. | SHOULD | v1 |

### 3.2 Discovery modes

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-DM-1 | The tool MUST support exactly one mode per run: `passive`, `active` or `reactive`. | MUST | v1 |
| FR-DM-2 | All modes MUST listen passively, and everything observed MUST feed into the graph. | MUST | v1 |
| FR-DM-3 | **Passive** mode MUST NOT send any packet, including DNS lookups. | MUST | v1 |
| FR-DM-4 | **Active** mode MUST require one or more user-provided CIDRs and MUST only probe addresses inside them (minus excludes). | MUST | v1 |
| FR-DM-5 | **Active** mode MUST NOT create probe targets from observed traffic. Its probe plan is fixed at start. | MUST | v1 |
| FR-DM-6 | **Reactive** mode MUST probe only targets derived from observed traffic (or from earlier probe replies, up to the generation limit), and only inside scope. | MUST | v1 |
| FR-DM-7 | Reactive scope MUST default to RFC1918, ULA (fc00::/7), CGNAT (100.64.0.0/10) and the capture host's local subnets, and be adjustable with allow/deny lists. | MUST | v1 |
| FR-DM-8 | Public addresses MUST NOT be probed in reactive mode unless `--allow-public` is given. Even then, they get at most one traceroute per /24 (or per ASN when ASN data is available) and are never swept. | MUST | v1 |
| FR-DM-9 | Reactive mode MUST enforce a generation limit (default 2) and a total probe budget (default 10,000 probes). | MUST | v1 |
| FR-DM-10 | All scanning modes MUST enforce a global rate limit (default 50 probes/s) and a per-destination rate limit (default 5 probes/s). | MUST | v1 |
| FR-DM-11 | `--dry-run` MUST print the planned targets and probe types without sending anything. In reactive mode it prints the targets the planner *would* create while running passively. | MUST | v1 |
| FR-DM-12 | Every probe sent MUST be written to a per-run audit log. | MUST | v1 |
| FR-DM-13 | Active mode MUST refuse CIDRs larger than /16 (IPv4) unless `--force-large` is given. | MUST | v1 |
| FR-DM-14 | The tool MUST print an authorization warning when a scanning mode starts. | MUST | v1 |

### 3.3 Stop conditions

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-ST-1 | A run MUST stop on any of these: `--duration`, `--packets`, or Ctrl-C/SIGTERM. | MUST | v1 |
| FR-ST-2 | `--until-converged T` MUST stop the run when no new entity has appeared for T **and** the probe queue is empty **and** no probes are in flight. | MUST | v1 |
| FR-ST-3 | Active mode MUST stop by default when its plan is finished and a grace period (default 10 s) has passed for late replies. | MUST | v1 |
| FR-ST-4 | Stopping MUST be clean: stop sending probes, wait out the grace period, run a final inference pass, and save the project and capture. | MUST | v1 |
| FR-ST-5 | A second Ctrl-C MUST force an immediate exit after a best-effort save. | SHOULD | v1 |

### 3.4 Inference and graph

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-GR-1 | The graph MUST model subnets, routers, hosts, external networks and unknown routers as entities (§6). | MUST | v1 |
| FR-GR-2 | Every entity, link and inferred attribute MUST carry a confidence and references to its evidence. | MUST | v1 |
| FR-GR-3 | Facts from probe replies MUST be marked with `probe` provenance. The probes themselves and their replies MUST NOT be treated as passively observed communication. | MUST | v1 |
| FR-GR-4 | Entity IDs MUST be stable across inference passes and across save/load cycles. Merges and renames of IDs MUST be recorded in an alias table (§6.3). | MUST | v1 |
| FR-GR-5 | The tool MUST produce a "coverage report": protocols seen, what each one contributed, entities with low confidence, and known gaps (for example "3 remote networks reached through an unknown path"). | MUST | v1 |
| FR-GR-6 | The data model MUST be dual-stack. v1 MUST implement IPv4 inference; IPv6 inference is v2. | MUST | v1/v2 |
| FR-GR-7 | An optional flow overlay MAY record aggregated host-to-host communication (packets, bytes, protocols, first/last seen), kept separate from topology links. | MAY | v1 |
| FR-GR-8 | External addresses MUST be grouped into a single "Internet" entity, or into per-ASN entities when the user supplies an offline ASN database. | MUST | v1 |

### 3.5 Persistence and export

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-PR-1 | A run MUST produce a project file (`.ngraph`) as defined in §10. | MUST | v1 |
| FR-PR-2 | Project files MUST carry a format version, and newer releases MUST migrate older versions on load. | MUST | v1 |
| FR-PR-3 | Project files MUST store discovered data, annotations, layout positions, view state and run metadata. | MUST | v1 |
| FR-PR-4 | Opening a project MUST NOT require any special privileges. | MUST | v1 |
| FR-PR-5 | The CLI MUST export to GraphML, GEXF, JSON (node-link) and DOT. Exports MAY drop annotations, layout and evidence. | MUST | v1 |
| FR-PR-6 | A new discovery run MUST be able to merge into an existing project (resume). | SHOULD | v2 |

### 3.6 User interface

| ID | Requirement | Pri | Rel |
|---|---|---|---|
| FR-UI-1 | The UI MUST display the graph interactively: pan, zoom, select, drag nodes. | MUST | v1 |
| FR-UI-2 | The user MUST be able to rename subnets, routers, hosts and links. The original identifier MUST stay visible in the tooltip and details panel. | MUST | v1 |
| FR-UI-3 | The user MUST be able to hide individual subnets, routers, hosts and links. | MUST | v1 |
| FR-UI-4 | Hiding a subnet MUST hide its hosts and links. Hiding a router MUST hide its links. Hiding a link MUST hide only that link. | MUST | v1 |
| FR-UI-5 | The user MUST be able to hide items by filter rule: type, confidence below a threshold, provenance, external, address range. | MUST | v1 |
| FR-UI-6 | A "Hidden items" panel MUST list manually hidden items so they can be restored. A "show hidden" toggle MUST display them faded. | MUST | v1 |
| FR-UI-7 | The UI MUST save the project (to its current path) and offer "Save as" (download). Autosave MUST protect unsaved edits. | MUST | v1 |
| FR-UI-8 | The UI MUST open previously saved projects. | MUST | v1 |
| FR-UI-9 | The UI MUST export screenshots as PNG (scale and background selectable) and SVG, for either the current view or the full graph. Hidden items MUST be left out. | MUST | v1 |
| FR-UI-10 | Screenshot export MUST offer anonymization: IPs, prefixes and names replaced with consistent placeholders. | MUST | v1 |
| FR-UI-11 | Edits MUST support undo/redo. | MUST | v1 |
| FR-UI-12 | A details panel MUST show an entity's attributes, confidence and evidence ("why is this a router?"). | MUST | v1 |
| FR-UI-13 | The user MUST be able to add a free-text note to any entity or link. | SHOULD | v1 |
| FR-UI-14 | Hosts MUST be drawn inside collapsible subnet containers. | MUST | v1 |
| FR-UI-15 | The UI MUST offer a force-directed layout and a hierarchical layout. Nodes the user has moved MUST stay pinned and be saved. | MUST | v1 |
| FR-UI-16 | The UI MUST be able to attach to a running engine, apply live updates without moving existing nodes, highlight new entities, and offer a "pause updates" control. | MUST | v1 |
| FR-UI-17 | Search MUST match both custom labels and original identifiers. | MUST | v1 |
| FR-UI-18 | Starting and stopping discovery from the UI. | SHOULD | v2 |
| FR-UI-19 | A desktop window wrapper (pywebview). | MAY | v2 |

---

## 4. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-1 | Performance | Read pcap files at **≥ 30,000 packets/s** on a modern laptop (initial target, to be validated). |
| NFR-2 | Performance | Sustain live capture at **10,000 packets/s** without kernel drops, using a 64 MiB dumpcap buffer. |
| NFR-3 | Memory | Process input as a stream. Memory grows with the number of entities, not packets. Target: ≤ 500 MB for 50,000 distinct IPs. |
| NFR-4 | Scale (UI) | Stay usable with 5,000 visible nodes. Collapsing subnets keeps larger graphs workable. |
| NFR-5 | Privileges | The Python process MUST NOT require root. Capture privileges live in `dumpcap` (file capabilities). v1 probing uses only unprivileged techniques. |
| NFR-6 | Security | Captured packets are untrusted input. Decoders MUST be robust against malformed data (fuzz-tested). |
| NFR-7 | Security | The UI server MUST bind to 127.0.0.1 only, require a session token, and validate `Host`/`Origin` headers (DNS-rebinding protection). |
| NFR-8 | Privacy | No telemetry, and no network access other than capture and explicitly enabled probes. The UI MUST load all assets locally (no CDNs). |
| NFR-9 | Portability | Linux first. OS-specific code (capture, host configuration, probes) MUST sit behind interfaces so macOS and Windows can be added later. |
| NFR-10 | Licensing | Project license MIT or Apache-2.0 (see §18). Runtime dependencies MUST NOT be GPL (scapy is therefore excluded). Every frontend library's license MUST be audited. |
| NFR-11 | Determinism | The same input MUST produce the same graph, IDs and export ordering. |
| NFR-12 | Maintainability | Python ≥ 3.11, fully type-hinted, mypy strict for the core packages, pytest, `uv` + `pyproject.toml`. |
| NFR-13 | Observability | Structured logging (JSON optional), a progress display for files and live runs, `--verbose`/`--quiet`. |
| NFR-14 | Usability | `netgrapher doctor` MUST check the environment (dumpcap present and capable, ping-socket permission, interfaces) and say how to fix each problem. |

---

## 5. Architecture

### 5.1 Process model

```
                          (file capabilities: cap_net_raw, cap_net_admin)
                         ┌──────────────────────┐
         network ───────►│ dumpcap  (child)     │── pcapng stream on stdout ──┐
                         └──────────────────────┘                              │
                                                                               ▼
┌──────────────────────────────── netgrapher engine (unprivileged) ─────────────────────────────────┐
│                                                                                                   │
│  Source ─► Decoder ─► Extractors ─► Fact store ─► Inference engine ─► Graph model ─► Project store │
│                           │              ▲                                   │                    │
│                           │              │ probe replies tagged              │ diffs              │
│                           ▼              │                                   ▼                    │
│                    Probe registry ◄── Prober ◄── Target planner       API server (FastAPI)        │
│                                       (rate limiter, audit log)              │  REST + WebSocket  │
└──────────────────────────────────────────────────────────────────────────────┼────────────────────┘
                                                                               │ 127.0.0.1 + token
                                                                               ▼
                                                                 Browser UI (Cytoscape.js)

v2: a small privileged helper (netgrapher-helper) receives probe requests from the
    prober over a Unix socket and sends raw packets (ARP, TCP SYN, Paris traceroute).
```

- **dumpcap** is the only component that needs capture privileges.
- The **engine** runs as the user. It can host the API/UI server itself (`discover --ui`), or the UI can run alone to view saved projects (`netgrapher ui`).
- The web server therefore never runs with capture or raw-socket privileges.

### 5.2 Components

| Component | Responsibility |
|---|---|
| **Source** | `LiveSource` starts dumpcap and reads its pcapng stream. `FileSource` reads pcap/pcapng. Both yield `(timestamp, interface, linktype, bytes)`. Optionally tees raw bytes to `-w`. |
| **HostInfo** | Reads the capture host's configuration (`ip -j addr/route/neigh`, `/etc/resolv.conf`) and emits `hostcfg` facts. Linux implementation in v1. |
| **Decoder** | dpkt-based decoding into a lightweight `DecodedPacket` (L2 evidence fields, IP header, L4 header, selected application payloads). Unwraps VLAN/GRE/IP-in-IP. |
| **Extractors** | One plugin per protocol (ARP, IPv4, ICMP, DHCP, DNS, mDNS, LLMNR, NBNS, OSPF, RIP, VRRP, HSRP, …). Each turns packets into typed **facts**. Extractors hold no global state. |
| **Fact store** | Append-only, deduplicated, time-aware store of facts with counters and first/last-seen times. Holds IP↔MAC bindings with time intervals. |
| **Inference engine** | Runs rules (§7) over the fact store and produces entities and links with confidence and evidence. Periodic full recompute (every 2 s in live runs; once at the end for files). |
| **Graph model** | The current graph. Computes diffs between inference passes for live updates. Owns stable-ID assignment and the alias table. |
| **Target planner** | `ActivePlanner` (fixed plan from CIDRs) or `ReactivePlanner` (subscribes to graph diffs). Applies scope, dedup, generation limit and budget, and pushes to a priority queue. |
| **Prober** | Async sender of probes, with token-bucket rate limiting. Records each probe in the registry and the audit log. |
| **Probe registry** | Maps probe identifiers (ICMP id/seq, UDP/TCP source port, TTL, destination) to probe records. Used to tag replies seen in the capture as `probe` provenance and to drop the outgoing probes from passive analysis. |
| **Project store** | Loads and saves `.ngraph` files, migrates old versions, merges annotations and the alias table. |
| **Exporters** | GraphML, GEXF, JSON node-link, DOT. |
| **API server** | FastAPI app serving the static UI, REST endpoints and a WebSocket event stream. |
| **Web UI** | Static HTML/JS (no build step in v1) with vendored Cytoscape.js and extensions. |

### 5.3 Concurrency

- The engine runs on an **asyncio** event loop.
- Reading and decoding packets happens in a **dedicated thread**, which pushes facts onto a bounded queue (dpkt is synchronous and CPU-bound).
- The prober, planner, inference ticker and API server (uvicorn) are asyncio tasks.
- The fact store is written from one consumer task only, so it needs no locks. Inference works on a consistent snapshot between ingestion batches.
- Multiprocessing is deferred. If profiling shows decoding is the bottleneck, decoding can be split across processes per capture file or interface.

### 5.4 Reply correlation

Every probe reply reaches the engine **through the capture stream**, which is the single source of truth. The prober only sends. For each captured packet, the decoder checks the probe registry:

1. **Outgoing probe** (matches a registry entry by 5-tuple, ICMP id/seq or TTL marker) → used to timestamp the probe, otherwise ignored.
2. **Reply to a probe** (ICMP echo reply, ICMP error quoting a probe header, TCP SYN-ACK/RST) → facts are emitted with `provenance=probe` and `probe_id`.
3. **Anything else** → normal `passive` facts.

As a fallback, errors received on the prober's own sockets (`IP_RECVERR`) are also recorded, in case the capture dropped the reply.

---

## 6. Data model

### 6.1 Entities

| Type | ID format | Key attributes |
|---|---|---|
| **Subnet** | `net:<prefix>` e.g. `net:10.0.1.0/24` | `prefix`, `version`, `prefix_confidence`, `kind` (`local`, `remote`, `transit`), `gateway_ids`, `dhcp_servers` |
| **Router** | `rtr:<canonical-ip>` (see §6.3) | `interfaces[] {ip, subnet_id, confidence}`, `router_id` (OSPF/etc.), `names[]`, `protocols[]` (OSPF, VRRP, …), `roles[]` (`default-gateway`, `dhcp-relay`, …) |
| **Host** | `host:<ip>` e.g. `host:10.0.1.23` | `ip`, `subnet_id`, `names[] {name, source}`, `hop_distance`, `os_family_guess` (from initial TTL), `roles[]` (`dns-server`, `dhcp-server`, …), `is_self`, `first_seen`, `last_seen`, `l2_evidence` (MACs; details panel only) |
| **External** | `ext:internet` or `ext:as<asn>` | `asn`, `as_name`, `prefixes[]`, `host_count` |
| **Unknown router** | `unk:<hash>` | `reason` (e.g. traceroute hop with no reply), `position` (between which entities, at which hop) |

A host IP that turns out to belong to a router is **promoted**: it becomes a router interface, the `host:` entity disappears, and an alias `host:<ip> → rtr:<id>` is recorded, so annotations follow it.

### 6.2 Links

| Type | Endpoints | Attributes |
|---|---|---|
| **member** | host → subnet | `confidence` |
| **interface** | router → subnet | `ip`, `confidence` (label on the edge: the interface IP or the user's label) |
| **inferred-path** | router/subnet → subnet/external | `hops` (exact or range), `basis` (`ttl`, `traceroute`), `confidence`. Stands in for an unseen chain of routers without drawing a phantom node per hop. |
| **uplink** | router → external | `confidence` |

Link IDs are derived from their endpoints: `lnk:<type>:<a>|<b>`.

The router–subnet model is the classic L3 topology representation: two routers are adjacent only through a shared subnet, never through a direct edge. Point-to-point /30 and /31 networks appear as small `transit` subnets.

### 6.3 Stable IDs and the alias table

IDs must not change between inference passes or between saves, because annotations refer to them.

- **Subnets.** If a later observation corrects the prefix length (e.g. /24 → /23), the subnet gets a new ID and an alias `old → new` is recorded.
- **Routers.** The canonical IP is the first interface IP that established the router. It never changes after creation, even if lower IPs show up later. When alias resolution merges routers A and B, the surviving ID is the older one, and an alias `B → A` is recorded.
- **Splits** (rare; evidence turns out wrong) create a new ID for the split-off part. Annotations stay with the original ID.
- **Annotation merges.** When two annotated entities merge, the surviving entity keeps its own label. The other label is stored in `note` and a warning is logged.
- The alias table is saved in the project file. Lookups resolve aliases transitively.

### 6.4 Facts, evidence and confidence

```python
@dataclass(frozen=True)
class Fact:
    kind: FactKind  # e.g. ARP_BINDING, DHCP_ACK, ICMP_TIME_EXCEEDED, TTL_OBSERVED, ...
    subject: str  # usually an IP
    data: Mapping[str, Any]  # kind-specific payload
    provenance: Provenance  # HOSTCFG | PASSIVE | PROBE
    run_id: str
    first_seen: float
    last_seen: float
    count: int
    frames: tuple[int, ...]  # first N frame numbers (N = 10), for traceability
    probe_id: str | None


@dataclass
class Evidence:
    id: str
    rule: str  # e.g. "R-RTR-ICMP"
    weight: float  # the rule's base confidence
    fact_refs: list[str]
    summary: str  # human readable: "10.0.0.1 sent ICMP Time Exceeded for 14 probes"
```

**Combining evidence.** Independent pieces of evidence are combined with *noisy-OR*:
`confidence = 1 − ∏(1 − wᵢ)`.
This is simple, monotonic and explainable. Contradicting evidence (for example a host-like TTL pattern on a supposed router) applies a penalty multiplier that the rule defines. Rule weights live in one table (`infer/weights.py`) so they can be tuned against lab ground truth (§15).

---

## 7. Inference

### 7.1 Rules (IPv4, v1)

| Rule | Evidence | Conclusion | Base weight |
|---|---|---|---|
| R-SUB-HOSTCFG | Capture host's interface address and prefix | Local subnet | 1.00 |
| R-SUB-DHCP | DHCP ACK with option 1 (mask) and assigned IP | Subnet | 0.95 |
| R-SUB-OSPF | OSPF Hello network mask / Network-LSA | Subnet | 0.95 |
| R-SUB-ROUTE | Capture host's routing table entry | Subnet exists (remote or local) | 0.90 |
| R-SUB-ARP | Set of IPs proven on-link by ARP | Lower bound on the subnet: the smallest prefix containing them | 0.40 |
| R-SUB-HEUR | Private IPs off-link, nothing better known | Assume /24 | 0.20 |
| R-RTR-HOSTCFG | Default or next-hop gateway in the host's routing table | Router + interface | 1.00 |
| R-RTR-DHCP | DHCP option 3 (router) | Router + interface | 0.90 |
| R-RTR-PROTO | Speaks OSPF, RIP, EIGRP, BGP, VRRP or HSRP | Router (VRRP/HSRP virtual IP recorded as a shared interface) | 0.95 |
| R-RTR-ICMP | Source of ICMP Time Exceeded, Redirect, or Net/Host Unreachable | Router | 0.90 |
| R-RTR-TRACE | Traceroute hop reply (probe) | Router at hop *n* on a path | 0.95 |
| R-RTR-MAC | One L2 source MAC carries ≥ 3 distinct off-subnet source IPs | The IP bound to that MAC (via ARP) is a router interface | 0.80 |
| R-ALIAS-ID | Same OSPF/BGP router ID | Merge routers | 0.95 |
| R-ALIAS-MAC | Same MAC bound to IPs in different subnets | Merge routers | 0.70 |
| R-ALIAS-MERCATOR | UDP to a closed port on IP A gets ICMP Port Unreachable from IP B (probe) | Merge routers | 0.85 |
| R-ALIAS-PTR | Reverse-DNS names share a device pattern (probe modes only) | Merge routers (weak) | 0.30 |
| R-HOP-TTL | Received TTL vs. inferred initial TTL (64/128/255) | `hop_distance`; an `inferred-path` link when > 0 | 0.60 |
| R-PATH-TRACE | A complete or partial traceroute | `interface` links along the path; `unk:` nodes for silent hops | 0.90 |
| R-EXT | Public IP (not RFC1918/CGNAT/link-local/multicast) | Member of `ext:internet` or `ext:as<n>` | 1.00 |
| R-NAME-* | DNS answers, DHCP option 12, mDNS, LLMNR, NBNS, PTR | `names[]` with source | 0.5–0.9 |
| R-ROLE-* | DHCP server, DNS server, OSPF DR, … | `roles[]` | 0.9 |

IPv6 rules (RA prefixes and routers, NDP, EUI-64, OSPFv3) are v2.

### 7.2 Placement of remote hosts

1. If the host is on a known subnet (by prefix containment), make it a member of that subnet.
2. Otherwise, if it is private and off-link: create or extend a `remote` subnet (R-SUB-HEUR), connected to the gateway router through an `inferred-path` with the hop distance from R-HOP-TTL.
3. Otherwise (public): attach it to the external entity.

### 7.3 Coverage report

Generated at the end of each run, and available in the UI and through `netgrapher info`:

- Packets, drops, duration, mode, scope, probes sent.
- Protocols seen, with what each contributed (e.g. "DHCP: 2 subnets, 1 router").
- Low-confidence entities (< 0.5) and why.
- Gaps: unresolved paths, remote subnets with an assumed prefix, routers seen with only one interface.
- Suggestions: e.g. "no routing protocols observed; try reactive mode", "high drop rate; increase buffer".

---

## 8. Discovery modes and probing

### 8.1 Mode summary

| Mode | Listens | Probes | Where targets come from |
|---|---|---|---|
| `passive` | ✔ | never (no DNS either) | — |
| `active` | ✔ | ✔ | Fixed plan from user CIDRs (required). Never reacts to observations. |
| `reactive` | ✔ | ✔ | Generated from observations and probe replies, within scope, up to the generation limit. |

### 8.2 Active plan

For each user CIDR (minus excludes), with addresses in shuffled order:

1. **Host discovery:** ICMP echo to every address. Addresses that don't respond get a TCP connect to ports 443, 80, 22, 445 and 3389 (a SYN-ACK or RST means the host is alive).
2. **Path discovery:** a UDP traceroute to one responsive address per /24 (or to `.1` if none responded).
3. **Alias probes:** Mercator UDP probes to every router interface found in steps 1–2 that lies inside the CIDRs.
4. **Names:** PTR lookups for responsive addresses.

Because the plan is fixed, its size is known in advance. This gives an exact `--dry-run` listing and percentage progress.

### 8.3 Reactive planner

| Trigger (graph event) | Action (if in scope, deduplicated) |
|---|---|
| New in-scope subnet (local or remote) | Host-discovery sweep of the prefix, if it is /22 or smaller (larger: traceroute only, plus a warning). Traceroute to one address in it. |
| New in-scope host on a not-yet-traced remote prefix | Traceroute to it (one per /24). |
| New router interface | Mercator alias probe; PTR lookup. |
| New public IP (only with `--allow-public`) | One traceroute per /24 (or ASN). Never a sweep. |

- **Generation:** targets derived from passive observations are generation 1. Targets derived from entities first seen in probe replies are generation *n+1*. Targets above `--max-generation` (default 2) are dropped and counted.
- **Budget:** when `--budget` probes have been sent, the planner stops and the run continues passively.
- **Priority:** traceroutes to new remote networks, then alias probes, then sweeps, then PTR lookups.

### 8.4 Probe techniques

| Probe | Purpose | v1 (unprivileged) mechanism | v2 (helper) |
|---|---|---|---|
| ICMP echo | Liveness | Linux ping socket: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` (needs the user's GID in `net.ipv4.ping_group_range`) | — |
| TCP connect | Liveness | Normal non-blocking `connect()` with a 1 s timeout | Raw SYN |
| UDP traceroute | Paths | UDP socket with `IP_TTL` per probe and `IP_RECVERR` to read ICMP errors, plus the capture (the same approach as `tracepath`) | Paris traceroute (ICMP/UDP/TCP) with a fixed flow ID |
| Mercator alias | Router aliases | UDP to a high closed port; compare the ICMP reply source (`SO_EE_OFFENDER` / capture) | — |
| IP-ID alias | Router aliases | — | Ally/MIDAR-style IP-ID sequence comparison |
| ARP sweep | On-link liveness | — (the neighbor cache is read passively) | Raw ARP |
| PTR lookup | Names | System resolver (probe modes only) | — |

Defaults: traceroute max TTL 30, one probe per hop, stop after 3 consecutive silent hops past the last reply. ICMP timeout 2 s. Global rate limit 50 pps, per destination 5 pps, at most 256 probes in flight.

### 8.5 Audit log

One JSON Lines file per run (`<project>.audit.jsonl`). Each line:

```json
{"ts": 1760212345.123, "run": "r1", "probe_id": "p000123", "type": "udp-trace",
 "dst": "10.20.0.1", "ttl": 3, "sport": 40213, "dport": 33437,
 "reason": "reactive:new-remote-subnet", "trigger": "net:10.20.0.0/24", "generation": 1}
```

---

## 9. Capture

### 9.1 Live capture via dumpcap

```
dumpcap -q -i <if1> [-i <if2> ...] -s 512 -B 64 [-p] [-f "<bpf>"] -w -
```

- Writes pcapng to stdout (`-w -`). The engine reads it as a stream and optionally tees the raw bytes to the `-w` file.
- Drop statistics come from pcapng Interface Statistics Blocks, plus a final stats query when the run ends.
- **Fallback:** if streaming pcapng parsing turns out to be unreliable with dpkt, use classic pcap (`-P`) when there is a single interface.
- **Privileges:** `dumpcap` with `cap_net_raw,cap_net_admin=eip`. On Debian/Kali: `sudo dpkg-reconfigure wireshark-common` (allow non-superusers), then `sudo usermod -aG wireshark $USER`. `netgrapher doctor` checks this.

### 9.2 Host configuration (Linux)

- `ip -j addr`, `ip -j route show table all`, `ip -j neigh` (JSON output, no extra dependency). Falls back to `/proc/net/*`.
- `/etc/resolv.conf` (and `resolvectl` when available) for DNS servers.
- Taken once at start and once at the end of a run. Differences are recorded as facts.

---

## 10. Project file format

A gzip-compressed JSON file with the extension `.ngraph`.

```jsonc
{
  "format": "netgrapher-project",
  "version": 1,
  "tool_version": "0.1.0",
  "created": "2026-10-11T21:00:00Z",
  "modified": "2026-10-11T21:45:00Z",

  "runs": [{
    "id": "r1", "mode": "reactive", "source": "live",
    "interfaces": ["eth0"], "cidrs": [], "scope": {"allow": ["10.0.0.0/8"], "deny": []},
    "started": "...", "ended": "...", "stop_reason": "converged",
    "stats": {"packets": 1203344, "drops_kernel": 0, "drops_iface": 0,
              "malformed": 12, "probes_sent": 4120},
    "hostcfg": { /* snapshot */ },
    "capture_file": {"path": "run1.pcapng", "sha256": "..."},
    "audit_file": "proj.audit.jsonl"
  }],

  "entities": {
    "net:10.0.1.0/24": {"type": "subnet", "prefix": "10.0.1.0/24", "kind": "local",
                        "confidence": 1.0, "evidence": ["e1", "e7"]},
    "rtr:10.0.1.1":    {"type": "router", "interfaces": [{"ip": "10.0.1.1", "subnet": "net:10.0.1.0/24"}],
                        "confidence": 0.99, "evidence": ["e2", "e9"]}
  },
  "links": {
    "lnk:interface:rtr:10.0.1.1|net:10.0.1.0/24": {"type": "interface", "a": "rtr:10.0.1.1",
        "b": "net:10.0.1.0/24", "ip": "10.0.1.1", "confidence": 0.99, "evidence": ["e2"]}
  },
  "evidence": {
    "e2": {"rule": "R-RTR-HOSTCFG", "weight": 1.0, "provenance": "hostcfg", "run": "r1",
           "summary": "Default gateway of eth0", "frames": [], "probe_id": null}
  },
  "aliases": {"host:10.0.1.1": "rtr:10.0.1.1"},
  "flows": [ /* optional overlay, capped at the top 10,000 by bytes */ ],

  "annotations": {
    "rtr:10.0.1.1": {"label": "Core GW", "hidden": false, "note": "", "color": null,
                     "position": {"x": 120.5, "y": -40.0}, "pinned": true}
  },
  "view": {"layout": "fcose", "zoom": 1.2, "pan": {"x": 0, "y": 0},
           "filters": [{"type": "confidence_below", "value": 0.3}],
           "collapsed": ["net:10.0.1.0/24"], "show_hidden": false}
}
```

Rules:

- `entities`, `links`, `evidence`, `aliases` and `flows` are written **only by the engine**. `annotations` and `view` are written **only by the UI**.
- Loading a file with an unknown *newer* major version is an error. Older versions go through `project/migrate.py`.
- Saving is atomic: write to a temporary file, `fsync`, then rename.
- Switching to SQLite is planned if projects get too large (see §16).

---

## 11. User interface

### 11.1 Technology

- **Backend:** FastAPI + uvicorn, run either inside the engine (`discover --ui`) or alone (`netgrapher ui`).
- **Frontend:** static HTML + ES-module JavaScript, **no build step in v1**, served from the Python package.
- **Libraries (vendored, never from a CDN):** Cytoscape.js, cytoscape-fcose, cytoscape-expand-collapse, cytoscape-elk with elkjs (hierarchical layout). SVG export uses an SVG exporter whose license must be checked (see §17).
- **v2:** an optional pywebview wrapper (`netgrapher ui --window`).

### 11.2 Layout of the screen

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│ [Open] [Save] [Save as] [Export ▾] [Screenshot ▾] │ Layout: [fCoSE ▾] │ 🔍 search  │
├──────────────┬────────────────────────────────────────────────┬───────────────────┤
│ Filters      │                                                │ Details           │
│ ☑ Routers    │                                                │ Core GW           │
│ ☑ Subnets    │                    graph canvas                │ rtr:10.0.1.1      │
│ ☑ Hosts      │                                                │ conf 0.99         │
│ ☑ External   │                                                │ Interfaces …      │
│ conf ≥ [0.3] │                                                │ Evidence …        │
│ provenance ▾ │                                                │ [Rename] [Hide]   │
│──────────────│                                                │ Note: …           │
│ Hidden (3)   │                                                │                   │
│  • net:… ↺   │                                                │                   │
├──────────────┴────────────────────────────────────────────────┴───────────────────┤
│ ● live  r1 reactive · 12,403 pkts · 0 drops · 41 entities · 120 probes  [Pause]   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### 11.3 Visual encoding

| Element | Encoding |
|---|---|
| Router | Round-rectangle node, router icon |
| Subnet | Compound container (collapsible); label = custom name or prefix |
| Host | Small circle inside its subnet; a different border for `is_self` |
| External | Cloud shape |
| Unknown router | Grey dashed node with a "?" |
| Provenance | Solid = observed (passive/hostcfg); double = confirmed by probe; dashed = inferred |
| Confidence | Opacity, from 0.35 to 1.0 |
| New in live mode | Pulse highlight for 5 s |

### 11.4 Editing behavior

- **Rename:** inline edit or from the details panel. An empty label resets to the default.
- **Hide / unhide:** cascades as defined in FR-UI-4. A hidden subnet's hosts are hidden *implicitly*: they don't appear in the Hidden panel individually.
- **Undo/redo:** a client-side command stack. Each command is an annotation patch plus its inverse.
- **Saving:** annotation patches go to the server immediately (`PATCH`). The server marks the project dirty and autosaves to `<project>.autosave` every 30 s. "Save" writes to the project path.

### 11.5 API

All endpoints require the session token (passed once in the URL fragment at launch, then swapped for an HttpOnly, SameSite=Strict cookie). Requests with an unexpected `Host` or `Origin` header are rejected.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/project` | Full project (entities, links, evidence summaries, annotations, view) |
| GET | `/api/entity/{id}/evidence` | Full evidence for one entity (loaded on demand) |
| PATCH | `/api/annotations/{id}` | Set label / hidden / note / color / position / pinned |
| POST | `/api/annotations:batch` | Several annotation patches (multi-select, undo) |
| PUT | `/api/view` | Save view state |
| POST | `/api/project/save` | Save to the current path |
| GET | `/api/project/download` | "Save as" as a file download |
| POST | `/api/project/open` | Open an uploaded `.ngraph` file, or a path from the recent list |
| GET | `/api/project/recent` | Recently opened projects |
| GET | `/api/report` | Coverage report |
| WS | `/api/events` | Live stream: `entity_added`, `entity_updated`, `entity_removed`, `alias`, `link_*`, `run_stats`, `run_ended` |

### 11.6 Screenshot export

- **PNG:** `cy.png({full, scale, bg})`. Scale 1–4×; background transparent, white or theme.
- **SVG:** via the SVG exporter (§17).
- **Anonymize:** a client-side mapping applied to labels before export. Subnets become `NET-01…`, routers `RTR-01…`, hosts `HOST-001…`, ASNs `AS-A…`. The mapping is consistent within an export. Custom labels are replaced too unless "keep custom labels" is ticked.

---

## 12. CLI

```
netgrapher discover [OPTIONS]
  --mode {passive,active,reactive}      default: passive
  -i, --interface IFACE                 repeatable; default: interface of the default route
  -r, --read FILE                       pcap/pcapng input (passive only)
  --cidr CIDR                           repeatable; required for and only valid with --mode active
  --scope CIDR / --exclude CIDR         reactive scope allow/deny (repeatable); --exclude also applies to active
  --allow-public                        reactive: allow limited traceroutes to public prefixes
  --max-generation N                    default 2
  --budget N                            default 10000 probes
  --rate PPS / --rate-per-host PPS      default 50 / 5
  --force-large                         allow active CIDRs larger than /16
  --dry-run                             print the probe plan, send nothing
  --duration DUR / --packets N          stop conditions
  --until-converged DUR                 stop when nothing new for DUR (and no probes pending)
  -s, --snaplen N                       default 512
  -f, --filter BPF                      extra capture filter
  --no-promisc
  -w, --write FILE.pcapng               save the raw capture
  -o, --output FILE.ngraph              default: netgrapher-<timestamp>.ngraph
  --asn-db FILE                         optional offline IP→ASN database
  --flows / --no-flows                  record the flow overlay (default: on)
  --ui [--port N] [--no-browser]        serve the live UI during the run

netgrapher ui [PROJECT.ngraph] [--port N] [--no-browser]
netgrapher export PROJECT.ngraph --format {graphml,gexf,json,dot} [-o FILE] [--include-hidden]
netgrapher info PROJECT.ngraph          summary + coverage report
netgrapher doctor                       environment checks with fix-it hints
```

Exit codes: `0` success, `1` runtime error, `2` usage error, `3` environment problem (see `doctor`).

---

## 13. Security, privacy and safety

| Concern | Mitigation |
|---|---|
| Malicious packets exploiting the parser | Pure-Python dpkt decoding (no C dissectors in process). Defensive length checks. Fuzzing (§15). The engine runs unprivileged. |
| Privilege escalation | Only `dumpcap` has capabilities. No sudo. The v2 helper is minimal: it accepts only well-formed probe requests, runs its own rate limit, and checks scope again itself. |
| UI exposed to other hosts or websites | Binds to 127.0.0.1 only. Session token. Host/Origin validation. SameSite cookie. No CORS. |
| Unintended scanning | Passive is the default mode. Active requires explicit CIDRs. Reactive has a private-only default scope, generation limit, budget and rate limits. `--dry-run`. Authorization warning. Audit log. |
| Sensitive data in outputs | Snaplen 512. No payload stored, only extracted fields. Anonymized screenshots. Project files may contain internal addressing and should be treated as confidential (stated in the README). |
| Supply chain | Frontend libraries vendored and pinned with checksums. Python dependencies pinned with `uv.lock`. |

---

## 14. Repository layout

```
netgrapher/
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── docs/
│   └── requirements-and-design.md
├── src/netgrapher/
│   ├── __init__.py
│   ├── cli.py                  # typer app: discover, ui, export, info, doctor
│   ├── config.py               # defaults, option models (pydantic)
│   ├── capture/
│   │   ├── source.py           # Source protocol, LiveSource (dumpcap), FileSource
│   │   └── hostinfo/           # HostInfo protocol; linux.py
│   ├── decode/
│   │   ├── packet.py           # DecodedPacket
│   │   └── decoder.py          # linktype dispatch, encapsulation unwrapping
│   ├── extract/                # one module per protocol: arp, ipv4, icmp, dhcp, dns, ospf, vrrp, ...
│   ├── facts/
│   │   ├── model.py            # Fact, FactKind, Provenance
│   │   └── store.py
│   ├── infer/
│   │   ├── engine.py
│   │   ├── weights.py
│   │   ├── confidence.py
│   │   └── rules/              # subnet.py, router.py, alias.py, path.py, names.py, external.py
│   ├── graph/
│   │   ├── model.py            # entities, links
│   │   ├── ids.py              # stable IDs, alias table
│   │   └── diff.py
│   ├── discovery/
│   │   ├── scope.py
│   │   ├── planner/            # active.py, reactive.py
│   │   ├── prober.py
│   │   ├── probes/             # icmp_echo.py, tcp_connect.py, udp_trace.py, mercator.py, ptr.py
│   │   ├── registry.py
│   │   ├── ratelimit.py
│   │   └── audit.py
│   ├── project/
│   │   ├── format.py
│   │   ├── migrate.py
│   │   └── store.py
│   ├── report.py               # coverage report
│   ├── export/                 # graphml.py, gexf.py, jsonlink.py, dot.py
│   ├── server/
│   │   ├── app.py
│   │   ├── api.py
│   │   ├── events.py
│   │   └── auth.py
│   └── web/                    # index.html, js/, css/, vendor/ (pinned libraries + LICENSES)
└── tests/
    ├── unit/
    ├── golden/                 # pcap → expected graph JSON
    ├── fuzz/
    ├── pcaps/
    └── labs/                   # containerlab topologies + ground-truth YAML
```

---

## 15. Testing strategy

| Level | What | Where |
|---|---|---|
| Unit | Each extractor (packet bytes → facts), each rule (facts → conclusions), confidence math, ID/alias logic, scope checks, rate limiter, project migration | `tests/unit`, CI |
| Golden | Reference pcaps → expected graph JSON (deterministic, compared after normalization) | `tests/golden`, CI |
| Fuzz | Decoders and extractors with Hypothesis-generated and mutated packets; must never raise | `tests/fuzz`, CI (short) + nightly (long) |
| Lab | containerlab topologies (routers + hosts) with a ground-truth YAML. Run all three modes and score subnet/router/link **precision and recall** | `tests/labs`, manual / nightly |
| UI | API tests (FastAPI TestClient). Playwright smoke tests: open, rename, hide, save, reopen, screenshot | CI |
| Safety | Assertions that passive mode sends zero packets, that probes never leave scope, and that the budget and generation limits hold | CI (network namespace) |

Sample pcap sources: the Wireshark SampleCaptures wiki, plus captures generated in the labs. Only pcaps whose licenses allow redistribution go into the repo.

---

## 16. Roadmap

| Milestone | Content |
|---|---|
| **0.1** | File input, decoder and extractors (IPv4, ARP, ICMP, DHCP, DNS), fact store, core inference rules, project save/load, `export`, `info`, golden tests. |
| **0.2** | Live capture via dumpcap, HostInfo (Linux), `doctor`, coverage report. |
| **0.3** | UI viewer: open, rename, hide, filters, save, PNG/SVG screenshots with anonymization, undo/redo. |
| **0.4** | Live attach (`discover --ui`), WebSocket diffs, stable live layout. |
| **0.5** | Active and reactive modes with unprivileged probes, scope, rate limits, budget, generation limit, `--dry-run`, audit log. OSPF/RIP/VRRP/HSRP extractors. |
| **1.0** | Hardening, lab precision/recall baseline, tuned rule weights, documentation, packaging. |
| **2.x** | IPv6 inference, privileged helper (ARP, SYN, Paris traceroute, IP-ID alias), resume/merge into projects, UI-controlled discovery, pywebview, macOS. |
| **Later** | Long-running monitor mode, Windows, NAT detection, SQLite project backend. |

---

## 17. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Passive inference is too weak on quiet or switched networks | Sparse graphs | Coverage report explains the gaps; reactive mode; lab-tuned weights. |
| Pure-Python decoding is too slow | Drops or slow file processing | Decode only the needed headers; filter early by protocol; profile; per-file multiprocessing; consider PyPy. |
| dpkt's pcapng reader and non-seekable stdin | Live capture broken | Validate early (spike in 0.2). Fallback: classic pcap (`-P`) for a single interface. |
| Frontend library licenses (e.g. **cytoscape-svg is reported to be GPL-3.0**; elkjs is EPL-2.0) | License conflict | Audit before vendoring. If needed, write a small in-house SVG serializer. Check EPL-2.0 compatibility for elkjs or use dagre (MIT) instead. |
| `ping_group_range` disallows ping sockets on some systems | No ICMP echo in v1 | `doctor` detects it and suggests the sysctl; TCP connect probes as fallback. |
| Router merges and splits break annotations | Lost user edits | Alias table, merge rules, tests. |
| Legal or ethical misuse of scanning | Harm, liability | Safe defaults, explicit opt-ins, warnings, audit log, documented authorization requirement. |
| IDS/IPS reactions to probes | Blocked capture host, alerts | Low default rates, documentation. |

---

## 18. Open items

| # | Item | Proposal |
|---|---|---|
| 1 | Final license: MIT or Apache-2.0 | **Apache-2.0** (explicit patent grant). Both meet NFR-10. |
| 2 | Default numbers (rates, budget, timeouts, convergence window, rule weights) | Use the values in this document and recalibrate after the first lab runs. |
| 3 | SVG export library | Decide after the license audit (§17). |
| 4 | ASN database format for `--asn-db` | Support an iptoasn.com-style TSV first. |

---

## 19. Decision log

| Date | Decision |
|---|---|
| 2026-10-11 | L3 only. L2 used solely as evidence. |
| 2026-10-11 | Live capture is the primary input. pcap/pcapng is kept as a secondary input through the same pipeline. Live runs can save the capture. |
| 2026-10-11 | Three discovery modes: passive, active, reactive. Every mode listens. |
| 2026-10-11 | Active mode probes only user-provided CIDRs (required) and does **not** react to observed traffic. |
| 2026-10-11 | Reactive default scope: private ranges plus local subnets. Public addresses opt-in with limited traceroutes. Generation limit 2, budget, rate limits, dry-run. |
| 2026-10-11 | Dual-stack data model. IPv4 in v1, IPv6 in v2. |
| 2026-10-11 | Linux first, OS code behind interfaces. Then macOS, then Windows. |
| 2026-10-11 | One-shot runs in v1. Long-running monitor later. |
| 2026-10-11 | Permissive license, no GPL dependencies. dpkt for parsing and crafting. dumpcap for capture. Snaplen 512. Python 3.11+, uv, typer, mypy, pytest. |
| 2026-10-11 | v1 probes are unprivileged. A privileged helper comes in v2. |
| 2026-10-11 | UI: localhost web app (FastAPI + Cytoscape.js). Discovery from the CLI in v1; UI-controlled discovery in v2. |
| 2026-10-11 | UI features: rename, hide (manual + filters, no delete), save, open, PNG/SVG screenshots with anonymization. Hosts in collapsible subnet containers. |
| 2026-10-11 | Annotations stored separately with stable IDs. Resume/merge designed now, implemented in v2. |
| 2026-10-11 | Project format: versioned gzipped JSON (`.ngraph`). |
