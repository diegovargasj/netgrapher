# netgrapher

**Builds a map of the routers, subnets and hosts on a network from the traffic it sees, and lets you explore and edit that map interactively.**

> **Status: early development (milestone 0.5).** All three discovery modes work: passive, plus active and reactive probing (unprivileged ICMP echo, TCP connect, UDP traceroute, PTR). Live and file capture, the interactive UI with live updates, `info`, `export`, `doctor` and `ui` are all available. IPv6 inference and the privileged probe helper are still *planned*. See [docs/requirements-and-design.md](docs/requirements-and-design.md) for the full specification.

---

## What it does

netgrapher listens on a network (or reads a pcap file) and works out its **network-layer (L3) topology**:

- **Subnets**: from the capture host's own configuration, DHCP, routing protocols, ARP and heuristics.
- **Routers and their interfaces**: from default gateways, ICMP errors, routing and redundancy protocols (OSPF, RIP, VRRP, HSRP), traceroutes and traffic patterns.
- **Hosts**: placed in their subnets, with names from DNS, DHCP, mDNS, LLMNR and NBNS.
- **Paths to remote networks and the Internet**: from TTL hop counts and traceroutes.

The tool can only see part of the network, so the map is usually incomplete. netgrapher makes the gaps visible instead of hiding them:

- Every node and link shows **how confident** the tool is and **why**: the evidence and the rules that produced it.
- Routers known to exist but never seen appear as "unknown" nodes or dashed paths.
- Each run ends with a **coverage report** listing what was found, what's missing, and suggestions to improve the result.

Layer 1/2 topology (switches, cables, VLANs) is out of scope.

## Discovery modes

| Mode | Listens | Sends probes | What gets probed |
|---|---|---|---|
| `passive` *(default)* | ✔ | **never** | Nothing. Not a single packet is sent, not even DNS lookups. |
| `active` | ✔ | ✔ | Only the CIDRs you pass with `--cidr`. The plan is fixed at start; observed traffic never adds targets. |
| `reactive` | ✔ | ✔ | Only networks and hosts **seen in the captured traffic**, within scope (by default private ranges and local subnets). |

Safety measures in the scanning modes: rate limits, a probe budget, a generation limit for reactive follow-ups, `--dry-run`, and an audit log of every probe sent.

> ⚠️ **Only use `active` or `reactive` mode on networks you own or are explicitly authorized to test.** Scanning other networks may be illegal and will likely trigger intrusion-detection systems.

## Features

- Live capture on one or more interfaces, or offline analysis of pcap/pcapng files.
- Interactive graph in your browser (served locally, works offline):
  - rename routers, subnets, hosts and links, and add notes;
  - hide items one by one or with filters (type, confidence, provenance, address range);
  - collapsible subnets, force-directed or hierarchical layout, search;
  - details panel showing the evidence behind each element;
  - live updates while discovery is running;
  - undo/redo and autosave.
- Save projects (`.ngraph`) and reopen them later on any machine, with no privileges needed.
- Screenshots as PNG or SVG, with optional **anonymization** for sharing.
- Export to GraphML, GEXF, JSON and DOT for Gephi, Graphviz, yEd and other tools.

## Requirements

- Linux (macOS and Windows planned)
- Python ≥ 3.11
- `dumpcap` (from the Wireshark/tshark packages), only needed for live capture
- A modern web browser

## Try it now (from source)

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/netgrapher doctor                                          # check dumpcap permissions
.venv/bin/netgrapher discover --duration 10m -w run.pcapng -o net.ngraph   # live, passive
.venv/bin/netgrapher discover --duration 10m --ui -o net.ngraph     # …and watch it grow in the UI
.venv/bin/netgrapher discover --read capture.pcapng -o net.ngraph   # or from a file
.venv/bin/netgrapher info net.ngraph
.venv/bin/netgrapher ui net.ngraph                                   # opens the UI in your browser
.venv/bin/netgrapher export net.ngraph --format dot -o net.dot && dot -Tsvg net.dot -o net.svg
```

Live capture stops on `--duration`, `--packets`, `--until-converged` or Ctrl-C (press twice to force). Development: `pip install -e . pytest hypothesis httpx playwright mypy ruff`, then `pytest`, `mypy` and `ruff check .`. The UI tests use your installed Chromium (or `NETGRAPHER_CHROMIUM`) and are skipped without one. The tests never capture real traffic: they use a fake dumpcap.

## Installation (planned)

```bash
# Install the tool
uv tool install netgrapher        # or: pipx install netgrapher

# Allow live capture without root (Debian / Ubuntu / Kali)
sudo apt install wireshark-common
sudo dpkg-reconfigure wireshark-common   # answer "Yes" to allow non-superusers to capture
sudo usermod -aG wireshark "$USER"       # then log out and back in

# Check that everything is set up
netgrapher doctor
```

netgrapher itself **never needs root**. Only `dumpcap` has capture capabilities, and the probes in v1 use unprivileged sockets.

## Quick start (planned)

```bash
# Listen passively on the default interface for 30 minutes, with the live UI open
netgrapher discover --duration 30m --ui -o office.ngraph

# Analyze an existing capture
netgrapher discover --read incident.pcapng -o incident.ngraph

# Active: scan the authorized ranges (preview the plan first)
netgrapher discover --mode active --cidr 10.10.0.0/22 --cidr 10.20.0.0/24 --dry-run   # preview, sends nothing
netgrapher discover --mode active --cidr 10.10.0.0/22 --cidr 10.20.0.0/24 -o lab.ngraph

# Reactive: probe only what shows up in traffic; stop when nothing new appears for 5 minutes
netgrapher discover --mode reactive -i eth0 --until-converged 5m -w run.pcapng -o net.ngraph

# Open a saved project in the UI
netgrapher ui net.ngraph

# Print a summary and the coverage report
netgrapher info net.ngraph

# Export for other tools
netgrapher export net.ngraph --format graphml -o net.graphml
```

Run `netgrapher discover --help` for all options: scope allow/deny lists, `--allow-public`, rate limits, budget, snaplen, BPF filter, and more.

## How it works (in brief)

```
capture (dumpcap) / pcap file
        → decode packets → extract facts (ARP, DHCP, ICMP, OSPF, TTLs, …)
        → inference rules with confidence scores → L3 graph (routers ↔ subnets ↔ hosts)
        → project file + interactive web UI
  (active/reactive) target planner → rate-limited prober → replies come back through the capture
```

Details are in the [requirements and design document](docs/requirements-and-design.md).

## Privacy

Project files, captures and audit logs contain internal addressing and hostnames. **Treat them as confidential.** Use the anonymized screenshot export when sharing graphs. netgrapher has no telemetry, and the UI loads nothing from the Internet.

## Roadmap

| Version | Highlights |
|---|---|
| 0.1–0.2 | pcap input, core IPv4 inference, project files, export, live capture, `doctor` |
| 0.3–0.4 | Interactive UI, live updates |
| 0.5 | Active and reactive modes |
| 1.0 | Hardening, accuracy measured against lab ground truth |
| 2.x | IPv6, privileged probe helper, merging runs into projects, discovery controls in the UI, macOS |

## Contributing

Contributors and coding agents: start with [docs/development-plan.md](docs/development-plan.md) (status, architecture, known bugs, TODOs) and [AGENTS.md](AGENTS.md).


The project is still in the design phase. Feedback on the [design document](docs/requirements-and-design.md) is welcome.

## License

[MIT](LICENSE).
