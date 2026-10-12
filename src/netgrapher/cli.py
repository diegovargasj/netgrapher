"""Command-line interface. See design §12."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from netgrapher import __version__
from netgrapher.capture.hostinfo import read_host_config
from netgrapher.capture.live import LiveCaptureError, LiveSource
from netgrapher.capture.source import CaptureFormatError
from netgrapher.config import (
    CaptureConfig,
    DiscoveryConfig,
    Mode,
    ProbeConfig,
    ScopeConfig,
    parse_duration,
)
from netgrapher.discover import LiveOptions, Status, run_file, run_live
from netgrapher.export import ExportFormat, export_project
from netgrapher.project.format import Project
from netgrapher.project.store import ProjectError, load, save
from netgrapher.report import build_report

app = typer.Typer(
    name="netgrapher",
    help="Best-effort L3 network topology discovery and interactive graphing.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3


def _load(path: Path) -> Project:
    try:
        return load(path)
    except ProjectError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_RUNTIME) from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"netgrapher {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    pass


@app.command()
def discover(
    mode: Annotated[Mode, typer.Option(help="Discovery mode.")] = Mode.PASSIVE,
    interface: Annotated[
        list[str] | None,
        typer.Option("-i", "--interface", help="Capture interface (repeatable)."),
    ] = None,
    read: Annotated[
        Path | None, typer.Option("-r", "--read", help="pcap/pcapng input (passive only).")
    ] = None,
    cidr: Annotated[
        list[str] | None, typer.Option(help="Target CIDR for active mode (repeatable).")
    ] = None,
    scope: Annotated[
        list[str] | None, typer.Option(help="Reactive scope allow-list CIDR (repeatable).")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option(help="CIDR never to probe (repeatable).")
    ] = None,
    allow_public: Annotated[
        bool, typer.Option(help="Reactive: allow limited traceroutes to public prefixes.")
    ] = False,
    max_generation: Annotated[int, typer.Option(help="Reactive generation limit.")] = 2,
    budget: Annotated[int, typer.Option(help="Total probe budget.")] = 10_000,
    rate: Annotated[float, typer.Option(help="Global probe rate (packets/s).")] = 50.0,
    rate_per_host: Annotated[float, typer.Option(help="Per-destination probe rate.")] = 5.0,
    force_large: Annotated[bool, typer.Option(help="Allow active CIDRs larger than /16.")] = False,
    dry_run: Annotated[bool, typer.Option(help="Print the probe plan; send nothing.")] = False,
    duration: Annotated[str | None, typer.Option(help="Stop after this long (e.g. 30m).")] = None,
    packets: Annotated[int | None, typer.Option(help="Stop after N packets.")] = None,
    until_converged: Annotated[
        str | None, typer.Option(help="Stop when nothing new appears for this long.")
    ] = None,
    snaplen: Annotated[int, typer.Option("-s", "--snaplen", help="Capture snaplen.")] = 512,
    bpf_filter: Annotated[
        str | None, typer.Option("-f", "--filter", help="Extra BPF capture filter.")
    ] = None,
    no_promisc: Annotated[bool, typer.Option(help="Disable promiscuous mode.")] = False,
    write: Annotated[
        Path | None, typer.Option("-w", "--write", help="Save the raw capture (pcapng).")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("-o", "--output", help="Project file (.ngraph).")
    ] = None,
    asn_db: Annotated[Path | None, typer.Option(help="Offline IP-to-ASN database.")] = None,
    flows: Annotated[bool, typer.Option(help="Record the flow overlay.")] = True,
    ui: Annotated[bool, typer.Option(help="Serve the live UI during the run.")] = False,
    port: Annotated[int, typer.Option(help="UI port.")] = 0,
    no_browser: Annotated[bool, typer.Option(help="Do not open a browser.")] = False,
) -> None:
    """Discover the L3 topology from live traffic or a capture file."""
    if read is not None and mode is not Mode.PASSIVE:
        typer.echo("--read is only valid with --mode passive", err=True)
        raise typer.Exit(EXIT_USAGE)

    config = DiscoveryConfig(
        mode=mode,
        cidrs=tuple(cidr or ()),
        capture=CaptureConfig(
            interfaces=tuple(interface or ()),
            snaplen=snaplen,
            promiscuous=not no_promisc,
            bpf_filter=bpf_filter,
        ),
        probes=ProbeConfig(
            rate_pps=rate,
            rate_per_host_pps=rate_per_host,
            budget=budget,
            max_generation=max_generation,
        ),
        scope=ScopeConfig(
            allow=tuple(scope) if scope else ScopeConfig().allow,
            deny=tuple(exclude or ()),
            allow_public=allow_public,
        ),
        force_large=force_large,
        dry_run=dry_run,
    )
    try:
        config.validate()
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    not_yet = [
        (mode is not Mode.PASSIVE, f"--mode {mode}", "0.5"),
        (ui, "--ui", "0.4"),
        (asn_db is not None, "--asn-db", "a later milestone"),
    ]
    for active, what, milestone in not_yet:
        if active:
            typer.echo(f"{what} is not implemented yet (milestone {milestone})", err=True)
            raise typer.Exit(EXIT_RUNTIME)
    if read is not None and (duration or packets or until_converged or write or interface):
        typer.echo("--duration/--packets/--until-converged/-w/-i apply to live capture", err=True)
        raise typer.Exit(EXIT_USAGE)
    try:
        options = LiveOptions(
            duration_s=parse_duration(duration) if duration else None,
            packets=packets,
            until_converged_s=parse_duration(until_converged) if until_converged else None,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    output = output or Path(f"netgrapher-{datetime.now():%Y%m%d-%H%M%S}.ngraph")
    status = _StatusPrinter()
    if read is not None:
        try:
            project = run_file(read, record_flows=flows, on_status=status)
        except (OSError, CaptureFormatError) as exc:
            status.done()
            typer.echo(f"cannot read {read}: {exc}", err=True)
            raise typer.Exit(EXIT_RUNTIME) from exc
    else:
        project = _discover_live(config, options, write, flows, status)
    status.done()
    save(project, output)
    typer.echo(build_report(project))
    typer.echo(f"\nProject saved to {output}")


def _discover_live(
    config: DiscoveryConfig,
    options: LiveOptions,
    write: Path | None,
    flows: bool,
    status: _StatusPrinter,
) -> Project:
    interfaces = list(config.capture.interfaces)
    if not interfaces:
        default = read_host_config().default_interface()
        if default is None:
            typer.echo("no default route; choose an interface with -i", err=True)
            raise typer.Exit(EXIT_USAGE)
        interfaces = [default]
    source = LiveSource(
        interfaces,
        snaplen=config.capture.snaplen,
        buffer_mib=config.capture.buffer_mib,
        promiscuous=config.capture.promiscuous,
        bpf_filter=config.capture.bpf_filter,
        write_path=write,
    )
    limits = [
        f"for {options.duration_s:g}s" if options.duration_s else "",
        f"up to {options.packets} packets" if options.packets else "",
        f"until nothing new for {options.until_converged_s:g}s"
        if options.until_converged_s
        else "",
    ]
    limit_text = ", ".join(x for x in limits if x) or "until Ctrl-C"
    typer.echo(f"Capturing passively on {', '.join(interfaces)} {limit_text}.", err=True)
    try:
        return run_live(
            source, options, record_flows=flows, on_status=status, on_message=status.message
        )
    except LiveCaptureError as exc:
        status.done()
        typer.echo(str(exc), err=True)
        typer.echo("Run `netgrapher doctor` to check your setup.", err=True)
        raise typer.Exit(EXIT_ENVIRONMENT) from exc


class _StatusPrinter:
    """Progress on stderr: one updating line on a terminal, occasional lines otherwise."""

    def __init__(self) -> None:
        self._tty = sys.stderr.isatty()
        self._last_plain = 0.0
        self._dirty = False

    def __call__(self, st: Status) -> None:
        parts = [
            f"{int(st.elapsed) // 60:02d}:{int(st.elapsed) % 60:02d}",
            f"{st.packets:,} packets",
        ]
        if st.fraction is not None:
            parts.append(f"{st.fraction:.0%} of file")
        if st.entities is not None:
            parts.append(f"{st.entities} entities")
        if st.stopping:
            parts.append(f"stopping ({st.stopping})")
        line = " · ".join(parts)
        if self._tty:
            sys.stderr.write("\r\033[K" + line)
            sys.stderr.flush()
            self._dirty = True
        elif st.elapsed - self._last_plain >= 10:
            print(line, file=sys.stderr)
            self._last_plain = st.elapsed

    def message(self, text: str) -> None:
        self.done()
        print(text, file=sys.stderr)

    def done(self) -> None:
        if self._dirty:
            sys.stderr.write("\n")
            self._dirty = False


@app.command("ui")
def ui_command(
    project: Annotated[Path | None, typer.Argument(help="Project file to open.")] = None,
    port: Annotated[int, typer.Option(help="UI port.")] = 0,
    no_browser: Annotated[bool, typer.Option(help="Do not open a browser.")] = False,
) -> None:
    """Open the interactive UI, optionally with a saved project."""
    from netgrapher.server.app import serve
    from netgrapher.server.state import AppState

    state = AppState()
    if project is not None:
        state.open(_load(project), project)

    def ready(url: str) -> None:
        typer.echo(f"netgrapher UI: {url}")
        typer.echo("Only this machine can connect. Press Ctrl-C to stop.")

    serve(state, port=port, open_browser=not no_browser, on_ready=ready)


@app.command()
def export(
    project: Annotated[Path, typer.Argument(help="Project file (.ngraph).")],
    format: Annotated[ExportFormat, typer.Option("--format", help="Output format.")],
    output: Annotated[Path | None, typer.Option("-o", "--output", help="Output file.")] = None,
    include_hidden: Annotated[bool, typer.Option(help="Include hidden items.")] = False,
) -> None:
    """Export a project to GraphML, GEXF, JSON or DOT."""
    text = export_project(_load(project), format, include_hidden=include_hidden)
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.write_text(text, encoding="utf-8")


@app.command()
def info(project: Annotated[Path, typer.Argument(help="Project file (.ngraph).")]) -> None:
    """Print a project summary and its coverage report."""
    typer.echo(build_report(_load(project)))


@app.command()
def doctor() -> None:
    """Check the environment (dumpcap, capabilities, ping sockets, interfaces)."""
    from netgrapher.doctor import Level, run_checks

    checks = run_checks()
    for check in checks:
        typer.echo(f"[{check.level}] {check.message}")
        if check.fix and check.level is not Level.OK:
            typer.echo(f"       fix: {check.fix}")
    if any(c.level is Level.FAIL for c in checks):
        raise typer.Exit(EXIT_ENVIRONMENT)
