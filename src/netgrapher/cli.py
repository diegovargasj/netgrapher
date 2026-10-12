"""Command-line interface. See design §12."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from netgrapher import __version__
from netgrapher.config import (
    CaptureConfig,
    DiscoveryConfig,
    Mode,
    ProbeConfig,
    ScopeConfig,
)

app = typer.Typer(
    name="netgrapher",
    help="Best-effort L3 network topology discovery and interactive graphing.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3


class ExportFormat(StrEnum):
    GRAPHML = "graphml"
    GEXF = "gexf"
    JSON = "json"
    DOT = "dot"


def _not_implemented(command: str) -> NoReturn:
    typer.echo(f"netgrapher {command}: not implemented yet", err=True)
    raise typer.Exit(EXIT_RUNTIME)


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

    _not_implemented("discover")


@app.command("ui")
def ui_command(
    project: Annotated[Path | None, typer.Argument(help="Project file to open.")] = None,
    port: Annotated[int, typer.Option(help="UI port.")] = 0,
    no_browser: Annotated[bool, typer.Option(help="Do not open a browser.")] = False,
) -> None:
    """Open the interactive UI, optionally with a saved project."""
    _not_implemented("ui")


@app.command()
def export(
    project: Annotated[Path, typer.Argument(help="Project file (.ngraph).")],
    format: Annotated[ExportFormat, typer.Option("--format", help="Output format.")],
    output: Annotated[Path | None, typer.Option("-o", "--output", help="Output file.")] = None,
    include_hidden: Annotated[bool, typer.Option(help="Include hidden items.")] = False,
) -> None:
    """Export a project to GraphML, GEXF, JSON or DOT."""
    _not_implemented("export")


@app.command()
def info(project: Annotated[Path, typer.Argument(help="Project file (.ngraph).")]) -> None:
    """Print a project summary and its coverage report."""
    _not_implemented("info")


@app.command()
def doctor() -> None:
    """Check the environment (dumpcap, capabilities, ping sockets, interfaces)."""
    _not_implemented("doctor")
