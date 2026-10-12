from typer.testing import CliRunner

from netgrapher import __version__
from netgrapher.cli import EXIT_USAGE, app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("discover", "ui", "export", "info", "doctor"):
        assert command in result.output


def test_active_requires_cidr() -> None:
    result = runner.invoke(app, ["discover", "--mode", "active"])
    assert result.exit_code == EXIT_USAGE


def test_cidr_rejected_outside_active() -> None:
    result = runner.invoke(app, ["discover", "--mode", "reactive", "--cidr", "10.0.0.0/24"])
    assert result.exit_code == EXIT_USAGE


def test_read_requires_passive() -> None:
    result = runner.invoke(app, ["discover", "--mode", "reactive", "--read", "x.pcap"])
    assert result.exit_code == EXIT_USAGE
