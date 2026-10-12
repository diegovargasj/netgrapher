import json
from pathlib import Path

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


def test_discover_read_info_and_export(tmp_path: Path) -> None:
    from synthetic import office_frames, write_pcap

    pcap, project, out = tmp_path / "o.pcap", tmp_path / "o.ngraph", tmp_path / "o.json"
    write_pcap(pcap, office_frames())
    result = runner.invoke(app, ["discover", "--read", str(pcap), "-o", str(project)])
    assert result.exit_code == 0, result.output
    assert "3 subnets, 2 routers" in result.output
    result = runner.invoke(app, ["info", str(project)])
    assert result.exit_code == 0 and "Gaps" in result.output
    result = runner.invoke(app, ["export", str(project), "--format", "json", "-o", str(out)])
    assert result.exit_code == 0
    assert any(n["id"] == "rtr:192.168.1.1" for n in json.loads(out.read_text())["nodes"])


def test_live_capture_not_yet_available() -> None:
    result = runner.invoke(app, ["discover"])
    assert result.exit_code == 1


def test_bad_inputs(tmp_path: Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture")
    assert runner.invoke(app, ["discover", "--read", str(junk)]).exit_code == 1
    assert runner.invoke(app, ["info", str(junk)]).exit_code == 1
