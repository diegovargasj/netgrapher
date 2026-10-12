import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netgrapher import __version__
from netgrapher.cli import EXIT_USAGE, app

runner = CliRunner()


@pytest.fixture
def fake_dumpcap_cli(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    import stat
    import sys

    from synthetic import office_frames, pcapng_head, pcapng_isb

    frames = office_frames()
    (tmp_path / "head.bin").write_bytes(pcapng_head([1], [(0, ts, f) for ts, f in frames]))
    (tmp_path / "tail.bin").write_bytes(pcapng_isb({0: 0}))
    wrapper = tmp_path / "dumpcap"
    fake = Path(__file__).parent.parent / "fake_dumpcap.py"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("NETGRAPHER_DUMPCAP", str(wrapper))
    monkeypatch.setenv("FAKE_DUMPCAP_DIR", str(tmp_path))
    return tmp_path


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


def test_probing_modes_and_ui_not_yet_available() -> None:
    assert runner.invoke(app, ["discover", "--mode", "reactive"]).exit_code == 1
    assert runner.invoke(app, ["discover", "--read", "x.pcap", "--ui"]).exit_code == 1


def test_live_options_rejected_for_files() -> None:
    result = runner.invoke(app, ["discover", "--read", "x.pcap", "--duration", "5m"])
    assert result.exit_code == EXIT_USAGE


def test_invalid_duration() -> None:
    result = runner.invoke(app, ["discover", "-i", "eth0", "--duration", "soon"])
    assert result.exit_code == EXIT_USAGE


def test_bad_inputs(tmp_path: Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture")
    assert runner.invoke(app, ["discover", "--read", str(junk)]).exit_code == 1
    assert runner.invoke(app, ["info", str(junk)]).exit_code == 1


def test_active_dry_run_sends_nothing() -> None:
    result = runner.invoke(
        app, ["discover", "--mode", "active", "--cidr", "10.10.0.0/29", "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert "Dry run:" in result.output and "icmp-echo" in result.output
    assert "10.10.0.1" in result.output


def test_read_rejected_with_active() -> None:
    result = runner.invoke(
        app, ["discover", "--read", "x.pcap", "--mode", "active", "--cidr", "10.0.0.0/24"]
    )
    assert result.exit_code == EXIT_USAGE


def test_cli_reactive_run(fake_dumpcap_cli, monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A reactive run through the CLI with fakes produces a project and an audit log."""
    import netgrapher.cli as cli_mod
    import netgrapher.discovery.controller as controller
    from netgrapher import discover
    from tests.fake_transport import FakeTransport
    from tests.unit.test_live import fake_host

    monkeypatch.setattr(cli_mod, "read_host_config", fake_host)
    monkeypatch.setattr(discover, "read_host_config", fake_host)
    monkeypatch.setattr(controller, "SocketTransport", lambda: FakeTransport())
    out = tmp_path / "reactive.ngraph"
    result = runner.invoke(
        app, ["discover", "--mode", "reactive", "-i", "eth0", "--duration", "0.6", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "Reactive discovery on eth0" in result.output
    assert "authorized to test" in result.output
    assert out.exists()
    assert (tmp_path / "reactive.audit.jsonl").exists()
