import os
import stat
import sys
from pathlib import Path

import pytest
from synthetic import GW, LAPTOP, office_frames, pcapng_head, pcapng_isb

from netgrapher.capture.hostinfo import (
    HostAddress,
    HostConfig,
    HostInterface,
    HostNeighbor,
    HostRoute,
)
from netgrapher.capture.live import LiveCaptureError, LiveSource
from netgrapher.discover import LiveOptions, Status, run_live

FAKE = Path(__file__).parent.parent / "fake_dumpcap.py"


def fake_host() -> HostConfig:
    return HostConfig(
        hostname="Alice-Laptop",
        interfaces=[
            HostInterface("lo", None, True, True, [HostAddress("127.0.0.1", 8)]),
            HostInterface(
                "eth0",
                "02:00:00:00:00:0a",
                True,
                False,
                [HostAddress(LAPTOP, 24), HostAddress("fe80::1", 64)],
            ),
        ],
        routes=[HostRoute("default", GW, "eth0", 100), HostRoute("10.50.0.0/16", GW, "eth0")],
        neighbors=[HostNeighbor(GW, "02:00:00:00:00:01", "eth0")],
        resolvers=[GW],
        taken_at=1_760_000_000.0,
    )


@pytest.fixture
def fake_dumpcap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    frames = office_frames()
    (tmp_path / "head.bin").write_bytes(pcapng_head([1], [(0, ts, f) for ts, f in frames]))
    (tmp_path / "tail.bin").write_bytes(pcapng_isb({0: 4}))
    wrapper = tmp_path / "dumpcap"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("NETGRAPHER_DUMPCAP", str(wrapper))
    monkeypatch.setenv("FAKE_DUMPCAP_DIR", str(tmp_path))
    return tmp_path


def source(**kwargs) -> LiveSource:  # type: ignore[no-untyped-def]
    return LiveSource(["eth0"], dumpcap=os.environ["NETGRAPHER_DUMPCAP"], **kwargs)


def test_command_line() -> None:
    src = LiveSource(
        ["eth0", "wlan0"], promiscuous=False, bpf_filter="not port 22", dumpcap="/usr/bin/dumpcap"
    )
    assert src.command() == [
        "/usr/bin/dumpcap",
        "-q",
        "-i",
        "eth0",
        "-i",
        "wlan0",
        "-s",
        "512",
        "-B",
        "64",
        "-p",
        "-f",
        "not port 22",
        "-w",
        "-",
    ]


def test_duration_stop_with_tee_and_drops(fake_dumpcap: Path) -> None:
    capture = fake_dumpcap / "out.pcapng"
    statuses: list[Status] = []
    project = run_live(
        source(write_path=capture),
        LiveOptions(duration_s=0.6, tick_s=0.1),
        host_config=fake_host,
        on_status=statuses.append,
    )
    run = project.runs[0]
    assert run["stop_reason"] == "duration"
    assert run["stats"]["packets"] == len(office_frames())
    assert run["stats"]["if_dropped"] == {"0": 4}  # from the ISB written on SIGINT
    expected = (fake_dumpcap / "head.bin").read_bytes() + (fake_dumpcap / "tail.bin").read_bytes()
    assert capture.read_bytes() == expected
    assert statuses and statuses[-1].entities
    assert "-w\n-" in (fake_dumpcap / "args.txt").read_text()


def test_host_config_feeds_inference(fake_dumpcap: Path) -> None:
    project = run_live(source(), LiveOptions(duration_s=0.3, tick_s=0.1), host_config=fake_host)
    g = project.graph
    me = g.entities[f"host:{LAPTOP}"]
    assert me.attrs["is_self"] is True
    assert {"name": "alice-laptop", "source": "hostcfg"} in me.attrs["names"]
    gw = g.entities[f"rtr:{GW}"]
    assert "default-gateway" in gw.attrs["roles"]
    assert any(g.evidence[e].rule == "R-RTR-HOSTCFG" for e in gw.evidence)
    lan = g.entities["net:192.168.1.0/24"]
    assert any(g.evidence[e].rule == "R-SUB-HOSTCFG" for e in lan.evidence)
    routed = g.links[f"lnk:inferred-path:rtr:{GW}|net:10.50.0.0/16"]
    assert routed.attrs["basis"] == ["route"]
    assert g.entities["net:10.50.0.0/16"].attrs["kind"] == "remote"
    hostcfg = project.runs[0]["hostcfg"]
    assert hostcfg["start"]["hostname"] == "Alice-Laptop"


def test_packet_limit_is_exact(fake_dumpcap: Path) -> None:
    project = run_live(source(), LiveOptions(packets=3, tick_s=0.1), host_config=fake_host)
    assert project.runs[0]["stop_reason"] == "packet-count"
    assert project.runs[0]["stats"]["packets"] == 3


def test_converged(fake_dumpcap: Path) -> None:
    project = run_live(
        source(), LiveOptions(until_converged_s=0.4, tick_s=0.1), host_config=fake_host
    )
    assert project.runs[0]["stop_reason"] == "converged"


def test_capture_that_ends_by_itself(fake_dumpcap: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_DUMPCAP_MODE", "eof")
    project = run_live(source(), LiveOptions(tick_s=0.1), host_config=fake_host)
    assert project.runs[0]["stop_reason"] == "capture-ended"


def test_dumpcap_failure_is_reported(fake_dumpcap: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_DUMPCAP_MODE", "fail")
    with pytest.raises(LiveCaptureError, match="permission"):
        run_live(source(), LiveOptions(tick_s=0.1), host_config=fake_host)


def test_missing_dumpcap() -> None:
    with pytest.raises(LiveCaptureError, match="cannot start"):
        run_live(source(), LiveOptions(tick_s=0.1), host_config=fake_host)


def test_cli_live_run(fake_dumpcap: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from netgrapher import discover
    from netgrapher.cli import app

    monkeypatch.setattr(discover, "read_host_config", fake_host)
    out = fake_dumpcap / "live.ngraph"
    result = CliRunner().invoke(
        app, ["discover", "-i", "eth0", "--duration", "0.5", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Capturing passively on eth0 for 0.5s" in result.output


def test_ipv6_host_configuration_is_ignored_until_v2(fake_dumpcap: Path) -> None:
    def host() -> HostConfig:
        config = fake_host()
        config.resolvers = ["fe80::1%wlan0", "2001:db8::53", GW]
        config.neighbors.append(HostNeighbor("fe80::2", "02:00:00:00:00:02", "eth0"))
        config.routes.append(HostRoute("default", "fe80::1", "eth0"))
        return config

    project = run_live(source(), LiveOptions(duration_s=0.3, tick_s=0.1), host_config=host)
    assert not any(":" in eid.split(":", 1)[1] for eid in project.graph.entities)


def test_on_graph_receives_intermediate_graphs(fake_dumpcap: Path) -> None:
    graphs = []
    run_live(
        source(),
        LiveOptions(duration_s=0.5, tick_s=0.1),
        host_config=fake_host,
        on_graph=graphs.append,
    )
    assert graphs and "rtr:192.168.1.1" in graphs[-1].entities


def test_cli_live_run_with_ui(fake_dumpcap: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from netgrapher import discover
    from netgrapher.cli import app
    from netgrapher.project.store import load
    from netgrapher.server import app as server_app

    monkeypatch.setattr(discover, "read_host_config", fake_host)
    monkeypatch.setattr(server_app, "wait_for_interrupt", lambda: None)
    out = fake_dumpcap / "live-ui.ngraph"
    result = CliRunner().invoke(
        app, ["discover", "-i", "eth0", "--duration", "0.5", "--ui", "--no-browser", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "netgrapher UI: http://127.0.0.1:" in result.output
    assert "The UI is still running" in result.output
    assert "rtr:192.168.1.1" in load(out).graph.entities
