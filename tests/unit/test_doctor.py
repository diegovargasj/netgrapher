import os
import struct
from pathlib import Path

from netgrapher.capture.hostinfo import HostConfig, HostInterface, HostRoute
from netgrapher.doctor import (
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    Level,
    check_dumpcap,
    check_interfaces,
    check_ping_sockets,
    permitted_capabilities,
)


def test_permitted_capabilities_v2_xattr() -> None:
    permitted = (1 << CAP_NET_RAW) | (1 << CAP_NET_ADMIN)
    xattr = struct.pack("<IIIII", 0x02000001, permitted, 0, 0, 0)
    assert permitted_capabilities(xattr) == {CAP_NET_ADMIN, CAP_NET_RAW}
    assert permitted_capabilities(b"") == set()


def test_dumpcap_missing_or_not_executable(tmp_path: Path) -> None:
    assert check_dumpcap("/nonexistent/dumpcap")[0].level is Level.FAIL
    assert check_dumpcap(None)[0].level is Level.FAIL  # NETGRAPHER_DUMPCAP points nowhere
    fake = tmp_path / "dumpcap"
    fake.write_text("")
    os.chmod(fake, 0o644)
    checks = check_dumpcap(str(fake), euid=1000)
    assert checks[-1].level is Level.FAIL and "wireshark" in (checks[-1].fix or "")


def test_dumpcap_without_capabilities(tmp_path: Path) -> None:
    fake = tmp_path / "dumpcap"
    fake.write_text("")
    os.chmod(fake, 0o755)
    checks = check_dumpcap(str(fake), euid=1000)
    assert checks[-1].level is Level.FAIL and "setcap" in (checks[-1].fix or "")
    assert check_dumpcap(str(fake), euid=0)[-1].level is Level.WARN


def test_ping_sockets() -> None:
    assert check_ping_sockets("0 2147483647", [1000])[0].level is Level.OK
    assert check_ping_sockets("1 0", [1000])[0].level is Level.WARN


def test_interfaces() -> None:
    config = HostConfig(
        interfaces=[HostInterface("eth0", "02:00:00:00:00:01", True, False)],
        routes=[HostRoute("default", "10.0.0.1", "eth0")],
    )
    levels = [c.level for c in check_interfaces(config)]
    assert levels == [Level.OK, Level.OK]
    assert check_interfaces(HostConfig())[0].level is Level.FAIL
