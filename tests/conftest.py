import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def _no_real_capture_or_host_access(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Tests must never capture real traffic, read this machine's network configuration, or
    write to the user's configuration directory.

    Tests that exercise live capture point NETGRAPHER_DUMPCAP at a fake dumpcap and pass a
    fake host configuration explicitly.
    """
    from netgrapher import cli, discover
    from netgrapher.capture import hostinfo

    monkeypatch.setenv("NETGRAPHER_DUMPCAP", "/nonexistent/dumpcap-disabled-in-tests")
    # The UI's recent-projects list lives under XDG_CONFIG_HOME: keep it out of the real home.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))

    def forbidden() -> hostinfo.HostConfig:
        raise AssertionError("test tried to read the real host configuration")

    monkeypatch.setattr(hostinfo, "read_host_config", forbidden)
    monkeypatch.setattr(discover, "read_host_config", forbidden)
    monkeypatch.setattr(cli, "read_host_config", forbidden)
