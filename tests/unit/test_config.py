import pytest

from netgrapher.config import DiscoveryConfig, Mode


def test_active_large_cidr_needs_force() -> None:
    with pytest.raises(ValueError, match="force-large"):
        DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/8",)).validate()
    DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/8",), force_large=True).validate()


def test_active_small_cidr_ok() -> None:
    DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/16", "192.168.1.0/24")).validate()
