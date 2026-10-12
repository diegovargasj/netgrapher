import pytest

from netgrapher.config import DiscoveryConfig, Mode


def test_active_large_cidr_needs_force() -> None:
    with pytest.raises(ValueError, match="force-large"):
        DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/8",)).validate()
    DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/8",), force_large=True).validate()


def test_active_small_cidr_ok() -> None:
    DiscoveryConfig(mode=Mode.ACTIVE, cidrs=("10.0.0.0/16", "192.168.1.0/24")).validate()


def test_parse_duration() -> None:
    from netgrapher.config import parse_duration

    assert parse_duration("90") == 90
    assert parse_duration("45s") == 45
    assert parse_duration("30m") == 1800
    assert parse_duration("1h30m") == 5400
    assert parse_duration("0.5") == 0.5
    for bad in ("", "soon", "0", "-5", "5x"):
        with pytest.raises(ValueError):
            parse_duration(bad)
