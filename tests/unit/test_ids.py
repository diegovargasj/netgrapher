import pytest

from netgrapher.graph.ids import AliasTable, host_id, link_id, router_id, subnet_id


def test_id_formats_are_normalized() -> None:
    assert subnet_id("10.0.1.7/24") == "net:10.0.1.0/24"
    assert host_id("10.0.1.5") == "host:10.0.1.5"
    assert router_id("10.0.1.1") == "rtr:10.0.1.1"
    assert link_id("interface", "rtr:10.0.1.1", "net:10.0.1.0/24") == (
        "lnk:interface:rtr:10.0.1.1|net:10.0.1.0/24"
    )


def test_alias_resolution_is_transitive() -> None:
    aliases = AliasTable()
    aliases.add("host:10.0.1.1", "rtr:10.0.1.1")
    aliases.add("rtr:10.0.1.1", "rtr:10.0.0.1")
    assert aliases.resolve("host:10.0.1.1") == "rtr:10.0.0.1"
    assert aliases.resolve("net:10.0.1.0/24") == "net:10.0.1.0/24"


def test_alias_cycle_rejected() -> None:
    aliases = AliasTable({"a": "b"})
    with pytest.raises(ValueError, match="cycle"):
        aliases.add("b", "a")
