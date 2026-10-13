"""Browser test of live updates (FR-UI-16): incremental changes, stable positions, highlighting,
pause/resume, edits during a run, and the end of the run."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.test_ui_smoke import CHROMIUM, playwright_api

pytestmark = pytest.mark.skipif(CHROMIUM is None, reason="no system Chromium found")
TOKEN = "live-smoke"


@pytest.fixture
def live(tmp_path: Path) -> Iterator[tuple[str, Any]]:
    import uvicorn

    from netgrapher.server.app import create_app
    from netgrapher.server.live import LiveSession
    from netgrapher.server.state import AppState

    state = AppState()
    session = LiveSession(state)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    hosts = {f"127.0.0.1:{port}"}
    srv = uvicorn.Server(
        uvicorn.Config(
            create_app(state, TOKEN, lambda: hosts),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", session
    srv.should_exit = True
    thread.join(timeout=5)


def leaf_positions(page: Any) -> dict[str, dict[str, float]]:
    return page.evaluate(
        "() => Object.fromEntries(window.netgrapher.cy().nodes(':childless')"
        ".map(n => [n.id(), n.position()]))"
    )


def test_live_updates(live: tuple[str, Any], tmp_path: Path) -> None:
    from synthetic import LAPTOP, LAPTOP_MAC, eth, graph_from_frames, office_frames, tcp

    from netgrapher.project.format import Project
    from netgrapher.project.store import load

    url, session = live
    frames = [f for _, f in office_frames()]
    newcomer = [
        eth(LAPTOP_MAC, "02:00:00:00:00:21", tcp(LAPTOP, "192.168.1.33", 40100, 22)),
        eth("02:00:00:00:00:21", LAPTOP_MAC, tcp("192.168.1.33", LAPTOP, 22, 40100)),
    ]
    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        page = browser.new_context(
            viewport={"width": 1400, "height": 850}, bypass_csp=True
        ).new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.goto(f"{url}/#token={TOKEN}")
        page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 0")
        page.wait_for_selector("#st-live:not([hidden])")

        session.publish_graph(graph_from_frames(frames[:8]))
        page.wait_for_function("window.netgrapher.cy().nodes().length > 0")
        before = leaf_positions(page)

        session.publish_graph(graph_from_frames(frames))
        page.wait_for_function("window.netgrapher.cy().nodes().length === 10")
        after = leaf_positions(page)
        for node_id, pos in before.items():
            if node_id in after:
                assert after[node_id] == pytest.approx(pos, abs=0.01), node_id
        fresh = page.evaluate("() => window.netgrapher.cy().nodes('.fresh').map(n => n.id())")
        added = set(after) - set(before)
        assert added and added <= set(fresh)  # every new node is highlighted

        page.get_by_role("button", name="Pause updates").click()
        session.publish_graph(graph_from_frames(frames + newcomer))
        page.wait_for_function("window.netgrapher.pending() === 1")
        assert page.evaluate("window.netgrapher.cy().nodes().length") == 10
        page.get_by_role("button", name="Resume updates (1)").click()
        page.wait_for_function(
            "window.netgrapher.cy().getElementById('host:192.168.1.33').nonempty()"
        )
        assert (
            page.evaluate(
                "window.netgrapher.cy().getElementById('host:192.168.1.33').parent().id()"
            )
            == "net:192.168.1.0/24"
        )

        box = page.locator("#cy").bounding_box()
        pos = page.evaluate(
            "() => window.netgrapher.cy().getElementById('rtr:192.168.1.1').renderedPosition()"
        )
        page.mouse.click(box["x"] + pos["x"], box["y"] + pos["y"])
        page.locator(".label-edit").fill("Core GW")
        page.locator(".label-edit").press("Enter")
        page.wait_for_function(
            "window.netgrapher.state.annotations['rtr:192.168.1.1']?.label === 'Core GW'"
        )

        out = tmp_path / "live.ngraph"
        session.finish(Project(graph=graph_from_frames(frames + newcomer)), out)
        page.wait_for_function("window.netgrapher.state.doc.can_save === true")
        assert page.locator("#st-live").inner_text() == "capture finished"
        assert page.locator("#btn-pause").is_hidden()
        browser.close()
    assert load(out).annotations["rtr:192.168.1.1"]["label"] == "Core GW"
    assert errors == [], errors


def test_subnet_hosts_are_gridded_not_a_strip(live: tuple[str, Any]) -> None:
    """Regression: hosts in a subnet must lay out as a grid, not a single sideways row."""
    from netgrapher.graph.model import Entity, EntityType, Graph, Link, LinkType

    url, session = live

    def lan_graph(n: int) -> Graph:
        subnet_id = "net:192.168.1.0/24"
        entities = {
            subnet_id: Entity(
                subnet_id, EntityType.SUBNET, 1.0, {"prefix": "192.168.1.0/24", "kind": "local"}, []
            ),
        }
        links = {}
        for i in range(10, 10 + n):
            hid = f"host:192.168.1.{i}"
            entities[hid] = Entity(
                hid, EntityType.HOST, 1.0, {"ip": f"192.168.1.{i}", "subnet_id": subnet_id}, []
            )
            links[f"lnk:member:{hid}|{subnet_id}"] = Link(
                f"lnk:member:{hid}|{subnet_id}", LinkType.MEMBER, hid, subnet_id, 1.0
            )
        return Graph(entities, links, {})

    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        page = browser.new_context(
            viewport={"width": 1400, "height": 850}, bypass_csp=True
        ).new_page()
        page.goto(f"{url}/#token={TOKEN}")
        page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 0")
        session.publish_graph(lan_graph(3))
        page.wait_for_function("window.netgrapher.cy().nodes(':childless').length === 3")
        session.publish_graph(lan_graph(15))  # grow -> new hosts must grid, not strip
        page.wait_for_function("window.netgrapher.cy().nodes(':childless').length === 15")

        positions = page.evaluate(
            "() => window.netgrapher.cy().nodes('[type = \"host\"]')"
            ".map(n => ({x: Math.round(n.position('x')), y: Math.round(n.position('y'))}))"
        )
        rows = {p["y"] for p in positions}
        cols = {p["x"] for p in positions}
        assert len(rows) >= 2, f"hosts are in a single row (a strip): {positions}"
        assert len(cols) <= 6, f"more columns than the grid width: {sorted(cols)}"
        # Rows should be evenly spaced (a real grid), not scattered.
        assert len(positions) == 15
        browser.close()


def test_hosts_are_ordered_by_ip_and_stable(live: tuple[str, Any]) -> None:
    """Hosts in a subnet lay out in strict numeric-IP order, and existing hosts don't move when
    a higher-IP host is added."""
    from netgrapher.graph.model import Entity, EntityType, Graph, Link, LinkType

    url, session = live

    def lan(octets: list[int]) -> Graph:
        sid = "net:10.0.0.0/24"
        entities = {
            sid: Entity(sid, EntityType.SUBNET, 1.0, {"prefix": "10.0.0.0/24", "kind": "local"}, [])
        }
        links = {}
        for i in octets:
            hid = f"host:10.0.0.{i}"
            entities[hid] = Entity(
                hid, EntityType.HOST, 1.0, {"ip": f"10.0.0.{i}", "subnet_id": sid}, []
            )
            links[f"lnk:member:{hid}|{sid}"] = Link(
                f"lnk:member:{hid}|{sid}", LinkType.MEMBER, hid, sid, 1.0
            )
        return Graph(entities, links, {})

    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        page = browser.new_context(
            viewport={"width": 1200, "height": 800}, bypass_csp=True
        ).new_page()
        page.goto(f"{url}/#token={TOKEN}")
        page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 0")
        session.publish_graph(lan([30, 2, 10, 100, 5, 20, 1]))  # arrive out of order
        page.wait_for_function("window.netgrapher.cy().nodes(':childless').length === 7")

        def host_positions() -> dict[str, dict[str, float]]:
            return page.evaluate(
                "() => Object.fromEntries(window.netgrapher.cy().nodes('[type=\"host\"]')"
                ".map(n => [n.data('id'), n.position()]))"
            )

        pos = host_positions()
        # In reading order (sort by y then x) the IPs must be ascending.
        ordered = sorted(pos.items(), key=lambda kv: (round(kv[1]["y"]), round(kv[1]["x"])))
        octets = [int(hid.split(".")[-1]) for hid, _ in ordered]
        assert octets == sorted(octets), octets

        # Adding a higher-IP host must not move the existing ones.
        session.publish_graph(lan([30, 2, 10, 100, 5, 20, 1, 200]))
        page.wait_for_function(
            "window.netgrapher.cy().getElementById('host:10.0.0.200').nonempty()"
        )
        after = host_positions()
        for hid, before_pos in pos.items():
            assert after[hid] == pytest.approx(before_pos, abs=0.01), hid
        browser.close()


def test_new_networks_do_not_overlap(live: tuple[str, Any]) -> None:
    """Newly discovered networks must claim free space, not land on top of existing ones."""
    from netgrapher.graph.model import Entity, EntityType, Graph, Link, LinkType

    url, session = live

    def build(remote_prefixes: list[str]) -> Graph:
        entities = {
            "rtr:10.0.0.1": Entity(
                "rtr:10.0.0.1",
                EntityType.ROUTER,
                1.0,
                {
                    "interfaces": [
                        {"ip": "10.0.0.1", "subnet": None, "virtual": False, "confidence": 1.0}
                    ]
                },
                [],
            ),
            "net:10.0.0.0/24": Entity(
                "net:10.0.0.0/24",
                EntityType.SUBNET,
                1.0,
                {"prefix": "10.0.0.0/24", "kind": "local"},
                [],
            ),
        }
        links = {}
        for prefix in remote_prefixes:
            sid = f"net:{prefix}"
            entities[sid] = Entity(
                sid, EntityType.SUBNET, 1.0, {"prefix": prefix, "kind": "remote"}, []
            )
            base = prefix.split("/")[0].rsplit(".", 1)[0]
            for j in range(2, 6):
                hid = f"host:{base}.{j}"
                entities[hid] = Entity(
                    hid, EntityType.HOST, 1.0, {"ip": f"{base}.{j}", "subnet_id": sid}, []
                )
                links[f"lnk:member:{hid}|{sid}"] = Link(
                    f"lnk:member:{hid}|{sid}", LinkType.MEMBER, hid, sid, 1.0
                )
            links[f"lnk:p:{prefix}"] = Link(
                f"lnk:inferred-path:rtr:10.0.0.1|{sid}",
                LinkType.INFERRED_PATH,
                "rtr:10.0.0.1",
                sid,
                0.9,
                {"hops": 2},
            )
        return Graph(entities, links, {})

    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        page = browser.new_context(
            viewport={"width": 1300, "height": 850}, bypass_csp=True
        ).new_page()
        page.goto(f"{url}/#token={TOKEN}")
        page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 0")
        session.publish_graph(build([]))
        page.wait_for_function(
            "window.netgrapher.cy().getElementById('net:10.0.0.0/24').nonempty()"
        )
        # Discover several remote networks at once.
        session.publish_graph(
            build(["10.20.0.0/24", "10.30.0.0/24", "10.40.0.0/24", "10.50.0.0/24"])
        )
        page.wait_for_function(
            "window.netgrapher.cy().getElementById('net:10.50.0.0/24').nonempty()"
        )

        boxes = page.evaluate(
            "() => window.netgrapher.cy().nodes('[type=\"subnet\"]').map(n => {"
            "const b = n.boundingBox({includeLabels: true}); "
            "return {id: n.id(), x1: b.x1, y1: b.y1, x2: b.x2, y2: b.y2};})"
        )

        def overlap(a: dict, b: dict) -> bool:
            return not (
                a["x2"] <= b["x1"] or b["x2"] <= a["x1"] or a["y2"] <= b["y1"] or b["y2"] <= a["y1"]
            )

        pairs = [
            (a["id"], b["id"]) for i, a in enumerate(boxes) for b in boxes[i + 1 :] if overlap(a, b)
        ]
        assert pairs == [], f"overlapping networks: {pairs}"
        assert len(boxes) == 5
        browser.close()
