"""Browser smoke tests for the UI (design §15): open, rename, hide, undo/redo, filter, collapse,
save, reopen and screenshot, against the synthetic office project.

Uses Playwright with the system Chromium (NETGRAPHER_CHROMIUM or `chromium` on PATH); skipped
when either is unavailable.
"""

from __future__ import annotations

import os
import re
import shutil
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
CHROMIUM = (
    os.environ.get("NETGRAPHER_CHROMIUM")
    or shutil.which("chromium")
    or shutil.which("chromium-browser")
)
pytestmark = pytest.mark.skipif(CHROMIUM is None, reason="no system Chromium found")

TOKEN = "ui-smoke"
GW = "rtr:192.168.1.1"


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Any]]:
    import socket

    import uvicorn
    from synthetic import office_frames, write_pcap

    from netgrapher.discover import run_file
    from netgrapher.project.store import load, save
    from netgrapher.server.app import create_app
    from netgrapher.server.state import AppState

    pcap = tmp_path / "office.pcap"
    write_pcap(pcap, office_frames())
    project_path = tmp_path / "office.ngraph"
    save(run_file(pcap), project_path)
    state = AppState()
    state.open(load(project_path), project_path)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app = create_app(state, TOKEN, lambda: hosts)
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", state
    srv.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def page(server: tuple[str, Any], tmp_path: Path) -> Iterator[Any]:
    url, _ = server
    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        # bypass_csp: Playwright evaluates test predicates with eval(), which the page CSP forbids.
        context = browser.new_context(
            viewport={"width": 1400, "height": 850}, accept_downloads=True, bypass_csp=True
        )
        pg = context.new_page()
        errors: list[str] = []
        pg.on("pageerror", lambda exc: errors.append(str(exc)))
        pg.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        pg.on(
            "response", lambda r: errors.append(f"{r.status} {r.url}") if r.status >= 400 else None
        )
        pg.goto(f"{url}/#token={TOKEN}")
        pg.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 10")
        pg.errors = errors  # type: ignore[attr-defined]
        yield pg
        assert errors == [], errors
        browser.close()


def click_node(page: Any, node_id: str, *, double: bool = False) -> None:
    # Pan the node to the viewport centre first, so the click always lands on it even after the
    # layout has shifted nodes off-screen (panning is something a user would do too).
    page.evaluate(
        "id => { const cy = window.netgrapher.cy(); cy.center(cy.getElementById(id)); }", node_id
    )
    page.wait_for_timeout(60)
    box = page.locator("#cy").bounding_box()
    pos = page.evaluate(
        "id => window.netgrapher.cy().getElementById(id).renderedPosition()", node_id
    )
    x, y = box["x"] + pos["x"], box["y"] + pos["y"]
    if double:
        page.mouse.dblclick(x, y)
    else:
        page.mouse.click(x, y)


def fit(page: Any) -> None:
    """Fit the graph so every node is within the viewport (clicks need on-screen nodes)."""
    page.get_by_role("button", name="Fit", exact=True).click()
    page.wait_for_timeout(100)


def select_node(page: Any, node_id: str) -> None:
    """Click a node and wait until it is the selected one (robust against the click missing)."""
    for _ in range(3):
        fit(page)
        click_node(page, node_id)
        try:
            page.wait_for_function(
                f"window.netgrapher.state.selected === '{node_id}'", timeout=2000
            )
            return
        except Exception:
            continue
    raise AssertionError(f"could not select {node_id}")


def annotation(page: Any, item_id: str) -> dict[str, Any]:
    return page.evaluate("id => window.netgrapher.state.annotations[id] || {}", item_id)


def has_class(page: Any, node_id: str, cls: str) -> bool:
    return page.evaluate(
        "([id, c]) => window.netgrapher.cy().getElementById(id).hasClass(c)", [node_id, cls]
    )


def test_rename_hide_undo_redo(page: Any, server: tuple[str, Any]) -> None:
    _, state = server
    click_node(page, GW)
    label = page.locator(".label-edit")
    label.fill("Core GW")
    label.press("Enter")
    page.wait_for_function(f"window.netgrapher.state.annotations['{GW}']?.label === 'Core GW'")
    assert state.project.annotations[GW]["label"] == "Core GW"

    page.get_by_role("button", name="Hide", exact=True).click()
    page.wait_for_function(f"window.netgrapher.cy().getElementById('{GW}').hasClass('gone')")
    assert page.locator("#hidden-list").inner_text().startswith("Core GW")

    page.locator("#cy").click(position={"x": 5, "y": 5})  # leave the text field
    page.keyboard.press("Control+z")
    page.wait_for_function(f"!window.netgrapher.cy().getElementById('{GW}').hasClass('gone')")
    page.keyboard.press("Control+z")
    page.wait_for_function(f"!window.netgrapher.state.annotations['{GW}']")
    page.keyboard.press("Control+Shift+z")
    page.wait_for_function(f"window.netgrapher.state.annotations['{GW}']?.label === 'Core GW'")
    assert page.locator("#st-dirty").is_visible()


def test_filters_and_collapse(page: Any) -> None:
    page.locator("#type-filters input[value=host]").uncheck()
    assert has_class(page, "host:192.168.1.10", "gone")
    page.locator("#type-filters input[value=host]").check()
    assert not has_class(page, "host:192.168.1.10", "gone")

    page.locator("#hide-cidr").fill("10.20.0.0/16")
    page.locator("#hide-cidr").press("Enter")
    page.wait_for_function(
        "window.netgrapher.cy().getElementById('net:10.20.0.0/24').hasClass('gone')"
    )

    click_node(page, "net:192.168.1.0/24", double=True)
    page.wait_for_function(
        "window.netgrapher.cy().getElementById('net:192.168.1.0/24').data('displayLabel')"
        ".endsWith('(2 hosts)')"
    )
    assert has_class(page, "host:192.168.1.10", "gone")


def test_save_and_reopen_keeps_layout_and_labels(page: Any, server: tuple[str, Any]) -> None:
    url, state = server
    from netgrapher.project.store import load

    click_node(page, GW)
    page.locator(".label-edit").fill("Core GW")
    page.locator(".label-edit").press("Enter")
    page.wait_for_function(f"window.netgrapher.state.annotations['{GW}']?.label === 'Core GW'")
    before = page.evaluate(
        "() => Object.fromEntries(window.netgrapher.cy().nodes(':childless')"
        ".map(n => [n.id(), n.position()]))"
    )
    page.get_by_role("button", name="Save", exact=True).click()
    page.wait_for_function("!window.netgrapher.state.doc.dirty")
    saved = load(state.path)
    assert saved.annotations[GW]["label"] == "Core GW"
    assert all("position" in saved.annotations[n] for n in before)

    page.goto(f"{url}/#token={TOKEN}")
    page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 10")
    after = page.evaluate(
        "() => Object.fromEntries(window.netgrapher.cy().nodes(':childless')"
        ".map(n => [n.id(), n.position()]))"
    )
    for node_id, pos in before.items():
        assert after[node_id] == pytest.approx(pos, abs=0.01)
    assert (
        page.evaluate(f"window.netgrapher.cy().getElementById('{GW}').data('label')") == "Core GW"
    )


def test_anonymized_svg_and_png_screenshots(page: Any, tmp_path: Path) -> None:
    def shoot(fmt: str, anonymize: bool) -> bytes:
        page.get_by_role("button", name="Screenshot").click()
        dialog = page.locator("#dlg-shot")
        dialog.locator("select[name=format]").select_option(fmt)
        dialog.locator("input[name=anonymize]").set_checked(anonymize)
        with page.expect_download() as info:
            dialog.get_by_role("button", name="Export").click()
        target = tmp_path / info.value.suggested_filename
        info.value.save_as(target)
        return target.read_bytes()

    svg = shoot("svg", anonymize=True).decode()
    assert svg.startswith("<svg") and "RTR-01" in svg and "NET-01" in svg
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", svg)
    plain = shoot("svg", anonymize=False).decode()
    assert "192.168.1.0/24" in plain
    # Labels are restored after an anonymized export.
    assert page.evaluate(f"window.netgrapher.cy().getElementById('{GW}').data('displayLabel')") == (
        "192.168.1.1"
    )
    png = shoot("png", anonymize=False)
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and len(png) > 1000


def test_details_show_evidence_and_text_is_not_html(page: Any) -> None:
    click_node(page, GW)
    page.wait_for_selector(".evidence .rule")
    rules = page.locator(".evidence .rule").all_inner_texts()
    assert {"R-RTR-DHCP", "R-RTR-MAC", "R-RTR-PROTO"} <= set(rules)
    label = page.locator(".label-edit")
    label.fill("<img src=x onerror=alert(1)>")
    label.press("Enter")
    page.wait_for_function(f"window.netgrapher.state.annotations['{GW}']?.label")
    page.locator("#type-filters input[value=router]").click()  # trigger a re-render elsewhere
    page.locator("#type-filters input[value=router]").click()
    assert page.locator("#hidden-list img, #details img").count() == 0


def test_white_background_screenshot_is_legible_in_dark_mode(
    server: tuple[str, Any], tmp_path: Path
) -> None:
    """Regression: on a white background, labels must be dark and subnet boxes light, regardless
    of the OS theme (previously they used the dark-theme palette and were invisible)."""
    url, _ = server
    with playwright_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        context = browser.new_context(
            viewport={"width": 1400, "height": 850}, bypass_csp=True, color_scheme="dark"
        )
        page = context.new_page()
        page.goto(f"{url}/#token={TOKEN}")
        page.wait_for_function("window.netgrapher && window.netgrapher.cy().nodes().length === 10")
        # Confirm the live (dark) theme really is dark, so the export has something to override.
        live_text = page.evaluate(
            "getComputedStyle(document.documentElement).getPropertyValue('--text').trim()"
        )
        assert live_text == "#e5e7eb"

        page.get_by_role("button", name="Screenshot").click()
        dialog = page.locator("#dlg-shot")
        dialog.locator("select[name=format]").select_option("svg")
        dialog.locator("select[name=bg]").select_option("white")
        with page.expect_download() as info:
            dialog.get_by_role("button", name="Export").click()
        svg = tmp_path / info.value.suggested_filename
        info.value.save_as(svg)
        content = svg.read_text()

        # Cytoscape emits colors as rgb(...). Light palette: text #1d2330, subnet-bg #eef2f7.
        assert 'fill="#ffffff"' in content  # the white background rect
        assert "rgb(29,35,48)" in content  # dark label text (light-palette --text)
        assert "rgb(229,231,235)" not in content  # never the dark-theme near-white text (#e5e7eb)
        assert "rgb(238,242,247)" in content  # light subnet-box fill (#eef2f7)
        assert "rgb(31,37,48)" not in content  # never the dark-theme subnet fill (#1f2530)

        # The live palette is restored after the export.
        assert (
            page.evaluate(
                "getComputedStyle(document.documentElement).getPropertyValue('--text').trim()"
            )
            == "#e5e7eb"
        )
        browser.close()


def node_count(page: Any) -> int:
    return page.evaluate("window.netgrapher.cy().nodes().length")


def test_create_delete_and_link_entities(page: Any, server: tuple[str, Any]) -> None:
    _, state = server
    before = node_count(page)

    # Add a host via the toolbar; it should land inside the discovered 10.0.0.0/24 subnet.
    page.locator("#sel-add").select_option("host")
    dialog = page.locator("#dlg-add")
    dialog.locator("#add-addr").fill("10.0.0.50")
    dialog.get_by_role("button", name="Add", exact=True).click()
    page.wait_for_function("window.netgrapher.cy().getElementById('host:10.0.0.50').nonempty()")
    assert node_count(page) == before + 1
    assert (
        page.evaluate("window.netgrapher.cy().getElementById('host:10.0.0.50').parent().id()")
        == "net:10.0.0.0/24"
    )
    assert state.project.user_entities["host:10.0.0.50"]["origin"] == "user"

    # Delete a discovered host via the details panel; it disappears but stays in the engine graph.
    select_node(page, "host:192.168.1.10")
    page.get_by_role("button", name="Delete", exact=True).click()
    page.wait_for_function("window.netgrapher.cy().getElementById('host:192.168.1.10').empty()")
    assert "host:192.168.1.10" in state.project.deleted
    assert "host:192.168.1.10" in state.project.graph.entities  # engine graph untouched

    # Undo restores it.
    page.keyboard.press("Control+z")
    page.wait_for_function("window.netgrapher.cy().getElementById('host:192.168.1.10').nonempty()")
    assert "host:192.168.1.10" not in state.project.deleted

    # Link mode: connect two top-level routers (unambiguous clicks, no existing edge between them).
    links_before = page.evaluate("window.netgrapher.cy().edges().length")
    page.get_by_role("button", name="Link", exact=True).click()
    click_node(page, GW)
    page.wait_for_function(f"window.netgrapher.cy().getElementById('{GW}').selected()")
    click_node(page, "rtr:10.0.0.2")
    page.wait_for_function(f"window.netgrapher.cy().edges().length === {links_before + 1}")
    user_link = next(iter(state.project.user_links))
    assert state.project.user_links[user_link]["type"] == "inferred-path"


def test_delete_subnet_cascades_in_ui(page: Any, server: tuple[str, Any]) -> None:
    _, state = server
    select_node(page, "net:10.20.0.0/24")
    page.get_by_role("button", name="Delete", exact=True).click()
    page.wait_for_function("window.netgrapher.cy().getElementById('net:10.20.0.0/24').empty()")
    # Its inferred-path link from the gateway is gone too.
    assert not page.evaluate(
        "window.netgrapher.cy().getElementById("
        "'lnk:inferred-path:rtr:192.168.1.1|net:10.20.0.0/24').nonempty()"
    )
    assert "net:10.20.0.0/24" in state.project.deleted
