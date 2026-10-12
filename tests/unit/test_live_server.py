import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from synthetic import graph_from_frames, office_frames

from netgrapher.project.format import Project
from netgrapher.project.store import load
from netgrapher.server.app import create_app
from netgrapher.server.live import LiveSession
from netgrapher.server.state import AppState

TOKEN = "t"
# Starlette's TestClient always sends "Host: testserver" on WebSocket handshakes, so these tests
# use that host for HTTP too (the session cookie is scoped to it).
HOST = "testserver"
FRAMES = [f for _, f in office_frames()]


def client_for(state: AppState, *, login: bool = True) -> TestClient:
    c = TestClient(create_app(state, TOKEN, lambda: {HOST}), base_url=f"http://{HOST}")
    if login:
        c.post("/api/session", headers={"X-Netgrapher-Token": TOKEN})
    return c


def receive_until(ws: Any, kind: str) -> dict[str, Any]:
    for _ in range(20):
        event = ws.receive_json()
        if event["type"] == kind:
            return event
    raise AssertionError(f"no {kind} event")


def test_events_require_a_session() -> None:
    c = client_for(AppState(), login=False)
    with pytest.raises(WebSocketDisconnect), c.websocket_connect("/api/events") as ws:
        ws.receive_json()


def test_events_reject_foreign_origin() -> None:
    c = client_for(AppState())
    with (
        pytest.raises(WebSocketDisconnect),
        c.websocket_connect("/api/events", headers={"Origin": "http://evil.example"}) as ws,
    ):
        ws.receive_json()


def test_graph_updates_stream_to_clients() -> None:
    state = AppState()
    session = LiveSession(state)
    c = client_for(state)
    with c.websocket_connect("/api/events") as ws:
        hello = ws.receive_json()
        assert hello == {"type": "hello", "seq": state.seq}
        session.publish_graph(graph_from_frames(FRAMES[:4]))
        first = receive_until(ws, "graph")
        assert first["seq"] == hello["seq"] + 1
        assert "net:192.168.1.0/24" in first["entities"]
        session.publish_graph(graph_from_frames(FRAMES))
        second = receive_until(ws, "graph")
        assert second["seq"] == first["seq"] + 1
        assert "ext:internet" in second["entities"]
    payload = c.get("/api/project").json()
    assert payload["seq"] == second["seq"] and payload["live"]["running"] is True


def test_unchanged_graph_sends_nothing() -> None:
    state = AppState()
    session = LiveSession(state)
    session.publish_graph(graph_from_frames(FRAMES))
    seq = state.seq
    session.publish_graph(graph_from_frames(FRAMES))
    assert state.seq == seq


def test_annotation_edits_are_broadcast() -> None:
    state = AppState()
    LiveSession(state).publish_graph(graph_from_frames(FRAMES))
    c = client_for(state)
    with c.websocket_connect("/api/events") as ws:
        ws.receive_json()
        c.patch("/api/annotations/rtr:192.168.1.1", json={"label": "Core"})
        event = receive_until(ws, "annotations")
        assert event["annotations"] == {"rtr:192.168.1.1": {"label": "Core"}}


def test_run_stats_and_finish_keep_user_edits(tmp_path: Path) -> None:
    from netgrapher.discover import Status

    state = AppState()
    session = LiveSession(state)
    session.publish_graph(graph_from_frames(FRAMES[:4]))
    c = client_for(state)
    c.patch("/api/annotations/rtr:192.168.1.1", json={"label": "Core"})
    with c.websocket_connect("/api/events") as ws:
        ws.receive_json()
        session.publish_status(Status(12.0, 340, 7))
        stats = receive_until(ws, "run_stats")
        assert (stats["packets"], stats["entities"]) == (340, 7)
        final = Project(graph=graph_from_frames(FRAMES), runs=[{"id": "r1"}])
        out = tmp_path / "live.ngraph"
        session.finish(final, out)
        ended = receive_until(ws, "run_ended")
        assert ended["path"] == str(out.resolve())
    saved = load(out)
    assert saved.annotations["rtr:192.168.1.1"] == {"label": "Core"}
    assert "ext:internet" in saved.graph.entities and saved.runs == [{"id": "r1"}]
    payload = c.get("/api/project").json()
    assert payload["can_save"] and payload["live"]["running"] is False and not payload["dirty"]


def test_aliases_move_annotations_during_a_run() -> None:
    from netgrapher.graph.model import Entity, EntityType, Graph

    state = AppState()
    session = LiveSession(state)
    h = Entity("host:10.0.0.1", EntityType.HOST, 1.0, {"ip": "10.0.0.1", "subnet_id": None}, [])
    session.publish_graph(Graph({h.id: h}, {}, {}))
    state.project.annotations["host:10.0.0.1"] = {"label": "Mystery box"}
    r = Entity(
        "rtr:10.0.0.1",
        EntityType.ROUTER,
        0.9,
        {"interfaces": [{"ip": "10.0.0.1", "virtual": False}]},
        [],
    )
    c = client_for(state)
    with c.websocket_connect("/api/events") as ws:
        ws.receive_json()
        session.publish_graph(Graph({r.id: r}, {}, {}))
        event = receive_until(ws, "graph")
    assert event["aliases"] == {"host:10.0.0.1": "rtr:10.0.0.1"}
    assert event["annotations"] == {"rtr:10.0.0.1": {"label": "Mystery box"}}
    assert state.project.aliases == {"host:10.0.0.1": "rtr:10.0.0.1"}
    # Old IDs still resolve through the alias table.
    assert (
        c.patch("/api/annotations/host:10.0.0.1", json={"note": "x"}).json()["id"] == "rtr:10.0.0.1"
    )
    json.dumps(event)  # events must be JSON-serializable
