import gzip
import hashlib
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from synthetic import graph_from_frames, office_frames

from netgrapher.project.format import Project
from netgrapher.project.store import load, save
from netgrapher.server.app import create_app, web_root
from netgrapher.server.state import AppState, autosave_path, remember_recent

TOKEN = "test-token"
HOST = "127.0.0.1:8765"


def office_project() -> Project:
    return Project(graph=graph_from_frames([f for _, f in office_frames()]))


@pytest.fixture
def state(tmp_path: Path) -> AppState:
    path = tmp_path / "office.ngraph"
    save(office_project(), path)
    st = AppState()
    st.open(load(path), path)
    return st


@pytest.fixture
def client(state: AppState) -> TestClient:
    app = create_app(state, TOKEN, lambda: {HOST})
    c = TestClient(app, base_url=f"http://{HOST}")
    assert c.post("/api/session", headers={"X-Netgrapher-Token": TOKEN}).status_code == 200
    return c


def test_requires_session(state: AppState) -> None:
    c = TestClient(create_app(state, TOKEN, lambda: {HOST}), base_url=f"http://{HOST}")
    assert c.get("/api/project").status_code == 401
    assert c.post("/api/session", headers={"X-Netgrapher-Token": "wrong"}).status_code == 401
    r = c.post("/api/session", headers={"X-Netgrapher-Token": TOKEN})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/api/project").status_code == 200
    assert c.get("/").status_code == 200  # the page itself holds no data


def test_rejects_foreign_host_and_origin(client: TestClient) -> None:
    assert client.get("/api/project", headers={"Host": "evil.example:8765"}).status_code == 403
    r = client.get("/api/project", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert client.get("/api/project", headers={"Origin": f"http://{HOST}"}).status_code == 200


def test_security_headers(client: TestClient) -> None:
    headers = client.get("/").headers
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_project_payload(client: TestClient) -> None:
    doc = client.get("/api/project").json()
    assert doc["name"] == "office.ngraph" and doc["can_save"] and not doc["dirty"]
    gw = doc["entities"]["rtr:192.168.1.1"]
    assert gw["type"] == "router" and gw["provenance"] == ["passive"]
    assert "lnk:uplink:rtr:192.168.1.1|ext:internet" in doc["links"]


def test_evidence(client: TestClient) -> None:
    ev = client.get("/api/entity/net:192.168.1.0/24/evidence").json()
    assert {e["rule"] for e in ev} == {"R-SUB-DHCP", "R-SUB-OSPF"}
    assert client.get("/api/entity/nope/evidence").status_code == 404


def test_annotations_set_and_clear(client: TestClient, state: AppState) -> None:
    r = client.patch(
        "/api/annotations/rtr:192.168.1.1",
        json={"label": "Core GW", "position": {"x": 1, "y": 2}, "pinned": True},
    )
    assert r.json()["annotation"] == {
        "label": "Core GW",
        "position": {"x": 1.0, "y": 2.0},
        "pinned": True,
    }
    assert state.dirty
    client.patch("/api/annotations/rtr:192.168.1.1", json={"label": None})
    assert state.project.annotations["rtr:192.168.1.1"] == {
        "position": {"x": 1.0, "y": 2.0},
        "pinned": True,
    }
    client.patch("/api/annotations/rtr:192.168.1.1", json={"position": None, "pinned": None})
    assert "rtr:192.168.1.1" not in state.project.annotations


def test_annotation_validation(client: TestClient) -> None:
    assert client.patch("/api/annotations/nope", json={"label": "x"}).status_code == 404
    assert client.patch("/api/annotations/rtr:192.168.1.1", json={"bogus": 1}).status_code == 422
    assert (
        client.patch("/api/annotations/rtr:192.168.1.1", json={"color": "red"}).status_code == 422
    )
    assert (
        client.patch("/api/annotations/rtr:192.168.1.1", json={"label": "x" * 201}).status_code
        == 422
    )


def test_link_annotation(client: TestClient, state: AppState) -> None:
    link = "lnk:uplink:rtr:192.168.1.1|ext:internet"
    assert client.patch(f"/api/annotations/{link}", json={"label": "ISP"}).status_code == 200
    assert state.project.annotations[link] == {"label": "ISP"}


def test_batch_is_all_or_nothing(client: TestClient, state: AppState) -> None:
    body = [
        {"id": "host:192.168.1.10", "patch": {"hidden": True}},
        {"id": "missing", "patch": {"hidden": True}},
    ]
    assert client.post("/api/annotations:batch", json=body).status_code == 404
    assert "host:192.168.1.10" not in state.project.annotations
    body[1]["id"] = "host:192.168.1.20"
    assert client.post("/api/annotations:batch", json=body).status_code == 200
    assert state.project.annotations["host:192.168.1.20"] == {"hidden": True}


def test_view(client: TestClient, state: AppState) -> None:
    view = {
        "layout": "dagre",
        "zoom": 1.5,
        "pan": {"x": 0, "y": 0},
        "show_hidden": True,
        "collapsed": ["net:10.20.0.0/24"],
        "filters": [{"type": "confidence_below", "value": 0.3}],
    }
    assert client.put("/api/view", json=view).status_code == 200
    assert state.project.view["layout"] == "dagre"
    assert client.put("/api/view", json={"layout": "random"}).status_code == 422


def test_save_writes_file_and_clears_autosave(client: TestClient, state: AppState) -> None:
    client.patch("/api/annotations/rtr:192.168.1.1", json={"label": "Core GW"})
    assert state.path is not None
    assert state.autosave() and autosave_path(state.path).exists()
    r = client.post("/api/project/save")
    assert r.status_code == 200 and not state.dirty
    assert not autosave_path(state.path).exists()
    assert load(state.path).annotations["rtr:192.168.1.1"] == {"label": "Core GW"}


def test_download_and_open_upload(client: TestClient, state: AppState) -> None:
    client.patch("/api/annotations/host:192.168.1.10", json={"note": "Alice"})
    data = client.get("/api/project/download").content
    assert json.loads(gzip.decompress(data))["annotations"]["host:192.168.1.10"] == {
        "note": "Alice"
    }
    r = client.post(
        "/api/project/open", content=data, headers={"Content-Type": "application/octet-stream"}
    )
    assert r.status_code == 200
    assert r.json()["can_save"] is False and state.path is None
    assert client.post("/api/project/save").status_code == 409
    bad = client.post(
        "/api/project/open", content=b"junk", headers={"Content-Type": "application/octet-stream"}
    )
    assert bad.status_code == 400


def test_open_by_path_only_from_recent(client: TestClient, tmp_path: Path) -> None:
    other = tmp_path / "other.ngraph"
    save(office_project(), other)
    r = client.post("/api/project/open", json={"path": str(other)})
    assert r.status_code == 403
    remember_recent(other.resolve())
    recent = client.get("/api/project/recent").json()
    assert str(other.resolve()) in [e["path"] for e in recent]
    assert client.post("/api/project/open", json={"path": str(other.resolve())}).status_code == 200


def test_report_and_export(client: TestClient) -> None:
    assert "Graph: 3 subnets" in client.get("/api/report").json()["text"]
    r = client.get("/api/export", params={"format": "graphml"})
    assert r.status_code == 200 and "<graphml" in r.text
    assert 'filename="office.graphml"' in r.headers["content-disposition"]


def test_static_assets_and_vendor_hashes() -> None:
    root = web_root()
    manifest = (root / "vendor" / "README.md").read_text()
    rows = re.findall(r"`([\w./-]+\.js)` \| `([0-9a-f]{64})`", manifest)
    assert len(rows) == 6
    for rel, digest in rows:
        assert hashlib.sha256((root / "vendor" / rel).read_bytes()).hexdigest() == digest
    index = (root / "index.html").read_text()
    assert "http://" not in index and "https://" not in index  # nothing from the network


def test_create_and_delete_user_entities(client: TestClient, state: AppState) -> None:
    # Create a user subnet and a user host.
    r = client.post("/api/entities", json={"type": "subnet", "prefix": "172.31.0.0/24"})
    assert r.status_code == 200
    assert r.json()["id"] == "net:172.31.0.0/24"
    assert r.json()["entity"]["origin"] == "user"
    r = client.post("/api/entities", json={"type": "host", "ip": "172.31.0.9", "label": "NAS"})
    assert r.status_code == 200 and r.json()["id"] == "host:172.31.0.9"

    doc = client.get("/api/project").json()
    assert "net:172.31.0.0/24" in doc["entities"] and "host:172.31.0.9" in doc["entities"]
    assert doc["dirty"] and state.project.user_entities

    # Link them (user link), then it shows up composed.
    r = client.post(
        "/api/links",
        json={
            "type": "member",
            "a": "host:172.31.0.9",
            "b": "net:172.31.0.0/24",
            "label": "static",
        },
    )
    assert r.status_code == 200
    lid = r.json()["id"]
    assert lid in client.get("/api/project").json()["links"]

    # Deleting the subnet tombstones it and the incident link (cascade).
    r = client.delete("/api/entities/net:172.31.0.0/24")
    assert r.status_code == 200
    assert set(r.json()["deleted"]) == {"net:172.31.0.0/24", lid}
    doc = client.get("/api/project").json()
    assert "net:172.31.0.0/24" not in doc["entities"]
    assert lid not in doc["links"]
    # The host survives, now without a parent subnet.
    assert doc["entities"]["host:172.31.0.9"]["subnet_id"] is None


def test_delete_discovered_entity_is_a_tombstone(client: TestClient, state: AppState) -> None:
    assert "host:192.168.1.10" in client.get("/api/project").json()["entities"]
    r = client.delete("/api/entities/host:192.168.1.10")
    assert r.status_code == 200
    doc = client.get("/api/project").json()
    assert "host:192.168.1.10" not in doc["entities"]
    assert "host:192.168.1.10" in state.project.deleted
    # The discovered entity is untouched in the engine graph; only tombstoned.
    assert "host:192.168.1.10" in state.project.graph.entities


def test_restore_undoes_a_deletion(client: TestClient) -> None:
    deleted = client.delete("/api/entities/host:192.168.1.20").json()["deleted"]
    assert "host:192.168.1.20" not in client.get("/api/project").json()["entities"]
    r = client.post("/api/restore", json={"ids": deleted})
    assert r.status_code == 200
    assert "host:192.168.1.20" in client.get("/api/project").json()["entities"]


def test_create_validation(client: TestClient) -> None:
    assert (
        client.post("/api/entities", json={"type": "subnet", "prefix": "nope"}).status_code == 422
    )
    assert client.post("/api/entities", json={"type": "host", "ip": "1.2.3.999"}).status_code == 422
    assert (
        client.post("/api/entities", json={"type": "node"}).status_code == 422
    )  # node needs label
    # A subnet that already exists is a conflict.
    assert (
        client.post(
            "/api/entities", json={"type": "subnet", "prefix": "192.168.1.0/24"}
        ).status_code
        == 409
    )
    # Link to a missing endpoint.
    assert (
        client.post(
            "/api/links", json={"type": "uplink", "a": "rtr:192.168.1.1", "b": "host:10.9.9.9"}
        ).status_code
        == 404
    )


def test_user_entities_round_trip(client: TestClient, state: AppState, tmp_path: Path) -> None:
    client.post("/api/entities", json={"type": "node", "label": "ISP router"})
    client.delete("/api/entities/host:192.168.1.10")
    client.post("/api/project/save")
    reloaded = load(state.path)
    assert reloaded.user_entities and "host:192.168.1.10" in reloaded.deleted
    # The composed graph after reload excludes the tombstoned host, includes the user node.
    from netgrapher.project.compose import rendered_entities

    entities = rendered_entities(reloaded)
    assert "host:192.168.1.10" not in entities
    assert any(e.attrs.get("origin") == "user" for e in entities.values())
