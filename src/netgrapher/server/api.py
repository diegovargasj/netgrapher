"""REST endpoints. See design §11.5."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Body,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, ConfigDict, Field

from netgrapher.export import ExportFormat, export_project
from netgrapher.graph.ids import AliasTable, link_id
from netgrapher.graph.model import Entity, EntityType, Graph, Link
from netgrapher.project.compose import rendered_entities, rendered_links
from netgrapher.project.format import Project
from netgrapher.project.store import ProjectError, dumps, load, loads
from netgrapher.report import build_report
from netgrapher.server.auth import COOKIE, token_matches
from netgrapher.server.state import AppState, recent_projects

MAX_UPLOAD_BYTES = 256 * 1024 * 1024


class Position(BaseModel):
    model_config = ConfigDict(extra="forbid")
    x: float
    y: float


class AnnotationPatch(BaseModel):
    """Fields set to null are removed; fields left out are unchanged."""

    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(default=None, max_length=200)
    hidden: bool | None = None
    note: str | None = Field(default=None, max_length=10_000)
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    position: Position | None = None
    pinned: bool | None = None


class BatchItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    patch: AnnotationPatch


class Filter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=50)
    value: Any = None


class View(BaseModel):
    model_config = ConfigDict(extra="forbid")
    layout: str = Field(default="fcose", pattern=r"^(fcose|dagre)$")
    zoom: float | None = None
    pan: Position | None = None
    filters: list[Filter] = Field(default_factory=list, max_length=50)
    collapsed: list[str] = Field(default_factory=list, max_length=10_000)
    show_hidden: bool = False


class OpenPath(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str


class EntitySpec(BaseModel):
    """User-created entity: subnet needs a prefix; host/router need an ip; a node needs a label."""

    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^(subnet|router|host|external|node)$")
    prefix: str | None = Field(default=None, max_length=64)
    ip: str | None = Field(default=None, max_length=64)
    label: str | None = Field(default=None, max_length=200)

    def _net(self) -> Any:
        import ipaddress

        try:
            return ipaddress.ip_network(self.prefix or "", strict=False)
        except ValueError as exc:
            raise HTTPException(422, f"invalid prefix: {self.prefix!r}") from exc

    def _addr(self) -> Any:
        import ipaddress

        try:
            return ipaddress.ip_address(self.ip or "")
        except ValueError as exc:
            raise HTTPException(422, f"invalid IP address: {self.ip!r}") from exc

    def entity_id(self) -> str:
        if self.type == "subnet":
            return f"net:{self._net()}"
        if self.type == "host":
            return f"host:{self._addr()}"
        if self.type == "router":
            return f"rtr:{self._addr()}"
        if not self.label:
            raise HTTPException(422, "a node needs a label")
        import hashlib

        return "user:" + hashlib.sha1(self.label.encode()).hexdigest()[:10]

    def attrs(self) -> dict[str, Any]:
        base: dict[str, Any] = {"type": self.type, "confidence": 1.0, "origin": "user"}
        if self.label:
            base["label"] = self.label
        if self.type == "subnet":
            net = self._net()
            base.update(prefix=str(net), version=net.version, prefix_confidence=1.0,
                        kind="user", gateway_ids=[], dhcp_servers=[])
        elif self.type == "host":
            base.update(ip=str(self._addr()), subnet_id=None, names=[], roles=[],
                        hop_distance=None, os_family_guess=None, is_self=False,
                        l2_evidence={"macs": []})
        elif self.type == "router":
            base.update(interfaces=[{"ip": str(self._addr()), "subnet": None, "confidence": 1.0,
                                     "virtual": False}], names=[], roles=[], protocols=[],
                        router_ids=[], hop_distance=None, l2_evidence={"macs": []})
        else:  # external / node
            base["type"] = "external"
            base.update(asn=None, as_name=None, host_count=0, addresses=[])
        return base


class LinkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(default="inferred-path",
                      pattern=r"^(member|interface|inferred-path|uplink)$")
    a: str = Field(max_length=256)
    b: str = Field(max_length=256)
    label: str | None = Field(default=None, max_length=200)


class RestoreSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(max_length=20_000)


def build_router(state: AppState, token: str, allowed_hosts: Callable[[], set[str]]) -> APIRouter:
    router = APIRouter(prefix="/api")

    def resolve(item_id: str) -> str:
        project = state.project
        resolved = AliasTable(project.aliases).resolve(item_id)
        known = (
            resolved in project.graph.entities
            or resolved in project.graph.links
            or resolved in project.user_entities
            or resolved in project.user_links
        )
        if not known:
            raise HTTPException(404, f"unknown entity or link: {item_id}")
        return resolved

    def broadcast_user_graph() -> None:
        with state.lock:
            state.seq += 1
            state.dirty = True
            entities, links = _composed(state.project)
            event = {
                "type": "user_graph",
                "seq": state.seq,
                "entities": {
                    eid: _entity_payload(state.project, entities, eid) for eid in entities
                },
                "links": {lid: lk.to_dict() for lid, lk in links.items()},
                "deleted": list(state.project.deleted),
            }
        state.bus.publish(event)

    def apply(item_id: str, patch: AnnotationPatch) -> dict[str, Any]:
        annotations = state.project.annotations
        current = dict(annotations.get(item_id, {}))
        for name in patch.model_fields_set:
            value = getattr(patch, name)
            if value is None:
                current.pop(name, None)
            else:
                current[name] = value.model_dump() if isinstance(value, BaseModel) else value
        if current:
            annotations[item_id] = current
        else:
            annotations.pop(item_id, None)
        state.dirty = True
        return current

    @router.post("/session")
    def session(
        response: Response, x_netgrapher_token: Annotated[str | None, Header()] = None
    ) -> dict[str, bool]:
        if not token_matches(token, x_netgrapher_token):
            raise HTTPException(401, "invalid token")
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict")
        return {"ok": True}

    @router.get("/project")
    def get_project() -> dict[str, Any]:
        with state.lock:
            return project_payload(state)

    @router.get("/entity/{item_id:path}/evidence")
    def get_evidence(item_id: str) -> list[dict[str, Any]]:
        with state.lock:
            resolved = resolve(item_id)
            graph = state.project.graph
            item = graph.entities.get(resolved) or graph.links.get(resolved)
            if item is None:
                return []  # user-created element: no discovery evidence
            return [
                {"id": e, **graph.evidence[e].to_dict()}
                for e in item.evidence
                if e in graph.evidence
            ]

    @router.patch("/annotations/{item_id:path}")
    def patch_annotation(item_id: str, patch: AnnotationPatch) -> dict[str, Any]:
        with state.lock:
            resolved = resolve(item_id)
            annotation = apply(resolved, patch)
        state.bus.publish({"type": "annotations", "annotations": {resolved: annotation}})
        return {"id": resolved, "annotation": annotation}

    @router.post("/annotations:batch")
    def patch_batch(items: Annotated[list[BatchItem], Body(max_length=20_000)]) -> dict[str, Any]:
        with state.lock:
            resolved = [resolve(item.id) for item in items]  # all-or-nothing
            changed = {
                rid: apply(rid, item.patch) for rid, item in zip(resolved, items, strict=True)
            }
        state.bus.publish({"type": "annotations", "annotations": changed})
        return {"annotations": changed}

    @router.websocket("/events")
    async def events(websocket: WebSocket) -> None:
        # HTTP middleware does not see WebSocket handshakes: check Host, Origin and session here.
        hosts = allowed_hosts()
        origin = websocket.headers.get("origin")
        if (
            websocket.headers.get("host") not in hosts
            or (origin is not None and origin.removeprefix("http://") not in hosts)
            or not token_matches(token, websocket.cookies.get(COOKIE))
        ):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        queue = state.bus.subscribe()
        try:
            await websocket.send_json({"type": "hello", "seq": state.seq})
            while True:
                receive = asyncio.ensure_future(websocket.receive())
                get = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait({receive, get}, return_when=asyncio.FIRST_COMPLETED)
                if receive in done:
                    get.cancel()
                    if receive.result().get("type") == "websocket.disconnect":
                        return
                    continue
                receive.cancel()
                await websocket.send_json(get.result())
        except (WebSocketDisconnect, RuntimeError):
            return
        finally:
            state.bus.unsubscribe(queue)

    @router.post("/entities")
    def create_entity(spec: EntitySpec) -> dict[str, Any]:
        with state.lock:
            project = state.project
            eid = spec.entity_id()
            rendered = set(rendered_entities(project))
            if eid in rendered:
                raise HTTPException(409, f"{eid} already exists")
            project.deleted[:] = [d for d in project.deleted if d != eid]  # un-tombstone if needed
            attrs = spec.attrs()
            if spec.type == "host" and spec.ip:
                attrs["subnet_id"] = _containing_subnet(rendered_entities(project), spec.ip)
            project.user_entities[eid] = attrs
        broadcast_user_graph()
        with state.lock:
            entities, _ = _composed(state.project)
            return {"id": eid, "entity": _entity_payload(state.project, entities, eid)}

    @router.post("/links")
    def create_link(spec: LinkSpec) -> dict[str, Any]:
        with state.lock:
            project = state.project
            rendered = set(rendered_entities(project))
            if spec.a not in rendered or spec.b not in rendered:
                raise HTTPException(404, "both endpoints must exist")
            if spec.a == spec.b:
                raise HTTPException(422, "a link needs two distinct endpoints")
            lid = link_id(spec.type, spec.a, spec.b)
            existing = set(rendered_links(project, rendered_entities(project)))
            if lid in existing:
                raise HTTPException(409, "that link already exists")
            project.deleted[:] = [d for d in project.deleted if d != lid]
            project.user_links[lid] = {"type": spec.type, "a": spec.a, "b": spec.b,
                                       **({"label": spec.label} if spec.label else {})}
        broadcast_user_graph()
        with state.lock:
            _, links = _composed(state.project)
            return {"id": lid, "link": links[lid].to_dict()}

    @router.delete("/entities/{item_id:path}")
    def delete_entity(item_id: str) -> dict[str, Any]:
        with state.lock:
            resolved = resolve(item_id)
            entities = rendered_entities(state.project)
            if resolved not in entities:
                raise HTTPException(404, f"{item_id} is not in the graph")
            removed = _delete(state.project, resolved, entities)
        broadcast_user_graph()
        return {"deleted": removed}

    @router.delete("/links/{item_id:path}")
    def delete_link(item_id: str) -> dict[str, Any]:
        with state.lock:
            resolved = resolve(item_id)
            if resolved not in state.project.deleted:
                state.project.deleted.append(resolved)
        broadcast_user_graph()
        return {"deleted": [resolved]}

    @router.post("/restore")
    def restore(body: RestoreSpec) -> dict[str, Any]:
        with state.lock:
            keep = set(body.ids)
            state.project.deleted[:] = [d for d in state.project.deleted if d not in keep]
        broadcast_user_graph()
        return {"restored": body.ids}

    @router.put("/view")
    def put_view(view: View) -> dict[str, Any]:
        with state.lock:
            state.project.view = view.model_dump(exclude_none=True)
            state.dirty = True
            return state.project.view

    @router.post("/project/save")
    def save_project() -> dict[str, Any]:
        with state.lock:
            if state.path is None:
                raise HTTPException(409, "this project has no file yet; use Save as")
            try:
                state.save()
            except OSError as exc:
                raise HTTPException(500, f"cannot save: {exc}") from exc
            return {"path": str(state.path), "dirty": False}

    @router.get("/project/download")
    def download() -> Response:
        with state.lock:
            data = dumps(state.project)
            name = state.path.name if state.path else "netgrapher.ngraph"
        return Response(
            data,
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{_safe(name)}"'},
        )

    @router.post("/project/open")
    async def open_project(request: Request) -> dict[str, Any]:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            wanted = OpenPath.model_validate(await request.json()).path
            if wanted not in {str(e["path"]) for e in recent_projects()}:
                raise HTTPException(403, "only recent projects can be opened by path")
            try:
                project, path = load(Path(wanted)), Path(wanted)
            except ProjectError as exc:
                raise HTTPException(400, str(exc)) from exc
        else:
            data = await request.body()
            if len(data) > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "file too large")
            try:
                project, path = loads(data, "uploaded file"), None
            except ProjectError as exc:
                raise HTTPException(400, str(exc)) from exc
        state.open(project, path)
        with state.lock:
            return project_payload(state)

    @router.get("/project/recent")
    def recent() -> list[dict[str, object]]:
        return recent_projects()

    @router.get("/report")
    def report() -> dict[str, str]:
        with state.lock:
            return {"text": build_report(state.project)}

    @router.get("/export")
    def export(format: ExportFormat, include_hidden: Annotated[bool, Query()] = False) -> Response:
        with state.lock:
            text = export_project(state.project, format, include_hidden=include_hidden)
            stem = state.path.stem if state.path else "netgrapher"
        ext = {"json": "json", "graphml": "graphml", "gexf": "gexf", "dot": "dot"}[format]
        return Response(
            text,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{_safe(stem)}.{ext}"'},
        )

    return router


def _safe(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in "._-") or "netgrapher"


def entity_payload(graph: Graph, eid: str) -> dict[str, Any]:
    """Payload for a discovered entity from an engine graph (used by live diffs)."""
    entity = graph.entities[eid]
    provenance = sorted(
        {
            part
            for e in entity.evidence
            if e in graph.evidence
            for part in graph.evidence[e].provenance.split("+")
        }
    )
    return {**entity.to_dict(), "origin": "discovered", "provenance": provenance}


def _containing_subnet(entities: dict[str, Entity], ip: str) -> str | None:
    """The id of a rendered subnet whose prefix contains `ip` (most specific), else None."""
    import ipaddress

    addr = ipaddress.ip_address(ip)
    best: tuple[int, str] | None = None
    for eid, entity in entities.items():
        if entity.type is EntityType.SUBNET and entity.attrs.get("prefix"):
            try:
                net = ipaddress.ip_network(entity.attrs["prefix"])
            except ValueError:
                continue
            if addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, eid)
    return best[1] if best else None


def _composed(project: Project) -> tuple[dict[str, Entity], dict[str, Link]]:
    entities = rendered_entities(project)
    return entities, rendered_links(project, entities)


def _entity_payload(project: Project, entities: dict[str, Entity], eid: str) -> dict[str, Any]:
    entity = entities[eid]
    if entity.attrs.get("origin") == "user":
        return {**entity.to_dict(), "provenance": ["user"]}
    return entity_payload(project.graph, eid)


def _delete(project: Project, eid: str, entities: dict[str, Entity]) -> list[str]:
    """Tombstone an entity, its member hosts (for a subnet) and every incident link.

    Returns the ids removed.
    """
    removed: list[str] = []
    links = rendered_links(project, entities)

    def tombstone_links(target: str) -> None:
        for lid, link in links.items():
            if (link.a == target or link.b == target) and lid not in project.deleted:
                project.deleted.append(lid)
                removed.append(lid)

    # Deleting a subnet cascades to the hosts inside it.
    targets = [eid]
    if entities[eid].type is EntityType.SUBNET:
        targets += [
            hid
            for hid, entity in entities.items()
            if entity.type is EntityType.HOST and entity.attrs.get("subnet_id") == eid
        ]
    for target in targets:
        if target not in project.deleted:
            project.deleted.append(target)
            removed.append(target)
        tombstone_links(target)
    return removed


def project_payload(state: AppState) -> dict[str, Any]:
    project = state.project
    entities, links = _composed(project)
    return {
        "seq": state.seq,
        "live": state.live,
        "path": str(state.path) if state.path else None,
        "name": state.path.name if state.path else "untitled",
        "dirty": state.dirty,
        "can_save": state.path is not None,
        "entities": {eid: _entity_payload(project, entities, eid) for eid in entities},
        "links": {lid: link.to_dict() for lid, link in links.items()},
        "annotations": project.annotations,
        "aliases": project.aliases,
        "view": project.view,
        "deleted": list(project.deleted),
        "runs": [
            {k: run.get(k) for k in ("id", "mode", "source", "started", "ended", "stop_reason")}
            for run in project.runs
        ],
    }
