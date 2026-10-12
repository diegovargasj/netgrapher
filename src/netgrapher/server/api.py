"""REST endpoints. See design §11.5."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Body, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from netgrapher.export import ExportFormat, export_project
from netgrapher.graph.ids import AliasTable
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


def build_router(state: AppState, token: str) -> APIRouter:
    router = APIRouter(prefix="/api")

    def resolve(item_id: str) -> str:
        project = state.project
        resolved = AliasTable(project.aliases).resolve(item_id)
        if resolved not in project.graph.entities and resolved not in project.graph.links:
            raise HTTPException(404, f"unknown entity or link: {item_id}")
        return resolved

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
            item = graph.entities.get(resolved) or graph.links[resolved]
            return [
                {"id": e, **graph.evidence[e].to_dict()}
                for e in item.evidence
                if e in graph.evidence
            ]

    @router.patch("/annotations/{item_id:path}")
    def patch_annotation(item_id: str, patch: AnnotationPatch) -> dict[str, Any]:
        with state.lock:
            resolved = resolve(item_id)
            return {"id": resolved, "annotation": apply(resolved, patch)}

    @router.post("/annotations:batch")
    def patch_batch(items: Annotated[list[BatchItem], Body(max_length=20_000)]) -> dict[str, Any]:
        with state.lock:
            resolved = [resolve(item.id) for item in items]  # all-or-nothing
            return {
                "annotations": {
                    rid: apply(rid, item.patch) for rid, item in zip(resolved, items, strict=True)
                }
            }

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


def project_payload(state: AppState) -> dict[str, Any]:
    project = state.project
    graph = project.graph
    entities = {}
    for eid, entity in graph.entities.items():
        provenance = sorted(
            {
                part
                for e in entity.evidence
                if e in graph.evidence
                for part in graph.evidence[e].provenance.split("+")
            }
        )
        entities[eid] = {**entity.to_dict(), "provenance": provenance}
    return {
        "path": str(state.path) if state.path else None,
        "name": state.path.name if state.path else "untitled",
        "dirty": state.dirty,
        "can_save": state.path is not None,
        "entities": entities,
        "links": {lid: link.to_dict() for lid, link in graph.links.items()},
        "annotations": project.annotations,
        "aliases": project.aliases,
        "view": project.view,
        "runs": [
            {k: run.get(k) for k in ("id", "mode", "source", "started", "ended", "stop_reason")}
            for run in project.runs
        ],
    }
