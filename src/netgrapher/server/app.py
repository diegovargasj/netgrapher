"""FastAPI application factory and server runner. See design §11."""

from __future__ import annotations

import socket
import threading
import webbrowser
from collections.abc import Callable
from importlib import resources
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from netgrapher.server.api import build_router
from netgrapher.server.auth import LocalOnlyMiddleware, new_token
from netgrapher.server.state import AppState


def web_root() -> Path:
    return Path(str(resources.files("netgrapher") / "web"))


def create_app(state: AppState, token: str, allowed_hosts: Callable[[], set[str]]) -> FastAPI:
    app = FastAPI(title="netgrapher", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(LocalOnlyMiddleware, token=token, allowed_hosts=allowed_hosts)
    app.include_router(build_router(state, token))
    root = web_root()

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(root / "index.html")

    app.mount("/static", StaticFiles(directory=root), name="static")
    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def serve(
    state: AppState,
    *,
    port: int = 0,
    open_browser: bool = True,
    on_ready: Callable[[str], None] | None = None,
) -> None:
    """Serve the UI on 127.0.0.1 until interrupted (NFR-7)."""
    port = port or _free_port()
    token = new_token()
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app = create_app(state, token, lambda: hosts)
    url = f"http://127.0.0.1:{port}/#token={token}"
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    stop = threading.Event()
    threading.Thread(target=state.autosave_forever, args=(stop,), daemon=True).start()

    def announce() -> None:
        while not server.started and not stop.is_set():
            stop.wait(0.05)
        if on_ready:
            on_ready(url)
        if open_browser:
            webbrowser.open(url)

    threading.Thread(target=announce, daemon=True).start()
    try:
        server.run()
    finally:
        stop.set()
        state.autosave()
