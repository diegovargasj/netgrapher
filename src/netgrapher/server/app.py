"""FastAPI application factory and server runner. See design §11."""

from __future__ import annotations

import socket
import threading
import time
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
    app.include_router(build_router(state, token, allowed_hosts))
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


class RunningServer:
    """The UI server running in a background thread (used during live discovery)."""

    def __init__(
        self,
        server: uvicorn.Server,
        thread: threading.Thread,
        url: str,
        autosave_stop: threading.Event,
        state: AppState,
    ) -> None:
        self.server = server
        self.thread = thread
        self.url = url
        self._autosave_stop = autosave_stop
        self._state = state

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self._autosave_stop.set()
        self._state.autosave()


def start_background(state: AppState, *, port: int = 0, open_browser: bool = True) -> RunningServer:
    """Start the UI server on 127.0.0.1 in a background thread (NFR-7)."""
    port = port or _free_port()
    token = new_token()
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app = create_app(state, token, lambda: hosts)
    url = f"http://127.0.0.1:{port}/#token={token}"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name="ui-server", daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise OSError(f"the UI server could not start on port {port}")
        time.sleep(0.02)
    autosave_stop = threading.Event()
    threading.Thread(target=state.autosave_forever, args=(autosave_stop,), daemon=True).start()
    if open_browser:
        webbrowser.open(url)
    return RunningServer(server, thread, url, autosave_stop, state)


def wait_for_interrupt() -> None:
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def serve(
    state: AppState,
    *,
    port: int = 0,
    open_browser: bool = True,
    on_ready: Callable[[str], None] | None = None,
) -> None:
    """Serve the UI on 127.0.0.1 until Ctrl-C."""
    running = start_background(state, port=port, open_browser=open_browser)
    if on_ready:
        on_ready(running.url)
    try:
        wait_for_interrupt()
    finally:
        running.stop()
