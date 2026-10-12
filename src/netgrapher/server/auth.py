"""Session token and Host/Origin validation (DNS-rebinding protection). See design §11.5, NFR-7.

The launch URL carries the token in its fragment (never sent to the server or logged). The page
exchanges it once for an HttpOnly, SameSite=Strict cookie via POST /api/session.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

COOKIE = "ng_session"
HEADER = "x-netgrapher-token"

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_matches(token: str, candidate: str | None) -> bool:
    return candidate is not None and hmac.compare_digest(token.encode(), candidate.encode())


class LocalOnlyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, token: str, allowed_hosts: Callable[[], set[str]]) -> None:
        super().__init__(app)
        self.token = token
        self.allowed_hosts = allowed_hosts

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        hosts = self.allowed_hosts()
        if request.headers.get("host") not in hosts:
            return JSONResponse({"detail": "unexpected Host header"}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None and origin.removeprefix("http://") not in hosts:
            return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        path = request.url.path
        if path.startswith("/api/") and path != "/api/session":
            supplied = request.cookies.get(COOKIE) or request.headers.get(HEADER)
            if not token_matches(self.token, supplied):
                return JSONResponse({"detail": "not authenticated"}, status_code=401)
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response
