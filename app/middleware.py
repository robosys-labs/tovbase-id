from __future__ import annotations

import json
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from app.config import settings

ACCESS_LOGGER = logging.getLogger("tovbase_id.access")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(did:[a-z0-9]+:[a-z0-9_-]+|[0-9a-f]{64}|(?:act|anch|att|aatt|evt|tgr)_[a-z0-9_-]+)"
)


def _request_id(header_value: str | None) -> str:
    if header_value and REQUEST_ID_RE.fullmatch(header_value):
        return header_value
    return secrets.token_urlsafe(16)


def _path_template(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return route_path
    return SENSITIVE_PATH_RE.sub("{id}", request.url.path)


def _log_access(
    *,
    request: Request,
    request_id: str,
    status_code: int,
    duration_ms: float,
    failed: bool = False,
) -> None:
    if not settings.access_log_enabled:
        return
    ACCESS_LOGGER.info(
        json.dumps(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path_template": _path_template(request),
                "status_code": status_code,
                "duration_ms": round(duration_ms, 3),
                "failed": failed,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def install_access_logging(app: FastAPI) -> None:
    @app.middleware("http")
    async def access_log_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = _request_id(request.headers.get("x-request-id"))
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            _log_access(
                request=request,
                request_id=request_id,
                status_code=500,
                duration_ms=duration_ms,
                failed=True,
            )
            raise

        response.headers["x-request-id"] = request_id
        duration_ms = (time.perf_counter() - started) * 1000
        _log_access(
            request=request,
            request_id=request_id,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response
