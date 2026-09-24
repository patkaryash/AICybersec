"""Health and readiness endpoints (no authentication).

GET /api/v1/health       liveness - always answers when the app is up.
GET /api/v1/health/ready readiness - 200 when the database is reachable,
                         503 DATABASE_ERROR otherwise.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import text

from backend.core.envelope import Envelope, ok
from backend.core.errors import ApiError, ErrorCode
from backend.core.time import utc_iso
from backend.db.session import get_engine

router = APIRouter(prefix="/api/v1/health", tags=["health"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


@router.get("", response_model=Envelope[dict[str, Any]])
def health(request: Request) -> Envelope[dict[str, Any]]:
    return ok(
        {
            "status": "ok",
            "version": request.app.version,
            "time": utc_iso(),
        },
        request_id=_request_id(request),
    )


@router.get("/ready", response_model=Envelope[dict[str, Any]])
def ready(request: Request) -> Envelope[dict[str, Any]]:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        # Readiness answers 503 with DATABASE_ERROR (general database
        # errors elsewhere map to 500).
        raise ApiError(
            ErrorCode.DATABASE_ERROR, "Database is not reachable.", status=503
        ) from None
    return ok({"status": "ready"}, request_id=_request_id(request))
