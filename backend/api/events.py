"""Events API: agent events (cursor pagination) + tool runs.

Thin routers over backend/services/event_service.py. Event data payloads
are sanitized at WRITE time by the scan pipeline (Phase 3+); tool-run
responses exclude argv/raw_output/stderr (internal/audit data).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, Meta, PageData, ok, paginated
from backend.db.models import User
from backend.db.session import get_db
from backend.schemas.events import AgentEventOut, ToolRunOut
from backend.services import event_service

router = APIRouter(prefix="/api/v1/scans/{scan_id}", tags=["events"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


@router.get("/agent-events", response_model=Envelope[PageData[AgentEventOut]])
def list_agent_events(
    scan_id: uuid.UUID,
    request: Request,
    after_id: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[AgentEventOut]]:
    """Cursor-style pagination: pass after_id (last seen seq) and iterate
    until fewer than limit events are returned; after_id=0 replays the
    full history."""
    rows = event_service.list_agent_events_for_scan(
        session, user=user, scan_id=scan_id, after_id=after_id, limit=limit
    )
    return Envelope[PageData[AgentEventOut]](
        success=True,
        data=PageData[AgentEventOut](
            items=[AgentEventOut.model_validate(e, from_attributes=True) for e in rows]
        ),
        meta=Meta(
            request_id=_request_id(request), page_size=limit
        ),
    )


@router.get("/tool-runs", response_model=Envelope[PageData[ToolRunOut]])
def list_tool_runs(
    scan_id: uuid.UUID,
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[ToolRunOut]]:
    rows, total = event_service.list_tool_runs_for_scan(
        session, user=user, scan_id=scan_id, page=page, page_size=page_size
    )
    return paginated(
        [ToolRunOut.model_validate(t, from_attributes=True) for t in rows],
        page,
        page_size,
        total,
        _request_id(request),
    )
