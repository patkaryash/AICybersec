"""Event service: read-only agent events (cursor pagination) + tool runs.

Agent-event data payloads are persisted by the scan pipeline (Phase 3+)
and must already be sanitized at WRITE time: no secrets, credentials,
environment variables, arbitrary stdout, or hidden model reasoning. This
service reads what was persisted; ToolRunOut excludes argv/raw_output/
stderr (internal/audit data, not API payloads).
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import AgentEvent, ToolRun, User
from backend.services.result_persistence import sanitize_event_data
from backend.services.scan_service import get_scan_for_user


def record_event(
    session: Session,
    *,
    scan_id: uuid.UUID,
    event_type: str,
    step: int | None = None,
    data: dict | None = None,
) -> None:
    """Persist one lifecycle event to agent_events (sanitized payload).

    Used by the ScanManager/executor for scan lifecycle events
    (scan_started, scan_status_changed, terminal events); the runtime's
    per-step events flow through the DatabaseEventSink instead.
    """
    session.add(
        AgentEvent(
            scan_id=scan_id,
            event_type=str(event_type)[:50],
            step=int(step) if isinstance(step, int) else None,
            data=sanitize_event_data(data or {}),
        )
    )


def list_agent_events_for_scan(
    session: Session,
    *,
    user: User,
    scan_id: uuid.UUID,
    after_id: int = 0,
    limit: int = 50,
) -> list[AgentEvent]:
    """Persisted events for one visible scan, ordered by seq (id).

    Cursor-style pagination: the client passes after_id (the last seq it
    has seen) and iterates until fewer than limit events are returned.
    Reconnects after_id=0 replay the full history without duplication.
    """
    get_scan_for_user(session, scan_id, user)
    query = (
        select(AgentEvent)
        .where(AgentEvent.scan_id == scan_id, AgentEvent.id > after_id)
        .order_by(AgentEvent.id)
        .limit(limit)
    )
    return list(session.scalars(query).all())


def list_tool_runs_for_scan(
    session: Session,
    *,
    user: User,
    scan_id: uuid.UUID,
    page: int,
    page_size: int,
) -> tuple[list[ToolRun], int]:
    """Tool runs for one visible scan, oldest first (execution order)."""
    get_scan_for_user(session, scan_id, user)
    query = select(ToolRun).where(ToolRun.scan_id == scan_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(ToolRun.created_at)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total
