"""Database event sink: agent_core EventSink persisted to Postgres (Phase 3).

The sink is the ONLY bridge between AgentRuntime and the database: the
runtime stays pure (it just calls ``handle(event)``), and every
persistence concern lives here. Writes use short-lived sessions - a
session is never held open while a tool executes.

Per-event mapping:
- every event            -> agent_events row (sanitized data payload)
- tool.started           -> tool_runs row (status running; validated
                            params correlated from the preceding
                            decision.proposed event)
- tool.finished          -> latest running tool_runs row for that tool
                            (completed | failed | timeout + summary/timing)
- finding.recorded       -> findings row (scanner_* only; deduped)

A failure inside the sink must NEVER break the agent loop: _write is
guarded and logs instead of raising.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.db.models import AgentEvent, ToolRun
from backend.services.result_persistence import (
    persist_finding,
    sanitize_event_data,
)

logger = logging.getLogger(__name__)

_FINISH_STATUS = {"ok": "completed", "error": "failed", "timeout": "timeout"}


class DatabaseEventSink:
    """EventSink writing agent events, tool runs and findings to Postgres."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        scan_id: uuid.UUID,
        project_id: uuid.UUID,
        initiated_by: str = "pipeline",
    ) -> None:
        self._sessions = session_factory
        self._scan_id = scan_id
        self._project_id = project_id
        self._initiated_by = initiated_by
        # Validated params proposed per step (from decision.proposed),
        # attached to the matching tool.started; popped on use.
        self._proposed_params: dict[int, dict[str, Any]] = {}

    # -- EventSink protocol -------------------------------------------------
    def handle(self, event: dict[str, Any]) -> None:
        try:
            self._write(event)
        except Exception:
            logger.exception("db sink failed to persist agent event")

    # -- internals ----------------------------------------------------------
    def _write(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("type", ""))
        step = event.get("step")
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        with self._sessions() as session:
            session.add(
                AgentEvent(
                    scan_id=self._scan_id,
                    event_type=event_type,
                    step=int(step) if isinstance(step, int) else None,
                    data=sanitize_event_data(data),
                )
            )
            if event_type == "decision.proposed":
                self._remember_proposal(event)
            elif event_type == "tool.started":
                self._open_tool_run(session, event)
            elif event_type == "tool.finished":
                self._close_tool_run(session, event)
            elif event_type == "finding.recorded":
                finding = data.get("finding")
                if isinstance(finding, dict):
                    persist_finding(
                        session,
                        scan_id=self._scan_id,
                        project_id=self._project_id,
                        finding=finding,
                    )
            session.commit()

    def _remember_proposal(self, event: dict[str, Any]) -> None:
        data = event.get("data")
        if not isinstance(data, dict):
            return
        decision = data.get("decision")
        if not isinstance(decision, dict) or decision.get("kind") != "tool_call":
            return
        params = decision.get("params")
        step = event.get("step")
        if isinstance(params, dict) and isinstance(step, int):
            self._proposed_params[step] = params

    def _open_tool_run(self, session: Session, event: dict[str, Any]) -> None:
        data = event.get("data")
        tool = data.get("tool") if isinstance(data, dict) else None
        if not isinstance(tool, str) or not tool:
            return
        step = event.get("step")
        params = self._proposed_params.pop(step, {}) if isinstance(step, int) else {}
        session.add(
            ToolRun(
                scan_id=self._scan_id,
                tool=tool[:50],
                status="running",
                initiated_by=self._initiated_by,
                parameters=params if isinstance(params, dict) else {},
                started_at=datetime.now(timezone.utc),
            )
        )

    def _close_tool_run(self, session: Session, event: dict[str, Any]) -> None:
        data = event.get("data")
        if not isinstance(data, dict):
            return
        tool = data.get("tool")
        if not isinstance(tool, str) or not tool:
            return
        row = (
            session.query(ToolRun)
            .filter(ToolRun.scan_id == self._scan_id, ToolRun.tool == tool, ToolRun.status == "running")
            .order_by(ToolRun.created_at.desc())
            .first()
        )
        if row is None:
            return
        status = _FINISH_STATUS.get(str(data.get("status")), "failed")
        now = datetime.now(timezone.utc)
        row.status = status
        summary = data.get("summary")
        row.summary = str(summary)[:2000] if summary is not None else None
        row.ended_at = now
        if row.started_at is not None:
            started = row.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            row.duration_ms = max(0, int((now - started).total_seconds() * 1000))
