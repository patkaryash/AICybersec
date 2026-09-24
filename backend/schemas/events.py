"""Event and tool-run DTOs.

AgentEventOut.seq is the database event id - the ordered cursor for
WS/SSE replay (after_id).

ToolRunOut deliberately excludes argv/raw_output/stderr: those are
internal/audit data, not API payloads.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AgentEventOut(BaseModel):
    seq: int
    scan_id: uuid.UUID
    event_type: str
    step: int | None
    data: dict[str, Any]
    created_at: datetime


class ToolRunOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    tool: str
    status: str
    initiated_by: str
    parameters: dict[str, Any]
    exit_code: int | None
    summary: str | None
    started_at: datetime | None
    ended_at: datetime | None
    duration_ms: int | None
