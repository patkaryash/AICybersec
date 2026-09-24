"""Scan DTOs.

Phase 2: POST /scans creates and persists the record with
status="queued" and returns 202 - no execution is scheduled (Phase 3).
target_snapshot is the authorization anchor: a copy of the project's
validated scope at scan creation.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ScanStatus = Literal[
    "queued",
    "initializing",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
]
ScanMode = Literal["pipeline", "agent"]
ScanProfile = Literal["recon", "web", "full"]

# Static pipeline size per profile (Phase 3 may refine progress reporting;
# the tool sequence lengths are fixed by the profiles).
PROFILE_TOTAL_STEPS: dict[str, int] = {"recon": 2, "web": 2, "full": 3}

CANCELLABLE_STATUSES = ("queued", "initializing")


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    profile: ScanProfile = "full"
    mode: ScanMode = "pipeline"
    goal: str | None = Field(default=None, max_length=2000)
    tool_timeout_s: int = Field(default=300, ge=30, le=1800)
    max_steps: int | None = Field(default=None, ge=1, le=100)


class FindingsCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ScanOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: ScanStatus
    mode: ScanMode
    profile: ScanProfile
    goal: str | None
    target_snapshot: list[Any]
    tool_timeout_s: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    updated_at: datetime
    total_steps: int
    current_step: int = 0
    findings_count: FindingsCount = Field(default_factory=FindingsCount)


class DashboardOut(BaseModel):
    """Single coherent dashboard response (aggregate stats + recent scans)."""

    total_projects: int = 0
    total_scans: int = 0
    running_scans: int = 0
    scans_by_status: dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    total_assets: int = 0
    recent_scans: list[ScanOut] = Field(default_factory=list)
