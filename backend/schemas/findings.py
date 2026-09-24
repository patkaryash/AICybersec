"""Finding DTOs - scanner evidence and AI analysis remain separate.

scanner_* fields are written only by the parser pipeline and are never
overwritten; ai_* fields are written only by the AI-enrichment step
(Phase 8). ai_analysis is free text in Phase 2 - the structured
AI-analysis detail is a documented Phase 8 extension.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

Severity = Literal["info", "low", "medium", "high", "critical"]
FindingStatus = Literal["open", "accepted_risk", "resolved", "false_positive"]
Confidence = Literal["low", "medium", "high"]


class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID | None
    fingerprint: str
    title: str
    description: str | None
    source_tool: str
    scanner_severity: Severity
    scanner_evidence: dict[str, Any]
    scanner_references: list[Any]
    ai_severity: Severity | None
    ai_analysis: str | None
    ai_confidence: Confidence | None
    ai_recommendation: str | None
    ai_analyzed_at: datetime | None
    status: FindingStatus
    created_at: datetime
    updated_at: datetime
