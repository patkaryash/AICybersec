"""Live website assessment DTOs (Phase 5 Stage 1).

Stage 1 covers authorization records + immutable snapshots only; no
live HTTP execution exists. Origins are validated/canonicalized by
backend/services/live_authorization_service.parse_origin before
persistence; the canonical form is what gets stored and returned.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

LiveAuthorizationStatus = Literal["active", "suspended", "revoked"]


class OriginEntry(BaseModel):
    """Canonical exact origin (no wildcards; port == scheme default)."""

    origin: str
    scheme: Literal["http", "https"]
    host: str
    port: int = Field(ge=1, le=65535)


class LiveAuthorizationCreate(BaseModel):
    project_id: uuid.UUID
    # Raw origin strings ("https://example.com"); validated and
    # canonicalized by the service before persistence.
    origins: list[str] = Field(min_length=1, max_length=100)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    # Audit pointer only (never claimed to prove consent itself):
    # at least one of evidence_sha256 / evidence_ref is required.
    evidence_sha256: str | None = Field(
        default=None, pattern=r"^[a-fA-F0-9]{64}$"
    )
    evidence_ref: str | None = Field(default=None, min_length=1, max_length=500)
    # Optional stricter validity window. valid_from defaults to now;
    # valid_until defaults to (now or valid_from) + configured max days.
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class LiveAuthorizationOut(BaseModel):
    """FULL audit view (admins only): includes evidence + approver."""

    id: uuid.UUID
    project_id: uuid.UUID
    status: LiveAuthorizationStatus
    policy_version: str
    evidence_sha256: str | None
    evidence_ref: str | None
    origins: list[OriginEntry]
    exclusions: list[OriginEntry]
    methods: list[str]
    approved_by: uuid.UUID
    approved_at: datetime
    valid_from: datetime
    valid_until: datetime
    created_at: datetime
    updated_at: datetime


class LiveAuthorizationOwnerOut(BaseModel):
    """Owner-facing view (F6 minimization).

    What a project owner needs to understand an authorization's state -
    and NOTHING about the operational audit trail: no ``evidence_ref`` /
    ``evidence_sha256`` (authorization evidence is admin-only audit
    metadata) and not ``approved_by`` (which admin issued the record).
    Lifecycle mechanics (status, window, origins/exclusions, policy
    version) remain visible to the owner; admin audit access is
    preserved by ``LiveAuthorizationOut``.
    """

    id: uuid.UUID
    project_id: uuid.UUID
    status: LiveAuthorizationStatus
    policy_version: str
    origins: list[OriginEntry]
    exclusions: list[OriginEntry]
    methods: list[str]
    approved_at: datetime
    valid_from: datetime
    valid_until: datetime
    created_at: datetime
    updated_at: datetime
