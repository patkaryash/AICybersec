"""Platform database models (SQLAlchemy 2.x, PostgreSQL).

Seven tables: users, projects, scans, assets, tool_runs, agent_events,
findings. Relationships:

    users 1 - N projects 1 - N scans 1 - N {assets, tool_runs, agent_events, findings}
    findings N - 1 assets (nullable)

Conventions:
- timezone-aware UTC timestamps (DateTime(timezone=True), server now())
- lifecycle statuses are VARCHAR + CHECK (painless Alembic evolution;
  native PG enums deliberately avoided)
- unique constraints are explicit named unique Index objects (uq_*)
- JSONB columns use with_variant(JSON) so the models also load on SQLite
  for offline tests; production is PostgreSQL only
- agent_events.id uses BigInteger (identity on PostgreSQL; Integer variant
  on SQLite where BIGINT PKs do not autoincrement)

Evidence/AI separation: findings.scanner_* columns are written only by
the parser pipeline; ai_* columns only by the AI-enrichment step. The AI
must never overwrite scanner evidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from backend.db.base import Base

_JSON = JSON().with_variant(JSONB(), "postgresql")

ACTIVE_SCAN_STATUSES = ("queued", "initializing", "running", "cancelling")
SCAN_STATUSES = ACTIVE_SCAN_STATUSES + ("completed", "failed", "cancelled")
SCAN_MODES = ("pipeline", "agent")
SCAN_PROFILES = ("recon", "web", "full")
PROJECT_STATUSES = ("active", "archived")
USER_ROLES = ("user", "admin")
TOOL_RUN_STATUSES = ("running", "completed", "failed", "timeout", "cancelled")
SEVERITIES = ("info", "low", "medium", "high", "critical")
FINDING_STATUSES = ("open", "accepted_risk", "resolved", "false_positive")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
        Index("uq_users_email", "email", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="user", server_default="user"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'archived')", name="ck_projects_status"),
        Index("ix_projects_owner_created", "owner_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    # Authorized scope: [{"type": "host"|"cidr"|"url", "value": "...", "note": "..."}]
    # Validated/normalized by the scope service; copied into
    # scans.target_snapshot at scan creation (the authorization anchor).
    scope: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'initializing', 'running', 'cancelling', "
            "'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
        CheckConstraint("mode IN ('pipeline', 'agent')", name="ck_scans_mode"),
        CheckConstraint("profile IN ('recon', 'web', 'full')", name="ck_scans_profile"),
        Index("ix_scans_project_created", "project_id", "created_at"),
        Index("ix_scans_status", "status"),
        # DB-level guarantee behind 409 SCAN_ALREADY_RUNNING: at most one
        # non-terminal scan per project.
        Index(
            "uq_scans_project_active",
            "project_id",
            unique=True,
            postgresql_where=text(
                "status IN ('queued', 'initializing', 'running', 'cancelling')"
            ),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", server_default="queued"
    )
    mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pipeline", server_default="pipeline"
    )
    profile: Mapped[str] = mapped_column(
        String(30), nullable=False, default="full", server_default="full"
    )
    goal: Mapped[str | None] = mapped_column(Text)
    # Copy of project scope at scan creation - the authorization anchor.
    # Changing project scope later never affects an existing scan.
    target_snapshot: Mapped[list] = mapped_column(_JSON, nullable=False)
    max_steps: Mapped[int | None] = mapped_column(Integer)
    tool_timeout_s: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default="300"
    )
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("asset_type IN ('host', 'service', 'url')", name="ck_assets_type"),
        Index("uq_assets_scan_identity", "scan_id", "asset_type", "value", unique=True),
        Index("ix_assets_project_type", "project_id", "asset_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # Canonical identifier: "host" | "host:port" | "scheme://host:port[/path]"
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    scheme: Mapped[str | None] = mapped_column(String(10))
    attributes: Mapped[dict] = mapped_column(
        _JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    source_tool: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ToolRun(Base):
    __tablename__ = "tool_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'timeout', 'cancelled')",
            name="ck_tool_runs_status",
        ),
        CheckConstraint(
            "initiated_by IN ('pipeline', 'agent')", name="ck_tool_runs_initiated_by"
        ),
        # No CHECK on 'tool' on purpose: new tools register without a
        # migration; the registry is the allowlist, this is an audit label.
        Index("ix_tool_runs_scan_created", "scan_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="running", server_default="running"
    )
    initiated_by: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pipeline", server_default="pipeline"
    )
    parameters: Mapped[dict] = mapped_column(_JSON, nullable=False, default=dict)
    # Exact argv executed - audit trail. Never shell=True; argv is built in
    # application code from validated parameters only.
    argv: Mapped[list | None] = mapped_column(_JSON)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    # Capped excerpt (<= max_tool_output_bytes); full output lives on disk
    # under runs/<scan_id>/<tool_run_id>/. Filesystem paths are never
    # exposed through API responses.
    raw_output: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AgentEvent(Base):
    __tablename__ = "agent_events"
    __table_args__ = (Index("ix_agent_events_scan_id", "scan_id", "id"),)

    # Monotonic identity - the ordered cursor for WS/SSE replay (after_id).
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    step: Mapped[int | None] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(_JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "scanner_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_scanner_severity",
        ),
        CheckConstraint(
            "ai_severity IS NULL OR ai_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_ai_severity",
        ),
        CheckConstraint(
            "ai_confidence IS NULL OR ai_confidence IN ('low', 'medium', 'high')",
            name="ck_findings_ai_confidence",
        ),
        CheckConstraint(
            "status IN ('open', 'accepted_risk', 'resolved', 'false_positive')",
            name="ck_findings_status",
        ),
        Index("uq_findings_scan_fp", "scan_id", "fingerprint", unique=True),
        Index("ix_findings_scan_severity", "scan_id", "scanner_severity"),
        Index("ix_findings_project", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    # Deterministic dedup: SHA-256(source_tool, target, title/template_id,
    # port-or-url). UNIQUE per scan collapses duplicate tool results.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source_tool: Mapped[str] = mapped_column(String(50), nullable=False)
    # --- scanner evidence (written only by the parser pipeline) ---
    scanner_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    scanner_evidence: Mapped[dict] = mapped_column(
        _JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    scanner_references: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    # --- AI analysis (written only by the AI-enrichment step) ---
    ai_severity: Mapped[str | None] = mapped_column(String(20))
    ai_analysis: Mapped[str | None] = mapped_column(Text)
    ai_confidence: Mapped[str | None] = mapped_column(String(10))
    ai_recommendation: Mapped[str | None] = mapped_column(Text)
    ai_analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", server_default="open"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
