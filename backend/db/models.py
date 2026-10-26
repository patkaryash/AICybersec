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
SCAN_PROFILES = ("recon", "web", "full", "live_probe")
PROJECT_STATUSES = ("active", "archived")
# Phase 5 Stage 1: live website assessment authorizations. 'expired' and
# 'not_yet_valid' are NOT stored statuses - the authorization record is
# immutable; expiry/validity are evaluated from the validity window at
# use time (see backend/services/live_authorization_service.py).
LIVE_AUTHORIZATION_STATUSES = ("active", "suspended", "revoked")
USER_ROLES = ("user", "admin")
TOOL_RUN_STATUSES = ("running", "completed", "failed", "timeout", "cancelled")
SEVERITIES = ("info", "low", "medium", "high", "critical")
FINDING_STATUSES = ("open", "accepted_risk", "resolved", "false_positive")
# Phase 4A attack-surface vocabulary. Existing rows are host/service/url;
# subdomain/endpoint/domain rows are produced only by future discovery
# stages (Subfinder/DNSX/Katana) - never fabricated by this phase.
ASSET_TYPES = ("host", "subdomain", "domain", "service", "url", "endpoint")


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
    # Authorized scope: [{"type": "host"|"cidr"|"url"|"domain", "value": "...",
    #   "note": "..."}]. A domain entry authorizes ONLY the exact domain,
    #   never its subdomains (see scope_service.target_in_scope).
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
        CheckConstraint(
            "profile IN ('recon', 'web', 'full', 'live_probe')",
            name="ck_scans_profile",
        ),
        # Hard DB-level gate: a live-probe scan ALWAYS carries its own
        # immutable authorization snapshot + external digest anchor,
        # separate from Project.scope / target_snapshot. Nothing else can
        # populate live_authorization_id. Phase 5 S2-2: it must ALSO
        # carry the immutable execution profile + its own external
        # digest anchor (migration 0005; single upgrade-only swap).
        CheckConstraint(
            "profile <> 'live_probe' OR (live_authorization_id IS NOT NULL "
            "AND authorization_snapshot IS NOT NULL "
            "AND authorization_snapshot_digest IS NOT NULL "
            "AND execution_profile IS NOT NULL "
            "AND execution_profile_digest IS NOT NULL)",
            name="ck_scans_live_probe_snapshot",
        ),
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
    # Phase 5 Stage 1 (live_probe scans ONLY; NULL for every other
    # profile): immutable authorization snapshot copied from the
    # live_authorizations record at scan creation, plus an external
    # SHA-256 digest anchor kept OUTSIDE the snapshot so silent
    # snapshot edits are detected before execution. The live-probe path
    # must use ONLY this snapshot - never Project.scope, never
    # target_snapshot, never Phase 4C promotion.
    # F2 hardening: RESTRICT (never SET NULL) - the CHECK constraint
    # requires live_authorization_id for every live_probe scan, so an
    # authorization referenced by any scan CANNOT be deleted silently
    # (the SET NULL spelling violated the CHECK and could strand rows).
    # Authorization deletion is a lifecycle decision (revoke), not a
    # FK side effect. Audit/digest columns stay intact for a live scan.
    live_authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("live_authorizations.id", ondelete="RESTRICT")
    )
    authorization_snapshot: Mapped[dict | None] = mapped_column(_JSON)
    authorization_snapshot_digest: Mapped[str | None] = mapped_column(String(64))
    # Phase 5 Stage 2 (S2-2; live_probe scans ONLY; NULL for every other
    # profile): immutable execution profile rendered ONCE at scan
    # creation from the server-pinned constants
    # (backend/services/live_probe_budgets.render_execution_profile),
    # plus an external SHA-256 digest anchor kept OUTSIDE the payload.
    # The digest is tamper-evidence ONLY - never authorization; the live
    # transport must re-verify every semantic binding against live
    # values (see live_authorization_service.verify_execution_profile)
    # and live execution remains refused until the dedicated Stage 2
    # prober ships.
    execution_profile: Mapped[dict | None] = mapped_column(_JSON)
    execution_profile_digest: Mapped[str | None] = mapped_column(String(64))
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


class LiveAuthorization(Base):
    """Explicit live-assessment authorization (Phase 5 Stage 1).

    One record authorizes a bounded live HTTP profile against EXACT
    normalized HTTP/HTTPS origins of one project (no wildcards, ports
    80/443, GET on ``/`` only, no redirect following - v1 policy).

    Invariants:
    - A record is created (activated) by an ADMIN; it is immutable
      afterwards. Lifecycle movements are one-way: active -> suspended
      or revoked; suspended authorizations are NOT resumable in v1 and
      a new authorization is required.
    - ``approved_by`` is the activating admin (audit metadata);
      ``approved_at`` is the approval instant. An evidence reference or
      SHA-256 evidence hash is REQUIRED and is an audit pointer only -
      the platform does NOT claim the evidence independently proves
      target-owner consent. Deletion semantics (F2): the project and
      approver links are ON DELETE RESTRICT - authorization records are
      audit artifacts and can never be silently erased by cascade; a
      project or user referenced by an existing authorization cannot be
      deleted (documented policy: authorization history outlives the
      objects that produced it; archival flows must be explicit).
    - ``origins``/``exclusions`` hold canonical origin entries
      [{origin, scheme, host, port}]; exclusions always take
      precedence over allow rules.
    - ``policy_version`` is the platform live-probe policy version at
      approval. Authorization snapshots (copied into scans) must match
      it or they are rejected (fail closed on policy drift).
    - ``valid_from``/``valid_until`` form the validity window; the max
      lifetime is enforced at creation (configurable, default 90 days).
    - Discovery is NOT authorization: this record is separate from
      Project.scope/target_snapshot and from Phase 4C promotion; it is
      bound to exactly one project and usable only by the live-probe
      path (Stage 1: nothing executes).
    """

    __tablename__ = "live_authorizations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')",
            name="ck_live_authorizations_status",
        ),
        CheckConstraint(
            "valid_until > valid_from", name="ck_live_authorizations_window"
        ),
        Index(
            "ix_live_authorizations_project_created",
            "project_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    # Platform live-probe policy version at approval (see backend config).
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    # Audit-only authorization evidence: an auditable reference and/or a
    # SHA-256 hash of the authorization evidence. At least one is
    # required by the service; neither proves consent by itself.
    evidence_ref: Mapped[str | None] = mapped_column(Text)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    # Canonical origin entries, exclusions take precedence over allows.
    origins: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    exclusions: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    # Permitted HTTP methods (v1: GET only; enforced with the profile).
    methods: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    # F2 hardening: RESTRICT (never CASCADE). There is no user-deletion
    # endpoint in the platform; if a user row is ever removed at the DB
    # level, the deletion now FAILS instead of silently erasing the
    # authorization audit trail (approver_id/approved_at/evidence). A
    # provenance-preserving archival flow is deferred to an explicit,
    # documented change (never a FK side effect).
    approved_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    valid_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
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


class Asset(Base):
    """Attack-surface node (Phase 4A foundation).

    Conceptual graph (each level optionally links to its parent via
    ``parent_asset_id``; NULL when the parent is unknown or out of scan):

        domain -> subdomain -> host -> service -> url -> endpoint

    Conventions (all queryable; see result_persistence builders):
    - domain:    value/canonical domain (e.g. "example.com")
    - subdomain: value/hostname (e.g. "api.example.com"),
      attributes {parent_domain, source, verification_status,
      dns_a[], dns_aaaa[], dns_cname[]}
    - host:      value/host IP or hostname; attributes may carry
      DNS enrichment {dns_a[], dns_aaaa[], dns_cname[]} (DATA only -
      never authorization)
    - service:   value "host:port"
    - url:       value full URL (final_url preferred)
    - endpoint:  value full URL; attributes {source_page?, crawl_depth?,
      http_method?}
    """

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('host', 'subdomain', 'domain', 'service', 'url', 'endpoint')",
            name="ck_assets_type",
        ),
        Index("uq_assets_scan_identity", "scan_id", "asset_type", "value", unique=True),
        Index("ix_assets_project_type", "project_id", "asset_type"),
        Index("ix_assets_parent", "parent_asset_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # Canonical identifier per type: domain/hostname | "host" |
    # "host:port" | full URL. Existing host/service/url rows keep their
    # exact values (the CHECK widening is purely additive).
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    scheme: Mapped[str | None] = mapped_column(String(10))
    # Optional link to the parent surface node in the same scan
    # (e.g. endpoint -> url, subdomain -> domain). NULL when the parent
    # is unknown - never guessed. Deleting the parent nulls the link
    # (child evidence is preserved).
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
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
