"""initial platform schema (7 tables)

Revision ID: 0001
Revises:
Create Date: 2026-09-23

users, projects, scans, assets, tool_runs, agent_events, findings.
Timezone-aware timestamps, VARCHAR + CHECK lifecycle statuses, JSONB
payload columns, unique indexes, and the partial unique index that
enforces at most one active (non-terminal) scan per project.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_JSONB = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=100), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), server_default="user", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
    )
    op.create_index("uq_users_email", "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
        sa.Column("scope", _JSONB, server_default=sa.text("'[]'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint("status IN ('active', 'archived')", name="ck_projects_status"),
    )
    op.create_index("ix_projects_owner_created", "projects", ["owner_id", "created_at"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="queued", nullable=False),
        sa.Column("mode", sa.String(length=20), server_default="pipeline", nullable=False),
        sa.Column("profile", sa.String(length=30), server_default="full", nullable=False),
        sa.Column("goal", sa.Text(), nullable=True),
        sa.Column("target_snapshot", _JSONB, nullable=False),
        sa.Column("max_steps", sa.Integer(), nullable=True),
        sa.Column("tool_timeout_s", sa.Integer(), server_default="300", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('queued', 'initializing', 'running', 'cancelling', "
            "'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
        sa.CheckConstraint("mode IN ('pipeline', 'agent')", name="ck_scans_mode"),
        sa.CheckConstraint("profile IN ('recon', 'web', 'full')", name="ck_scans_profile"),
    )
    op.create_index("ix_scans_project_created", "scans", ["project_id", "created_at"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index(
        "uq_scans_project_active",
        "scans",
        ["project_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('queued', 'initializing', 'running', 'cancelling')"
        ),
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("scheme", sa.String(length=10), nullable=True),
        sa.Column("attributes", _JSONB, server_default=sa.text("'{}'"), nullable=False),
        sa.Column("source_tool", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.CheckConstraint("asset_type IN ('host', 'service', 'url')", name="ck_assets_type"),
    )
    op.create_index("uq_assets_scan_identity", "assets", ["scan_id", "asset_type", "value"], unique=True)
    op.create_index("ix_assets_project_type", "assets", ["project_id", "asset_type"])

    op.create_table(
        "tool_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="running", nullable=False),
        sa.Column("initiated_by", sa.String(length=20), server_default="pipeline", nullable=False),
        sa.Column("parameters", _JSONB, nullable=False),
        sa.Column("argv", _JSONB, nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'timeout', 'cancelled')",
            name="ck_tool_runs_status",
        ),
        sa.CheckConstraint("initiated_by IN ('pipeline', 'agent')", name="ck_tool_runs_initiated_by"),
    )
    op.create_index("ix_tool_runs_scan_created", "tool_runs", ["scan_id", "created_at"])

    op.create_table(
        "agent_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("step", sa.Integer(), nullable=True),
        sa.Column("data", _JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_agent_events_scan_id", "agent_events", ["scan_id", "id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_tool", sa.String(length=50), nullable=False),
        sa.Column("scanner_severity", sa.String(length=20), nullable=False),
        sa.Column("scanner_evidence", _JSONB, server_default=sa.text("'{}'"), nullable=False),
        sa.Column("scanner_references", _JSONB, server_default=sa.text("'[]'"), nullable=False),
        sa.Column("ai_severity", sa.String(length=20), nullable=True),
        sa.Column("ai_analysis", sa.Text(), nullable=True),
        sa.Column("ai_confidence", sa.String(length=10), nullable=True),
        sa.Column("ai_recommendation", sa.Text(), nullable=True),
        sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="open", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "scanner_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_scanner_severity",
        ),
        sa.CheckConstraint(
            "ai_severity IS NULL OR ai_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_ai_severity",
        ),
        sa.CheckConstraint(
            "ai_confidence IS NULL OR ai_confidence IN ('low', 'medium', 'high')",
            name="ck_findings_ai_confidence",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'accepted_risk', 'resolved', 'false_positive')",
            name="ck_findings_status",
        ),
    )
    op.create_index("uq_findings_scan_fp", "findings", ["scan_id", "fingerprint"], unique=True)
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "scanner_severity"])
    op.create_index("ix_findings_project", "findings", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_project", table_name="findings")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("uq_findings_scan_fp", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_agent_events_scan_id", table_name="agent_events")
    op.drop_table("agent_events")
    op.drop_index("ix_tool_runs_scan_created", table_name="tool_runs")
    op.drop_table("tool_runs")
    op.drop_index("ix_assets_project_type", table_name="assets")
    op.drop_index("uq_assets_scan_identity", table_name="assets")
    op.drop_table("assets")
    op.drop_index("uq_scans_project_active", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_project_created", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_projects_owner_created", table_name="projects")
    op.drop_table("projects")
    op.drop_index("uq_users_email", table_name="users")
    op.drop_table("users")
