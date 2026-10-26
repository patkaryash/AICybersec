"""Phase 5 Stage 1: live website assessment authorizations.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-22

- Adds the ``live_authorizations`` table (admin-activated authorization
  records for the opt-in live-probe workflow; see
  backend/services/live_authorization_service.py).
- Widen scans.ck_scans_profile to include 'live_probe'.
- Adds the per-scan immutable authorization snapshot columns
  (scans.live_authorization_id FK -> live_authorizations.id
  ON DELETE SET NULL, scans.authorization_snapshot JSONB,
  scans.authorization_snapshot_digest) plus a CHECK that a live_probe
  scan ALWAYS carries the snapshot (DB-level third gate behind the
  API flag gate and the ScanManager refusal).

Reversible: downgrade drops the CHECK/FK/columns, restores the original
profile CHECK (live_probe rows cannot satisfy it and are deleted first -
live-probe SCANS have no execution even in later stages of Stage 1, so
this loses only queued-refused rows), then drops the authorization
table. The final drop makes revocation records irrecoverable - Stage 1
authorizations are deleted wholesale on downgrade by design (documented
data loss; re-upgrade starts with an empty authorization plane).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_JSONB = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

_OLD_PROFILE_TYPES = "'recon', 'web', 'full'"
_NEW_PROFILE_TYPES = "'recon', 'web', 'full', 'live_probe'"


def upgrade() -> None:
    op.create_table(
        "live_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
        sa.Column("policy_version", sa.String(length=50), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("origins", _JSONB, server_default=sa.text("'[]'"), nullable=False),
        sa.Column("exclusions", _JSONB, server_default=sa.text("'[]'"), nullable=False),
        sa.Column("methods", _JSONB, server_default=sa.text("'[]'"), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')",
            name="ck_live_authorizations_status",
        ),
        sa.CheckConstraint(
            "valid_until > valid_from", name="ck_live_authorizations_window"
        ),
    )
    op.create_index(
        "ix_live_authorizations_project_created",
        "live_authorizations",
        ["project_id", "created_at"],
    )

    op.execute(
        sa.text("ALTER TABLE scans DROP CONSTRAINT ck_scans_profile")
    )
    op.execute(
        sa.text(
            "ALTER TABLE scans ADD CONSTRAINT ck_scans_profile CHECK (profile IN "
            f"({_NEW_PROFILE_TYPES}))"
        )
    )

    op.add_column(
        "scans",
        sa.Column("live_authorization_id", sa.Uuid(), nullable=True),
    )
    op.add_column("scans", sa.Column("authorization_snapshot", _JSONB, nullable=True))
    op.add_column(
        "scans",
        sa.Column("authorization_snapshot_digest", sa.String(length=64), nullable=True),
    )
    op.create_foreign_key(
        "fk_scans_live_authorization",
        "scans",
        "live_authorizations",
        ["live_authorization_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        "ck_scans_live_probe_snapshot",
        "scans",
        sa.text(
            "profile <> 'live_probe' OR (live_authorization_id IS NOT NULL "
            "AND authorization_snapshot IS NOT NULL "
            "AND authorization_snapshot_digest IS NOT NULL)"
        ),
    )


def downgrade() -> None:
    op.drop_constraint("ck_scans_live_probe_snapshot", "scans", type_="check")
    op.drop_constraint("fk_scans_live_authorization", "scans", type_="foreignkey")
    op.drop_column("scans", "authorization_snapshot_digest")
    op.drop_column("scans", "authorization_snapshot")
    op.drop_column("scans", "live_authorization_id")
    # live_probe rows cannot satisfy the restored CHECK; remove them
    # (and their cascaded children) before the constraint swap. Stage 1
    # live scans never executed, so this deletes refused/queued rows only.
    op.execute(
        sa.text("DELETE FROM scans WHERE profile = 'live_probe'")
    )
    op.execute(sa.text("ALTER TABLE scans DROP CONSTRAINT ck_scans_profile"))
    op.execute(
        sa.text(
            "ALTER TABLE scans ADD CONSTRAINT ck_scans_profile CHECK (profile IN "
            f"({_OLD_PROFILE_TYPES}))"
        )
    )
    op.drop_table("live_authorizations")
