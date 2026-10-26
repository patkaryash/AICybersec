"""Phase 5 Stage 2 (S2-2): live-probe execution profile columns.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-22

Purely additive storage for the execution-profile contract (design §4.1):

- scans.execution_profile (JSONB) - rendered ONCE at live-scan creation
  from the server-pinned constants (backend/services/live_probe_budgets
  .render_execution_profile); NULL for every non-live_probe profile.
- scans.execution_profile_digest (VARCHAR(64)) - external SHA-256
  digest anchor beside the payload (the same double-anchor pattern
  proven for authorization_snapshot).

The existing CHECK ``ck_scans_live_probe_snapshot`` is swapped (same
name, upgrade-only on the lab DB) so live_probe rows must ALSO carry
non-null execution_profile AND execution_profile_digest - a live scan
can never exist without its full profile set. Pre-0005 queued live rows
do not satisfy the swapped CHECK and must be re-issued (they never
executed; verification refuses them closed as "execution profile
missing" if any survive).

Reversible: downgrade restores the 0003/0004 CHECK spelling first and
then drops the two columns (used ONLY on disposable test databases;
the lab DB is only ever upgraded). No destructive operations on any
shared/dev database.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_JSONB = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

_ORIGINAL_CHECK = (
    "profile <> 'live_probe' OR (live_authorization_id IS NOT NULL "
    "AND authorization_snapshot IS NOT NULL "
    "AND authorization_snapshot_digest IS NOT NULL)"
)
_EXTENDED_CHECK = (
    "profile <> 'live_probe' OR (live_authorization_id IS NOT NULL "
    "AND authorization_snapshot IS NOT NULL "
    "AND authorization_snapshot_digest IS NOT NULL "
    "AND execution_profile IS NOT NULL "
    "AND execution_profile_digest IS NOT NULL)"
)


def upgrade() -> None:
    op.add_column("scans", sa.Column("execution_profile", _JSONB, nullable=True))
    op.add_column(
        "scans",
        sa.Column("execution_profile_digest", sa.String(length=64), nullable=True),
    )
    # Single constraint swap by NAME (the name is referenced by 0003/0004
    # downgrade logic, so it must survive unchanged).
    op.drop_constraint("ck_scans_live_probe_snapshot", "scans", type_="check")
    op.create_check_constraint(
        "ck_scans_live_probe_snapshot",
        "scans",
        sa.text(_EXTENDED_CHECK),
    )


def downgrade() -> None:
    op.drop_constraint("ck_scans_live_probe_snapshot", "scans", type_="check")
    op.create_check_constraint(
        "ck_scans_live_probe_snapshot",
        "scans",
        sa.text(_ORIGINAL_CHECK),
    )
    op.drop_column("scans", "execution_profile_digest")
    op.drop_column("scans", "execution_profile")
