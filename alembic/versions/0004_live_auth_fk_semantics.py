"""Phase 5 Stage 1 hardening (F2): authorization FK deletion semantics.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-22

Purely additive constraint re-creation (no columns, tables or data are
touched). Three FK behaviors changed to fail closed - all three choices
are AUDIT-PRESERVING:

1. scans.live_authorization_id  : SET NULL -> RESTRICT
   The 0003 spelling (SET NULL) conflicted with the
   ``ck_scans_live_probe_snapshot`` CHECK (a live_probe scan would lose
   its FK and then violate the CHECK). RESTRICT makes deletion of an
   authorization referenced by ANY scan fail closed: authorization
   removal is a lifecycle decision (revoke/suspend), never a FK side
   effect, and the scan keeps its snapshot/digest/integrity fields.

2. live_authorizations.project_id : CASCADE -> RESTRICT
   Deleting a project that ever received an authorization would
   otherwise silently erase the authorization audit trail. Documented
   policy: authorization history OUTLIVES the objects that produced it
   (RESTRICT). A project referenced by any authorization cannot be
   deleted; archival flows, if needed later, must be explicit code -
   never a FK cascade.

3. live_authorizations.approved_by : CASCADE -> RESTRICT
   There is no user-deletion endpoint in the platform; if a user row is
   ever removed at the DB level, the deletion now fails instead of
   silently erasing who approved what, when, and with which evidence.

Reversible: downgrade restores the 0003 constraint spellings (same
constraint names, so the later 0003 downgrade sees its original names).
The downgrade is used ONLY on disposable test databases - on the lab DB
we only ever upgrade.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Scans -> live_authorizations: SET NULL -> RESTRICT
    op.drop_constraint("fk_scans_live_authorization", "scans", type_="foreignkey")
    op.create_foreign_key(
        "fk_scans_live_authorization",
        "scans",
        "live_authorizations",
        ["live_authorization_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    # live_authorizations.project_id: CASCADE -> RESTRICT
    op.drop_constraint("live_authorizations_project_id_fkey", "live_authorizations", type_="foreignkey")
    op.create_foreign_key(
        "live_authorizations_project_id_fkey",
        "live_authorizations",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    # live_authorizations.approved_by: CASCADE -> RESTRICT
    op.drop_constraint("live_authorizations_approved_by_fkey", "live_authorizations", type_="foreignkey")
    op.create_foreign_key(
        "live_authorizations_approved_by_fkey",
        "live_authorizations",
        "users",
        ["approved_by"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_scans_live_authorization", "scans", type_="foreignkey")
    op.create_foreign_key(
        "fk_scans_live_authorization",
        "scans",
        "live_authorizations",
        ["live_authorization_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint("live_authorizations_project_id_fkey", "live_authorizations", type_="foreignkey")
    op.create_foreign_key(
        "live_authorizations_project_id_fkey",
        "live_authorizations",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("live_authorizations_approved_by_fkey", "live_authorizations", type_="foreignkey")
    op.create_foreign_key(
        "live_authorizations_approved_by_fkey",
        "live_authorizations",
        "users",
        ["approved_by"],
        ["id"],
        ondelete="CASCADE",
    )
