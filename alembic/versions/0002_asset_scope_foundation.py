"""Phase 4A asset + scope foundation.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-29

- Widens assets.ck_assets_type to
  ('host', 'subdomain', 'domain', 'service', 'url', 'endpoint').
  Existing host/service/url rows remain valid (purely additive).
- Adds assets.parent_asset_id (UUID, nullable, FK -> assets.id
  ON DELETE SET NULL) + ix_assets_parent index, so the conceptual
  domain -> subdomain -> host -> service -> url -> endpoint graph is
  queryable with plain PostgreSQL joins. NULL when the parent is
  unknown - never guessed.

Project scope needs no DDL: scope entries live in the projects.scope
JSONB payload, and the new ``domain`` type is validated in application
code (backend/services/scope_service.py).

Reversible: downgrade drops the FK/index/column and restores the
original CHECK. Rows using the new asset types cannot satisfy the old
CHECK, so downgrade removes them first (documented data loss limited
to Phase 4A+ rows; pre-4A host/service/url rows are untouched).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_OLD_TYPES = "'host', 'service', 'url'"
_NEW_TYPES = "'host', 'subdomain', 'domain', 'service', 'url', 'endpoint'"


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE assets DROP CONSTRAINT ck_assets_type"))
    op.execute(
        sa.text(f"ALTER TABLE assets ADD CONSTRAINT ck_assets_type CHECK (asset_type IN ({_NEW_TYPES}))")
    )
    op.add_column(
        "assets",
        sa.Column("parent_asset_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_assets_parent",
        "assets",
        "assets",
        ["parent_asset_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_assets_parent", "assets", ["parent_asset_id"])


def downgrade() -> None:
    op.drop_index("ix_assets_parent", table_name="assets")
    op.drop_constraint("fk_assets_parent", "assets", type_="foreignkey")
    op.drop_column("assets", "parent_asset_id")
    # New-type rows cannot satisfy the restored CHECK; remove only them.
    op.execute(
        sa.text(
            "DELETE FROM assets WHERE asset_type NOT IN (" + _OLD_TYPES + ")"
        )
    )
    op.execute(sa.text("ALTER TABLE assets DROP CONSTRAINT ck_assets_type"))
    op.execute(
        sa.text(f"ALTER TABLE assets ADD CONSTRAINT ck_assets_type CHECK (asset_type IN ({_OLD_TYPES}))")
    )
