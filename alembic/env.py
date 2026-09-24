"""Alembic environment for the AICybersec platform schema.

URL precedence: AICYBERSEC_DATABASE_URL (env) > alembic.ini fallback.
Read directly from the environment (no settings cache) so programmatic
test runs can override the target database reliably.
"""
from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine

from backend.db.base import Base
from backend.db import models  # noqa: F401  (registers tables on metadata)

config = context.config
target_metadata = Base.metadata


def get_url() -> str:
    return (
        os.getenv("AICYBERSEC_DATABASE_URL")
        or config.get_main_option("sqlalchemy.url")
    )


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url(), pool_pre_ping=True)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
