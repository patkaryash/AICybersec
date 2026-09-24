"""Database engine and session factory (sync SQLAlchemy + psycopg 3).

Engines are created lazily and cached; tests reset the caches via
conftest. The initial deployment is a SINGLE backend process - the engine
and its connection pool are not distributed-safe.

Transactions: services must commit around long-running work (never hold
a transaction open while a security tool runs):

    create DB state -> COMMIT -> run tool -> persist result -> COMMIT
"""
from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import get_backend_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_backend_settings()
    # connect_timeout: dead/unreachable hosts must fail fast instead of
    # hanging on OS-level TCP retries (some environments drop SYNs to
    # closed ports instead of refusing them).
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        future=True,
        connect_args={"connect_timeout": 5},
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_engine(), autoflush=False, expire_on_commit=False, future=True
    )


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: one session per request, always closed."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
