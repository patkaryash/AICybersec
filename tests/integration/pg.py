"""PostgreSQL availability check for integration tests.

DB-backed tests require a live PostgreSQL matching the configured
AICYBERSEC_DATABASE_URL (docker compose up postgres in the lab); they
skip cleanly when none is reachable. The check targets the exact
database the tests use, so a running server without the platform
database also counts as "not available".
"""
from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from backend.core.config import get_backend_settings


def _pg_reachable() -> bool:
    try:
        import psycopg

        url = make_url(get_backend_settings().database_url)
        conninfo = (
            f"host={url.host} port={url.port or 5432} user={url.username} "
            f"password={url.password} dbname={url.database} connect_timeout=2"
        )
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


requires_pg = pytest.mark.skipif(
    not _pg_reachable(),
    reason=(
        "PostgreSQL not reachable at the configured AICYBERSEC_DATABASE_URL "
        "(docker compose up postgres)"
    ),
)
