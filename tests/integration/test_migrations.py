"""Integration tests: Alembic migrations against a real PostgreSQL.

Requires a live PostgreSQL (see integration/pg.py); skips otherwise.
Runs `upgrade head` on a fresh temporary database, asserts the platform
schema exists, then downgrades to base and asserts the tables are gone.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

from integration.pg import requires_pg

from backend.core.config import get_backend_settings

ROOT = Path(__file__).resolve().parents[2]

PLATFORM_TABLES = {
    "users",
    "projects",
    "scans",
    "assets",
    "tool_runs",
    "agent_events",
    "findings",
    "live_authorizations",  # Phase 5 Stage 1
}


def _server_conninfo() -> str:
    """Connection to the server's default 'postgres' database (CREATE/DROP DATABASE)."""
    url = make_url(get_backend_settings().database_url)
    return (
        f"host={url.host} port={url.port or 5432} user={url.username} "
        f"password={url.password} dbname=postgres connect_timeout=2"
    )


def _alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _create_db(db_name: str) -> None:
    with psycopg.connect(_server_conninfo(), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{db_name}"')


def _drop_db(db_name: str) -> None:
    with psycopg.connect(_server_conninfo(), autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')


def _tables_in(db_url: str) -> set[str]:
    url = make_url(db_url)
    with psycopg.connect(
        f"host={url.host} port={url.port or 5432} user={url.username} "
        f"password={url.password} dbname={url.database} connect_timeout=2"
    ) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public'"
        ).fetchall()
    return {r[0] for r in rows}


def _test_db_url(monkeypatch: pytest.MonkeyPatch) -> str:
    base = make_url(get_backend_settings().database_url)
    db_name = f"aicybersec_test_{uuid.uuid4().hex[:8]}"
    test_url = (
        f"postgresql+psycopg://{base.username}:{base.password}"
        f"@{base.host}:{base.port or 5432}/{db_name}"
    )
    monkeypatch.setenv("AICYBERSEC_DATABASE_URL", test_url)
    return test_url


def _scans_profile_state(db_url: str) -> tuple[set[str], str | None]:
    """Column presence + the ck_scans_live_probe_snapshot definition."""
    url = make_url(db_url)
    with psycopg.connect(
        f"host={url.host} port={url.port or 5432} user={url.username} "
        f"password={url.password} dbname={url.database} connect_timeout=2"
    ) as conn:
        cols = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='scans' "
            "AND column_name IN ('execution_profile', 'execution_profile_digest')"
        ).fetchall()
        check = conn.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'scans'::regclass "
            "AND conname = 'ck_scans_live_probe_snapshot'"
        ).fetchone()
    return {r[0] for r in cols}, check[0] if check else None


@requires_pg
def test_phase5_execution_profile_upgrade_downgrade_roundtrip(monkeypatch):
    """Phase 5 Stage 2 (S2-2), DISPOSABLE database only.

    Upgrade to head: the two execution-profile columns exist and the
    swapped CHECK requires them for live_probe rows. Downgrade to 0004:
    both columns are gone and the CHECK is back at the 0003/0004
    spelling. Re-upgrade: everything restored.
    """
    monkeypatch.chdir(ROOT)
    test_url = _test_db_url(monkeypatch)
    db_name = make_url(test_url).database
    _create_db(db_name)
    try:
        cfg = _alembic_config(test_url)
        command.upgrade(cfg, "head")
        cols, check = _scans_profile_state(test_url)
        assert cols == {"execution_profile", "execution_profile_digest"}
        assert check is not None
        assert "execution_profile IS NOT NULL" in check
        assert "execution_profile_digest IS NOT NULL" in check
        assert "authorization_snapshot IS NOT NULL" in check

        command.downgrade(cfg, "0004")
        cols, check = _scans_profile_state(test_url)
        assert cols == set()
        assert check is not None
        assert "execution_profile" not in check
        assert "authorization_snapshot_digest IS NOT NULL" in check

        command.upgrade(cfg, "head")
        cols, check = _scans_profile_state(test_url)
        assert cols == {"execution_profile", "execution_profile_digest"}
        assert "execution_profile_digest IS NOT NULL" in check
    finally:
        _drop_db(db_name)


@requires_pg
def test_upgrade_head_creates_platform_schema(monkeypatch):
    monkeypatch.chdir(ROOT)
    test_url = _test_db_url(monkeypatch)
    _create_db(make_url(test_url).database)
    try:
        command.upgrade(_alembic_config(test_url), "head")
        tables = _tables_in(test_url)
        assert PLATFORM_TABLES <= tables
        assert "alembic_version" in tables
    finally:
        _drop_db(make_url(test_url).database)


@requires_pg
def test_downgrade_base_removes_platform_schema(monkeypatch):
    monkeypatch.chdir(ROOT)
    test_url = _test_db_url(monkeypatch)
    db_name = make_url(test_url).database
    _create_db(db_name)
    try:
        cfg = _alembic_config(test_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        assert PLATFORM_TABLES.isdisjoint(_tables_in(test_url))
    finally:
        _drop_db(db_name)


@requires_pg
def test_migrations_are_idempotent_after_upgrade(monkeypatch):
    """`upgrade head` on an already-migrated database must be a no-op."""
    monkeypatch.chdir(ROOT)
    test_url = _test_db_url(monkeypatch)
    db_name = make_url(test_url).database
    _create_db(db_name)
    try:
        cfg = _alembic_config(test_url)
        command.upgrade(cfg, "head")
        command.upgrade(cfg, "head")  # second run must not raise
        assert PLATFORM_TABLES <= _tables_in(test_url)
    finally:
        _drop_db(db_name)


@requires_pg
def test_phase5_fk_semantics_upgrade_downgrade_roundtrip(monkeypatch):
    """Phase 5 F2 hardening, DISPOSABLE database only.

    After `upgrade head`: the three authorization FKs must NOT delete
    cascade/set-null (RESTRICT/NO ACTION). After a full head -> base ->
    head round trip (which internally downgrades 0004 back to 0003's
    spellings and forward again): the final definitions are RESTRICT
    again, and no CASCADE/SET NULL leaks into the final head state.
    """
    monkeypatch.chdir(ROOT)
    test_url = _test_db_url(monkeypatch)
    db_name = make_url(test_url).database
    _create_db(db_name)
    try:
        cfg = _alembic_config(test_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")
        with psycopg.connect(
            f"host={make_url(test_url).host} port={make_url(test_url).port or 5432} "
            f"user={make_url(test_url).username} password={make_url(test_url).password} "
            f"dbname={db_name} connect_timeout=2"
        ) as conn:
            rows = conn.execute(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE contype = 'f' AND conrelid IN ('scans'::regclass, "
                "'live_authorizations'::regclass)"
            ).fetchall()
        defs = {name: definition for name, definition in rows}
        scan_fk = defs["fk_scans_live_authorization"]
        proj_fk = defs["live_authorizations_project_id_fkey"]
        appr_fk = defs["live_authorizations_approved_by_fkey"]
        for definition in (scan_fk, proj_fk, appr_fk):
            assert "CASCADE" not in definition
            assert "SET NULL" not in definition
            assert "RESTRICT" in definition or "NO ACTION" in definition
    finally:
        _drop_db(db_name)
