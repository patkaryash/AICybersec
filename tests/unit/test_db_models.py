"""Unit tests: platform models - metadata shape + DDL renderability.

create_all on SQLite proves the models' DDL renders offline (JSON/Uuid
variants, partial index, CHECK constraints); the PostgreSQL-only DDL and
the Alembic migration are verified by the integration tests against a
real server.
"""
from __future__ import annotations

from sqlalchemy import create_engine, inspect

from backend.db import models  # noqa: F401
from backend.db.base import Base

EXPECTED_TABLES = {
    "users",
    "projects",
    "scans",
    "assets",
    "tool_runs",
    "agent_events",
    "findings",
}


def test_seven_tables_in_metadata():
    assert EXPECTED_TABLES <= set(Base.metadata.tables)


def test_scan_table_columns():
    scan = Base.metadata.tables["scans"]
    cols = {c.name for c in scan.columns}
    assert {
        "id",
        "project_id",
        "status",
        "mode",
        "profile",
        "goal",
        "target_snapshot",
        "max_steps",
        "tool_timeout_s",
        "error",
        "created_at",
        "started_at",
        "completed_at",
        "cancelled_at",
        "updated_at",
    } <= cols


def test_finding_scanner_ai_separation():
    finding = Base.metadata.tables["findings"]
    cols = {c.name for c in finding.columns}
    assert {"scanner_severity", "scanner_evidence", "scanner_references", "source_tool"} <= cols
    assert {"ai_severity", "ai_analysis", "ai_confidence", "ai_recommendation", "ai_analyzed_at"} <= cols


def test_foreign_keys_and_cascade():
    scan = Base.metadata.tables["scans"]
    fks = {fk.parent.name: fk for fk in scan.foreign_keys}
    assert "project_id" in fks
    assert fks["project_id"].column.table.name == "projects"
    assert fks["project_id"].ondelete == "CASCADE"

    finding = Base.metadata.tables["findings"]
    finding_fks = {fk.parent.name: fk for fk in finding.foreign_keys}
    assert {"scan_id", "project_id", "asset_id"} <= set(finding_fks)


def test_unique_indexes():
    scan = Base.metadata.tables["scans"]
    by_name = {i.name: i for i in scan.indexes}
    assert by_name["uq_scans_project_active"].unique
    # partial unique index: postgresql-only WHERE clause present
    assert by_name["uq_scans_project_active"].dialect_options["postgresql"]["where"] is not None

    finding = Base.metadata.tables["findings"]
    finding_idx = {i.name: i for i in finding.indexes}
    assert finding_idx["uq_findings_scan_fp"].unique

    asset = Base.metadata.tables["assets"]
    asset_idx = {i.name: i for i in asset.indexes}
    assert asset_idx["uq_assets_scan_identity"].unique


def test_check_constraints_present():
    scan = Base.metadata.tables["scans"]
    checks = {c.name for c in scan.constraints if c.__class__.__name__ == "CheckConstraint"}
    assert {"ck_scans_status", "ck_scans_mode", "ck_scans_profile"} <= checks


def test_ddl_renders_on_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    assert EXPECTED_TABLES <= set(insp.get_table_names())
    Base.metadata.drop_all(engine)
