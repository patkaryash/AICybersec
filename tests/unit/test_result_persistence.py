"""Unit tests: persistence helpers - fingerprint, sanitize, assets (no DB)."""
from __future__ import annotations

import json

from agent_core.schemas.results import Observation
from backend.services.result_persistence import (
    MAX_EVENT_DATA_CHARS,
    assets_from_observation,
    finding_fingerprint,
    sanitize_event_data,
)

def test_fingerprint_deterministic_and_sensitive():
    a = finding_fingerprint("nuclei", "https://h/", "X", "T-1")
    assert a == finding_fingerprint("nuclei", "https://h/", "X", "T-1")
    assert len(a) == 64
    assert a != finding_fingerprint("nuclei", "https://h/", "X", "T-2")
    assert a != finding_fingerprint("nmap", "https://h/", "X", "T-1")


def test_sanitize_strips_reasoning_and_caps():
    data = {
        "decision": {
            "kind": "tool_call",
            "tool": "nmap",
            "params": {"target": "h"},
            "reasoning": "secret chain of thought here",
        },
        "big": "x" * (MAX_EVENT_DATA_CHARS + 100),
    }
    out = sanitize_event_data(data)
    assert "reasoning" not in out["decision"]
    assert out["decision"]["tool"] == "nmap"
    assert len(out["big"]) < len(data["big"])
    # adversarial circular input collapses instead of recursing forever
    circular: dict = {}
    circular["self"] = circular
    out = sanitize_event_data({"o": circular})
    assert "circular" in json.dumps(out)


def test_assets_from_nmap_observation():
    obs = Observation(
        step=1, source="tool", tool="nmap", ok=True, summary="s",
        data={"hosts": [
            {"ip": "10.0.0.5", "ports": [
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service": {"name": "http"}},
                {"port": 22, "protocol": "tcp", "state": "closed"},
                {"port": "bogus", "protocol": "tcp", "state": "open"},
            ]},
            "not-a-host",
        ]},
        findings=[],
    )
    assets = assets_from_observation(obs)
    by_value = {a["value"]: a for a in assets}
    assert by_value["10.0.0.5"]["asset_type"] == "host"
    assert by_value["10.0.0.5:80"]["asset_type"] == "service"
    assert by_value["10.0.0.5:80"]["attributes"]["service"] == "http"
    assert "10.0.0.5:22" not in by_value  # closed ports excluded
    assert all(a["source_tool"] == "nmap" for a in assets)


def test_assets_from_httpx_observation():
    obs = Observation(
        step=2, source="tool", tool="httpx", ok=True, summary="s",
        data={"services": [
            {"url": "http://h:8080/", "final_url": "http://h:8080/app",
             "status_code": 200, "title": "T", "tech": ["nginx"]},
            "not-a-service",
        ]},
        findings=[],
    )
    assets = assets_from_observation(obs)
    assert len(assets) == 1
    assert assets[0]["asset_type"] == "url"
    assert assets[0]["value"] == "http://h:8080/app"
    assert assets[0]["port"] == 8080
    assert assets[0]["attributes"]["tech"] == ["nginx"]


def test_no_assets_from_non_tool_observations():
    assert assets_from_observation({"source": "rejected", "tool": "nmap"}) == []
    assert assets_from_observation({"source": "tool", "tool": "nuclei", "data": {}}) == []
    assert assets_from_observation("garbage") == []


def _sqlite_factory(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.db import models  # noqa: F401
    from backend.db.base import Base

    engine = create_engine(
        f"sqlite:///{tmp_path}/persist.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed_scan(factory):
    from backend.db.models import Project, Scan, User

    with factory() as session:
        user = User(email="u@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=[])
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id, status="running", mode="pipeline", profile="full",
            target_snapshot=[], tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id, project.id


def test_persist_finding_dedupes_and_separates_ai_columns(tmp_path):
    from backend.services.result_persistence import persist_finding

    factory = _sqlite_factory(tmp_path)
    scan_id, project_id = _seed_scan(factory)
    finding = {
        "id": "nuclei:x", "title": "X", "severity": "critical",
        "target": "https://h/", "asset": "https://h/", "description": "d",
        "evidence": {"template_id": "T-1"}, "tool": "nuclei",
        "confidence": "high", "status": "open", "references": ["https://r/"],
    }
    with factory() as session:
        row = persist_finding(session, scan_id=scan_id, project_id=project_id, finding=finding)
        assert row is not None
        assert row.scanner_severity == "critical"
        assert row.scanner_evidence["tool_confidence"] == "high"
        assert row.ai_severity is None and row.ai_analysis is None
        session.commit()
        # identical finding dedupes to None (unique fingerprint per scan)
        assert persist_finding(session, scan_id=scan_id, project_id=project_id, finding=finding) is None
        session.commit()
    with factory() as session:
        from backend.db.models import Finding as FindingRow

        assert session.query(FindingRow).count() == 1


def test_persist_finding_normalizes_bad_vocab(tmp_path):
    from backend.services.result_persistence import persist_finding

    factory = _sqlite_factory(tmp_path)
    scan_id, project_id = _seed_scan(factory)
    with factory() as session:
        row = persist_finding(
            session, scan_id=scan_id, project_id=project_id,
            finding={"title": "X", "severity": "apocalyptic", "status": "bogus", "tool": "t"},
        )
        assert row is not None
        assert row.scanner_severity == "info"
        assert row.status == "open"
        session.commit()


def test_persist_assets_dedupes(tmp_path):
    from backend.db.models import Asset
    from backend.services.result_persistence import persist_assets_from_observations

    factory = _sqlite_factory(tmp_path)
    scan_id, _ = _seed_scan(factory)
    obs = Observation(
        step=1, source="tool", tool="httpx", ok=True, summary="s",
        data={"services": [{"url": "http://h/", "final_url": "http://h/",
                            "status_code": 200}]},
        findings=[],
    )
    with factory() as session:
        from backend.db.models import Scan as ScanRow

        scan = session.get(ScanRow, scan_id)
        assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 1
        # second pass inserts nothing (identity dedup)
        assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 0
        session.commit()
        assert session.query(Asset).count() == 1
