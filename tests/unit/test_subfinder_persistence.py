"""Unit tests: Phase 4B subfinder persistence (SQLite, no network)."""
from __future__ import annotations

from agent_core.schemas.results import Observation
from backend.services.result_persistence import (
    assets_from_observation,
    persist_assets_from_observations,
)


def _sqlite_factory(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.db import models  # noqa: F401
    from backend.db.base import Base

    engine = create_engine(
        f"sqlite:///{tmp_path}/subfinder.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed_scan(factory, snapshot):
    from backend.db.models import Project, Scan, User

    with factory() as session:
        user = User(email="u@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=snapshot)
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id, status="running", mode="pipeline", profile="full",
            target_snapshot=list(snapshot), tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id


def _obs(domain: str, entries: list) -> Observation:
    return Observation(
        step=1, source="tool", tool="subfinder", ok=True, summary="s",
        data={"domain": domain, "subdomains": entries},
        findings=[],
    )


DOMAIN_SNAPSHOT = [{"type": "domain", "value": "example.com", "note": None}]


class TestSubfinderPersistence:
    def test_subdomain_asset_created_with_parent(self, tmp_path):
        from backend.db.models import Asset, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = _obs("example.com", [
                {"host": "api.example.com", "source": "crtsh",
                 "verification_status": "resolved", "dns_a": ["93.184.216.34"]},
                {"host": "dev.example.com", "source": "github",
                 "verification_status": "unverified"},
            ])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 3
            rows = {r.value: r for r in session.query(Asset).all()}
            assert set(rows) == {"example.com", "api.example.com", "dev.example.com"}
            assert rows["example.com"].asset_type == "domain"
            api = rows["api.example.com"]
            assert api.parent_asset_id == rows["example.com"].id
            assert api.attributes["verification_status"] == "resolved"
            assert api.attributes["dns_a"] == ["93.184.216.34"]
            assert api.attributes["source"] == "crtsh"
            assert rows["dev.example.com"].attributes["verification_status"] == "unverified"
            session.commit()

    def test_duplicate_suppressed(self, tmp_path):
        from backend.db.models import Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = _obs("example.com", [{"host": "api.example.com", "source": "crtsh"}])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 2
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 0
            session.commit()

    def test_invalid_discovery_not_persisted(self, tmp_path):
        from backend.db.models import Asset, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = _obs("example.com", [
                {"host": "*.example.com"},
                {"host": "http://api.example.com"},
                {"host": "not a host!!"},
                {"host": "example.com"},  # root itself
                "not-a-dict",
            ])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 1
            assert session.query(Asset).count() == 1  # domain root only
            session.commit()

    def test_out_of_scope_discovery_not_persisted(self, tmp_path):
        from backend.db.models import Asset, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = _obs("example.com", [
                {"host": "api.example.com"},
                {"host": "evil.com"},
                {"host": "example.com.evil.com"},
                {"host": "evil-example.com"},
            ])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 2
            values = {r.value for r in session.query(Asset).all()}
            assert values == {"example.com", "api.example.com"}
            session.commit()

    def test_snapshot_mismatch_yields_nothing(self, tmp_path):
        from backend.db.models import Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            # observation domain not an authorized snapshot parent
            obs = _obs("evil.com", [{"host": "x.evil.com"}])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 0
            session.commit()

    def test_no_host_assets_from_discovered_ips(self, tmp_path):
        from backend.db.models import Asset, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = Observation(
                step=1, source="tool", tool="subfinder", ok=True, summary="s",
                data={"domain": "example.com", "subdomains": [
                    {"host": "api.example.com", "source": "crtsh",
                     "verification_status": "resolved", "dns_a": ["93.184.216.34"]},
                ]},
                findings=[],
            )
            persist_assets_from_observations(session, scan=scan, observations=[obs])
            types = {r.asset_type for r in session.query(Asset).all()}
            assert types == {"domain", "subdomain"}
            session.commit()

    def test_host_scope_parent_supported(self, tmp_path):
        from backend.db.models import Asset, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        snapshot = [{"type": "host", "value": "api.example.com", "note": None}]
        scan_id = _seed_scan(factory, snapshot)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            obs = _obs("api.example.com", [{"host": "x.api.example.com"}])
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 2
            values = {r.value for r in session.query(Asset).all()}
            assert values == {"api.example.com", "x.api.example.com"}
            session.commit()

    def test_project_scope_never_mutated(self, tmp_path):
        from backend.db.models import Project, Scan as ScanRow

        factory = _sqlite_factory(tmp_path)
        scan_id = _seed_scan(factory, DOMAIN_SNAPSHOT)
        with factory() as session:
            scan = session.get(ScanRow, scan_id)
            before = list(scan.target_snapshot)
            obs = _obs("example.com", [{"host": "api.example.com"}])
            persist_assets_from_observations(session, scan=scan, observations=[obs])
            session.commit()
            assert scan.target_snapshot == before
            project = session.get(Project, scan.project_id)
            assert project.scope == DOMAIN_SNAPSHOT

    def test_direct_mapping_without_snapshot_context(self):
        assets = assets_from_observation(
            {"source": "tool", "tool": "subfinder",
             "data": {"domain": "example.com",
                      "subdomains": [{"host": "a.example.com"}]}},
            snapshot=None,
        )
        assert {a["value"] for a in assets} == {"example.com", "a.example.com"}
