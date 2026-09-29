"""Unit tests for Phase 4C DNSX data enrichment (SQLite, no DNS/network)."""
from __future__ import annotations

from agent_core.schemas.results import Observation, ToolResult
from backend.services.result_persistence import apply_dns_enrichment, apply_dnsx_enrichment


def _sqlite_factory(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.db import models  # noqa: F401
    from backend.db.base import Base

    engine = create_engine(
        f"sqlite:///{tmp_path}/dnsx-persistence.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed_scan(factory):
    from backend.db.models import Project, Scan, User

    scope = [{"type": "domain", "value": "example.com", "note": None}]
    with factory() as session:
        user = User(email="dnsx@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="DNSX", scope=scope)
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id,
            status="running",
            mode="pipeline",
            profile="full",
            target_snapshot=list(scope),
            tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id, project.id


def _asset(factory, scan_id, *, host, asset_type="subdomain", attributes=None):
    from backend.db.models import Asset, Scan

    with factory() as session:
        scan = session.get(Scan, scan_id)
        row = Asset(
            scan_id=scan.id,
            project_id=scan.project_id,
            asset_type=asset_type,
            value=host,
            host=host,
            port=None,
            scheme=None,
            parent_asset_id=None,
            attributes=attributes or {},
            source_tool="subfinder",
        )
        session.add(row)
        session.commit()


def _observation(hosts, records, *, tool="dnsx"):
    return Observation(
        step=1,
        source="tool",
        tool=tool,
        ok=True,
        summary="dnsx",
        data={"targets": hosts, "records": records, "skipped": 0, "truncated": False},
        findings=[],
    )


def _apply(factory, scan_id, observation):
    from backend.db.models import Scan

    with factory() as session:
        scan = session.get(Scan, scan_id)
        count = apply_dnsx_enrichment(session, scan=scan, observation=observation)
        session.commit()
        return count


def _get_asset(factory, scan_id, host):
    from backend.db.models import Asset

    with factory() as session:
        return session.query(Asset).filter(Asset.scan_id == scan_id, Asset.host == host).one_or_none()


class TestDnsxPersistence:
    def test_tool_result_compatible_structure(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})
        result = ToolResult(
            status="ok",
            data={
                "targets": ["api.example.com"],
                "records": [{"host": "api.example.com", "a": ["1.1.1.1"]}],
            },
            findings=[],
        )
        assert _apply(factory, scan_id, result) == 1
        assert _get_asset(factory, scan_id, "api.example.com").attributes["dns_a"] == ["1.1.1.1"]

    def test_existing_subdomain_receives_a_and_resolves(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})

        assert _apply(factory, scan_id, _observation(
            ["api.example.com"], [{"host": "api.example.com", "a": ["93.184.216.34"]}]
        )) == 1
        row = _get_asset(factory, scan_id, "api.example.com")
        assert row.attributes["dns_a"] == ["93.184.216.34"]
        assert row.attributes["verification_status"] == "resolved"

    def test_existing_subdomain_receives_aaaa_and_resolves(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="v6.example.com", attributes={"verification_status": "unverified"})

        _apply(factory, scan_id, _observation(
            ["v6.example.com"],
            [{"host": "v6.example.com", "aaaa": ["2001:db8::1"]}],
        ))
        row = _get_asset(factory, scan_id, "v6.example.com")
        assert row.attributes["dns_aaaa"] == ["2001:db8::1"]
        assert row.attributes["verification_status"] == "resolved"

    def test_cname_is_data_only_and_does_not_resolve(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="cdn.example.com", attributes={"verification_status": "unverified"})

        _apply(factory, scan_id, _observation(
            ["cdn.example.com"],
            [{"host": "cdn.example.com", "cname": ["edge.provider.net"]}],
        ))
        row = _get_asset(factory, scan_id, "cdn.example.com")
        assert row.attributes["dns_cname"] == ["edge.provider.net"]
        assert row.attributes["verification_status"] == "unverified"

    def test_existing_asset_receives_all_three(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="all.example.com", attributes={"verification_status": "unverified"})

        _apply(factory, scan_id, _observation(
            ["all.example.com"],
            [{
                "host": "all.example.com",
                "a": ["1.1.1.1"],
                "aaaa": ["2001:db8::2"],
                "cname": ["alias.example.net"],
            }],
        ))
        row = _get_asset(factory, scan_id, "all.example.com")
        assert row.attributes["dns_a"] == ["1.1.1.1"]
        assert row.attributes["dns_aaaa"] == ["2001:db8::2"]
        assert row.attributes["dns_cname"] == ["alias.example.net"]
        assert row.attributes["verification_status"] == "resolved"

    def test_unknown_host_and_dns_values_create_no_assets(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        assert _apply(factory, scan_id, _observation(
            ["unknown.example.com"],
            [{"host": "unknown.example.com", "a": ["1.1.1.1"]}],
        )) == 0
        with factory() as session:
            assert session.query(Asset).count() == 0

    def test_ip_and_cname_values_never_create_assets(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        assert _apply(factory, scan_id, _observation(
            ["existing.example.com"],
            [{
                "host": "existing.example.com",
                "a": ["192.0.2.1"],
                "aaaa": ["2001:db8::3"],
                "cname": ["target.example.net"],
            }],
        )) == 0
        with factory() as session:
            assert session.query(Asset).count() == 0

    def test_only_queried_hostname_can_match(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="queried.example.com", attributes={"verification_status": "unverified"})
        _asset(factory, scan_id, host="unqueried.example.com", attributes={"verification_status": "unverified"})

        _apply(factory, scan_id, _observation(
            ["queried.example.com"],
            [
                {"host": "queried.example.com", "a": ["1.1.1.1"]},
                {"host": "unqueried.example.com", "a": ["2.2.2.2"]},
            ],
        ))
        assert _get_asset(factory, scan_id, "queried.example.com").attributes["dns_a"] == ["1.1.1.1"]
        unrelated = _get_asset(factory, scan_id, "unqueried.example.com")
        assert unrelated.attributes == {"verification_status": "unverified"}

    def test_attributes_are_preserved_and_values_are_sorted_deduped(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(
            factory,
            scan_id,
            host="api.example.com",
            attributes={"verification_status": "unverified", "owner": "team-a", "dns_a": ["9.9.9.9"]},
        )
        _apply(factory, scan_id, _observation(
            ["api.example.com"],
            [{
                "host": "api.example.com",
                "a": ["9.9.9.9", "1.1.1.1", "1.1.1.1"],
                "aaaa": ["2001:db8::5", "2001:0db8:0:0:0:0:0:5"],
                "cname": ["B.Example.net", "a.example.net"],
            }],
        ))
        row = _get_asset(factory, scan_id, "api.example.com")
        assert row.attributes["owner"] == "team-a"
        assert row.attributes["dns_a"] == ["1.1.1.1", "9.9.9.9"]
        assert row.attributes["dns_aaaa"] == ["2001:db8::5"]
        assert row.attributes["dns_cname"] == ["a.example.net", "b.example.net"]

    def test_malformed_and_empty_observations_are_safe(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        assert _apply(factory, scan_id, _observation([], [])) == 0
        assert _apply(factory, scan_id, _observation(
            ["api.example.com"],
            [None, "bad", {}, {"host": "api.example.com", "a": ["not-an-ip"]}],
        )) == 0
        assert apply_dnsx_enrichment(
            None, scan=None, observation=ToolResult(status="error", data={})
        ) == 0

    def test_rejected_or_wrong_tool_observation_is_ignored(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})
        rejected = Observation(
            step=1,
            source="rejected",
            tool="dnsx",
            ok=False,
            summary="rejected",
            data={"targets": ["api.example.com"], "records": [{"host": "api.example.com", "a": ["1.1.1.1"]}]},
            findings=[],
        )
        wrong_tool = _observation(
            ["api.example.com"], [{"host": "api.example.com", "a": ["1.1.1.1"]}], tool="httpx"
        )
        assert _apply(factory, scan_id, rejected) == 0
        assert _apply(factory, scan_id, wrong_tool) == 0
        assert _get_asset(factory, scan_id, "api.example.com").attributes == {"verification_status": "unverified"}

    def test_scope_snapshot_findings_and_rows_unchanged(self, tmp_path):
        from backend.db.models import Asset, Finding, Project, Scan

        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})
        before_count = 1
        _apply(factory, scan_id, _observation(
            ["api.example.com"], [{"host": "api.example.com", "a": ["1.1.1.1"]}]
        ))
        with factory() as session:
            project = session.get(Project, project_id)
            scan = session.get(Scan, scan_id)
            assert project.scope == [{"type": "domain", "value": "example.com", "note": None}]
            assert scan.target_snapshot == project.scope
            assert session.query(Asset).count() == before_count
            assert session.query(Finding).count() == 0

    def test_repeated_enrichment_is_idempotent(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})
        obs = _observation(
            ["api.example.com"],
            [{"host": "api.example.com", "a": ["1.1.1.1", "1.1.1.1"]}],
        )
        assert _apply(factory, scan_id, obs) == 1
        assert _apply(factory, scan_id, obs) == 1
        row = _get_asset(factory, scan_id, "api.example.com")
        assert row.attributes == {"verification_status": "resolved", "dns_a": ["1.1.1.1"]}

    def test_direct_legacy_records_still_supported(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        _asset(factory, scan_id, host="api.example.com", attributes={"verification_status": "unverified"})
        from backend.db.models import Scan

        with factory() as session:
            scan = session.get(Scan, scan_id)
            assert apply_dns_enrichment(
                session,
                scan=scan,
                records=[{"host": "API.EXAMPLE.COM.", "dns_a": ["1.1.1.1"]}],
            ) == 1
            session.commit()
        assert _get_asset(factory, scan_id, "api.example.com").attributes["verification_status"] == "resolved"
