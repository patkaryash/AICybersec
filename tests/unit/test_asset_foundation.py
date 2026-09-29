"""Unit tests: Phase 4A asset + finding foundation.

Covers asset builders, subdomain/endpoint persistence with parent
links, deduplication, deterministic finding -> asset linkage (and its
null-safe behavior), DNS enrichment as DATA, existing Nmap/HTTPX
persistence compatibility, and API serialization of the new types.

SQLite-backed (file tmp DB via Base.metadata.create_all) - the same
pattern as test_result_persistence; PostgreSQL migration coverage is
in tests/integration/test_migrations.py.
"""
from __future__ import annotations

import uuid

import pytest

from agent_core.schemas.results import Observation
from backend.services.result_persistence import (
    apply_dns_enrichment,
    assets_from_observation,
    build_domain_asset,
    build_endpoint_asset,
    build_subdomain_asset,
    link_findings_to_assets,
    persist_assets_from_observations,
    persist_finding,
    resolve_finding_asset_id,
)


def _sqlite_factory(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.db import models  # noqa: F401
    from backend.db.base import Base

    engine = create_engine(
        f"sqlite:///{tmp_path}/foundation.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed_scan(factory):
    from backend.db.models import Project, Scan, User

    with factory() as session:
        user = User(email="u@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(
            owner_id=user.id,
            name="P",
            scope=[{"type": "domain", "value": "example.com", "note": None}],
        )
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id,
            status="running",
            mode="pipeline",
            profile="full",
            target_snapshot=list(project.scope),
            tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id, project.id


def _get_scan(factory, scan_id):
    from backend.db.models import Scan as ScanRow

    with factory() as session:
        return session.get(ScanRow, scan_id)


# --- builders ------------------------------------------------------------


class TestAssetBuilders:
    def test_build_subdomain_asset(self):
        asset = build_subdomain_asset(
            hostname="API.Example.COM.",
            parent_domain="Example.COM",
            source="subfinder",
            source_tool="subfinder",
        )
        assert asset["asset_type"] == "subdomain"
        assert asset["value"] == "api.example.com"
        assert asset["host"] == "api.example.com"
        assert asset["attributes"]["parent_domain"] == "example.com"
        assert asset["attributes"]["source"] == "subfinder"
        assert asset["attributes"]["verification_status"] == "unverified"
        assert asset["parent_type"] == "domain"
        assert asset["parent_value"] == "example.com"

    def test_build_subdomain_without_parent_has_no_hint(self):
        asset = build_subdomain_asset(hostname="lonely.example.com")
        assert "parent_type" not in asset
        assert asset["attributes"]["verification_status"] == "unverified"

    def test_build_subdomain_bad_status_falls_back(self):
        asset = build_subdomain_asset(hostname="a.example.com", verification_status="bogus")
        assert asset["attributes"]["verification_status"] == "unverified"

    def test_build_endpoint_asset(self):
        asset = build_endpoint_asset(
            url="https://example.com:8443/app/login?x=1",
            source_page="https://example.com:8443/app",
            crawl_depth=2,
            http_method="get",
            source_tool="katana",
        )
        assert asset["asset_type"] == "endpoint"
        assert asset["value"] == "https://example.com:8443/app/login?x=1"
        assert asset["host"] == "example.com"
        assert asset["port"] == 8443
        assert asset["scheme"] == "https"
        assert asset["attributes"]["source_page"] == "https://example.com:8443/app"
        assert asset["attributes"]["crawl_depth"] == 2
        assert asset["attributes"]["http_method"] == "GET"
        assert asset["parent_type"] == "url"
        assert asset["parent_value"] == "https://example.com:8443/app"

    def test_build_domain_asset(self):
        asset = build_domain_asset(domain="Example.COM.")
        assert asset["asset_type"] == "domain"
        assert asset["value"] == "example.com"
        assert asset["host"] == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", "not a host", "http://x.com", "*.x.com"])
    def test_build_subdomain_rejects_malformed(self, bad: str):
        with pytest.raises(ValueError):
            build_subdomain_asset(hostname=bad)

    @pytest.mark.parametrize("bad", ["", "not-a-url", "://missing", "http://"])
    def test_build_endpoint_rejects_malformed(self, bad: str):
        with pytest.raises(ValueError):
            build_endpoint_asset(url=bad)


# --- observation mapping (future tools dormant, current tools intact) ----


class TestObservationMapping:
    def test_subfinder_observation_maps_to_subdomains(self):
        # Phase 4B: the observation's domain is emitted as a domain asset
        # (parent root) plus valid descendants as subdomain assets;
        # malformed/out-of-parent names are dropped.
        assets = assets_from_observation(
            {
                "source": "tool",
                "tool": "subfinder",
                "data": {
                    "domain": "example.com",
                    "subdomains": [
                        {"host": "api.example.com", "source": "crtsh"},
                        {"host": "evil payload !!", "source": "x"},
                        "not-a-dict",
                        {"host": "  "},
                        {"host": "evil.com"},
                        {"host": "example.com.evil.com"},
                    ],
                },
            }
        )
        by_value = {a["value"]: a for a in assets}
        assert by_value["example.com"]["asset_type"] == "domain"
        assert by_value["api.example.com"]["asset_type"] == "subdomain"
        assert by_value["api.example.com"]["parent_value"] == "example.com"
        assert "evil.com" not in by_value
        assert "example.com.evil.com" not in by_value
        assert len(assets) == 2

    def test_katana_observation_maps_to_endpoints(self):
        assets = assets_from_observation(
            {
                "source": "tool",
                "tool": "katana",
                "data": {
                    "endpoints": [
                        {
                            "url": "https://example.com/login",
                            "source_page": "https://example.com/",
                            "crawl_depth": 1,
                            "method": "get",
                        },
                        {"url": "not-a-url"},
                    ]
                },
            }
        )
        assert len(assets) == 1
        assert assets[0]["asset_type"] == "endpoint"
        assert assets[0]["attributes"]["crawl_depth"] == 1

    def test_dnsx_and_nuclei_yield_no_assets(self):
        assert assets_from_observation({"source": "tool", "tool": "dnsx", "data": {}}) == []
        assert (
            assets_from_observation({"source": "tool", "tool": "nuclei", "data": {}}) == []
        )

    def test_nmap_persistence_unchanged(self):
        obs = Observation(
            step=1, source="tool", tool="nmap", ok=True, summary="s",
            data={"hosts": [
                {"ip": "10.0.0.5", "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open",
                     "service": {"name": "http"}},
                    {"port": 22, "protocol": "tcp", "state": "closed"},
                ]},
            ]},
            findings=[],
        )
        assets = assets_from_observation(obs)
        by_value = {a["value"]: a for a in assets}
        assert by_value["10.0.0.5"]["asset_type"] == "host"
        assert by_value["10.0.0.5:80"]["asset_type"] == "service"

    def test_httpx_persistence_unchanged(self):
        obs = Observation(
            step=2, source="tool", tool="httpx", ok=True, summary="s",
            data={"services": [
                {"url": "http://h:8080/", "final_url": "http://h:8080/app",
                 "status_code": 200, "title": "T", "tech": ["nginx"]},
            ]},
            findings=[],
        )
        assets = assets_from_observation(obs)
        assert len(assets) == 1
        assert assets[0]["asset_type"] == "url"
        assert assets[0]["value"] == "http://h:8080/app"


# --- persistence: parents, dedup, null-safety -----------------------------


class TestAssetPersistence:
    def test_subdomain_persists_with_domain_parent_link(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        scan = _get_scan(factory, scan_id)
        with factory() as session:
            scan = session.merge(scan)
            # persist via observations to exercise the full path; Phase 4B
            # emits the domain root plus the subdomain, linked in-batch
            obs = Observation(
                step=1, source="tool", tool="subfinder", ok=True, summary="s",
                data={
                    "domain": "example.com",
                    "subdomains": [{"host": "api.example.com", "source": "crtsh"}],
                },
                findings=[],
            )
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 2
            row = session.query(Asset).filter(Asset.value == "api.example.com").one()
            assert row.asset_type == "subdomain"
            assert row.attributes["parent_domain"] == "example.com"
            parent = session.query(Asset).filter(Asset.value == "example.com").one()
            assert parent.asset_type == "domain"
            assert row.parent_asset_id == parent.id
            # rerun dedupes both rows
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 0
            session.commit()

    def test_parent_link_resolves_within_same_batch(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            httpx_obs = Observation(
                step=1, source="tool", tool="httpx", ok=True, summary="s",
                data={"services": [
                    {"url": "https://example.com/", "final_url": "https://example.com/",
                     "status_code": 200},
                ]},
                findings=[],
            )
            katana_obs = Observation(
                step=2, source="tool", tool="katana", ok=True, summary="s",
                data={"endpoints": [
                    {"url": "https://example.com/login",
                     "source_page": "https://example.com/", "crawl_depth": 1},
                ]},
                findings=[],
            )
            assert persist_assets_from_observations(
                session, scan=scan, observations=[httpx_obs, katana_obs]
            ) == 2
            endpoint = session.query(Asset).filter(
                Asset.asset_type == "endpoint").one()
            parent = session.query(Asset).filter(Asset.asset_type == "url").one()
            assert endpoint.parent_asset_id == parent.id
            session.commit()

    def test_unknown_parent_stays_null_and_reruns_dedupe(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            obs = Observation(
                step=1, source="tool", tool="katana", ok=True, summary="s",
                data={"endpoints": [
                    {"url": "https://example.com/orphan",
                     "source_page": "https://example.com/never-seen"},
                ]},
                findings=[],
            )
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 1
            row = session.query(Asset).filter(Asset.asset_type == "endpoint").one()
            assert row.parent_asset_id is None
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 0
            session.commit()
            assert session.query(Asset).count() == 1

    def test_endpoint_queryable_via_parent_join(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            parent = Asset(
                scan_id=scan.id, project_id=scan.project_id, asset_type="url",
                value="https://example.com/", host="example.com", port=443,
                scheme="https", parent_asset_id=None, attributes={},
                source_tool="httpx",
            )
            session.add(parent)
            session.flush()
            child = Asset(
                scan_id=scan.id, project_id=scan.project_id, asset_type="endpoint",
                value="https://example.com/login", host="example.com", port=443,
                scheme="https", parent_asset_id=parent.id,
                attributes={"source_page": "https://example.com/"},
                source_tool="katana",
            )
            session.add(child)
            session.commit()
            # relationship traversal: endpoint -> parent url
            got = (
                session.query(Asset)
                .filter(Asset.asset_type == "endpoint")
                .one()
            )
            par = session.get(Asset, got.parent_asset_id)
            assert par is not None and par.value == "https://example.com/"
            # children of a url: join query
            kids = (
                session.query(Asset)
                .filter(Asset.parent_asset_id == parent.id)
                .all()
            )
            assert [k.value for k in kids] == ["https://example.com/login"]


# --- finding -> asset linkage ----------------------------------------------


class TestFindingAssetLinkage:
    def _finding(self, target: str) -> dict:
        return {
            "id": "nuclei:t", "title": "Exposed panel", "severity": "high",
            "target": target, "description": "d",
            "evidence": {"template_id": "T-1", "matched_at": target},
            "tool": "nuclei", "confidence": "high", "status": "open",
            "references": [],
        }

    def test_exact_value_match_links(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            session.add(
                Asset(
                    scan_id=scan.id, project_id=scan.project_id, asset_type="url",
                    value="https://example.com/panel", host="example.com",
                    port=443, scheme="https", parent_asset_id=None,
                    attributes={}, source_tool="httpx",
                )
            )
            session.flush()
            row = persist_finding(
                session, scan_id=scan.id, project_id=scan.project_id,
                finding=self._finding("https://example.com/panel"),
            )
            assert row is not None
            assert row.asset_id is not None
            session.commit()

    def test_unknown_target_stays_null(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            row = persist_finding(
                session, scan_id=scan_id, project_id=project_id,
                finding=self._finding("https://unknown.example/x"),
            )
            assert row is not None
            assert row.asset_id is None
            session.commit()

    def test_ambiguous_host_match_stays_null(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            for value in ("https://example.com/a", "https://example.com/b"):
                session.add(
                    Asset(
                        scan_id=scan.id, project_id=scan.project_id,
                        asset_type="url", value=value, host="example.com",
                        port=443, scheme="https", parent_asset_id=None,
                        attributes={}, source_tool="httpx",
                    )
                )
            session.flush()
            # candidate matches two assets by host, no exact value hit
            asset_id = resolve_finding_asset_id(
                session, scan_id=scan.id, candidates=["https://example.com/other"]
            )
            assert asset_id is None
            session.commit()

    def test_backfill_links_after_assets_arrive(self, tmp_path):
        from backend.db.models import Asset
        from backend.db.models import Finding as FindingRow

        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            row = persist_finding(
                session, scan_id=scan_id, project_id=project_id,
                finding=self._finding("https://example.com/panel"),
            )
            assert row is not None and row.asset_id is None
            session.commit()
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            obs = Observation(
                step=1, source="tool", tool="httpx", ok=True, summary="s",
                data={"services": [
                    {"url": "https://example.com/panel",
                     "final_url": "https://example.com/panel", "status_code": 200},
                ]},
                findings=[],
            )
            assert persist_assets_from_observations(session, scan=scan, observations=[obs]) == 1
            assert link_findings_to_assets(session, scan=scan) == 1
            session.commit()
        with factory() as session:
            row = session.query(FindingRow).one()
            asset = session.get(Asset, row.asset_id)
            assert asset is not None and asset.value == "https://example.com/panel"

    def test_fingerprint_dedup_preserved_with_linkage(self, tmp_path):
        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            first = persist_finding(
                session, scan_id=scan_id, project_id=project_id,
                finding=self._finding("https://example.com/panel"),
            )
            assert first is not None
            session.commit()
            assert persist_finding(
                session, scan_id=scan_id, project_id=project_id,
                finding=self._finding("https://example.com/panel"),
            ) is None
            session.commit()


# --- DNS enrichment is DATA -------------------------------------------------


class TestDnsEnrichment:
    def test_enrichment_updates_matching_assets_only(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            session.add(
                Asset(
                    scan_id=scan.id, project_id=scan.project_id, asset_type="host",
                    value="example.com", host="example.com", port=None,
                    scheme=None, parent_asset_id=None, attributes={},
                    source_tool="nmap",
                )
            )
            session.flush()
            updated = apply_dns_enrichment(
                session, scan=scan,
                records=[
                    {"host": "Example.COM",
                     "dns_a": ["93.184.216.34"], "dns_aaaa": [], "dns_cname": []},
                    {"host": "unknown.example.com", "dns_a": ["1.2.3.4"]},
                    "garbage",
                    {"host": "  "},
                ],
            )
            assert updated == 1
            row = session.query(Asset).filter(Asset.value == "example.com").one()
            assert row.attributes["dns_a"] == ["93.184.216.34"]
            session.commit()

    def test_enrichment_does_not_create_assets(self, tmp_path):
        from backend.db.models import Asset

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            assert apply_dns_enrichment(
                session, scan=scan,
                records=[{"host": "new.example.com", "dns_a": ["1.2.3.4"]}],
            ) == 0
            assert session.query(Asset).count() == 0
            session.commit()


# --- API serialization ------------------------------------------------------


class TestApiSerialization:
    def test_asset_out_serializes_new_types(self, tmp_path):
        from backend.db.models import Asset
        from backend.schemas.assets import AssetOut

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            parent_id = uuid.uuid4()
            for asset_type, value in (
                ("subdomain", "api.example.com"),
                ("endpoint", "https://example.com/login"),
                ("domain", "example.com"),
            ):
                row = Asset(
                    scan_id=scan.id, project_id=scan.project_id,
                    asset_type=asset_type, value=value, host="example.com",
                    port=None, scheme=None, parent_asset_id=parent_id,
                    attributes={"source": "test"}, source_tool="test",
                )
                session.add(row)
                session.flush()
                out = AssetOut.model_validate(row, from_attributes=True)
                assert out.asset_type == asset_type
                assert out.parent_asset_id == parent_id
                assert out.value == value
            session.commit()

    def test_asset_out_legacy_types_have_null_parent(self, tmp_path):
        from backend.db.models import Asset
        from backend.schemas.assets import AssetOut

        factory = _sqlite_factory(tmp_path)
        scan_id, _ = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Scan as ScanRow

            scan = session.get(ScanRow, scan_id)
            row = Asset(
                scan_id=scan.id, project_id=scan.project_id, asset_type="host",
                value="10.0.0.5", host="10.0.0.5", port=None, scheme=None,
                parent_asset_id=None, attributes={}, source_tool="nmap",
            )
            session.add(row)
            session.flush()
            out = AssetOut.model_validate(row, from_attributes=True)
            assert out.parent_asset_id is None
            session.commit()

    def test_finding_out_carries_asset_link(self, tmp_path):
        from backend.schemas.findings import FindingOut

        factory = _sqlite_factory(tmp_path)
        scan_id, project_id = _seed_scan(factory)
        with factory() as session:
            from backend.db.models import Asset

            asset_id = uuid.uuid4()
            session.add(
                Asset(
                    id=asset_id, scan_id=scan_id, project_id=project_id,
                    asset_type="url", value="https://example.com/x",
                    host="example.com", port=443, scheme="https",
                    parent_asset_id=None, attributes={}, source_tool="httpx",
                )
            )
            session.flush()
            row = persist_finding(
                session, scan_id=scan_id, project_id=project_id,
                finding={
                    "title": "X", "severity": "high",
                    "target": "https://example.com/x",
                    "evidence": {"matched_at": "https://example.com/x"},
                    "tool": "nuclei", "status": "open",
                },
            )
            assert row is not None and row.asset_id == asset_id
            out = FindingOut.model_validate(row, from_attributes=True)
            assert out.asset_id == asset_id
            session.commit()
