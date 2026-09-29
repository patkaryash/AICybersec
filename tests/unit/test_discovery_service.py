"""Focused deterministic discovery-service tests (no network/subprocesses)."""
from __future__ import annotations

import threading
from types import SimpleNamespace

from pydantic import BaseModel, Field

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.results import ToolResult
from agent_core.schemas.state import AgentState
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.dnsx import MAX_TARGETS
from agent_core.tools.registry import ToolRegistry
from backend.services.discovery_service import DiscoveryService, _default_asset_hosts


class StubSubfinderParams(BaseModel):
    domain: str


class StubDnsxParams(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)


class StubSubfinder(Tool):
    name = "subfinder"
    description = "test subfinder"
    input_model = StubSubfinderParams
    danger_level = "safe"

    def __init__(self, data_by_domain, calls):
        self.data_by_domain = data_by_domain
        self.calls = calls

    def policy_target(self, params):
        return params.get("domain")

    def execute(self, params, ctx: ToolContext):
        self.calls.append(params.domain)
        return ToolResult(status="ok", data=self.data_by_domain.get(params.domain, {}), findings=[])


class StubDnsx(Tool):
    name = "dnsx"
    description = "test dnsx"
    input_model = StubDnsxParams
    danger_level = "safe"

    def __init__(self, records_by_host, calls, failures=None, policy_calls=None, on_call=None):
        self.records_by_host = records_by_host
        self.calls = calls
        self.failures = set(failures or ())
        self.policy_calls = policy_calls if policy_calls is not None else []
        self.on_call = on_call

    def policy_targets(self, params):
        return params.get("targets", [])

    def execute(self, params, ctx: ToolContext):
        batch = list(params.targets)
        self.calls.append(batch)
        self.policy_calls.append(list(ctx.allowed_targets))
        if self.on_call is not None:
            self.on_call()
        if any(host in self.failures for host in batch):
            return ToolResult(status="error", summary="dnsx batch failed", findings=[])
        return ToolResult(
            status="ok",
            data={
                "targets": batch,
                "records": [self.records_by_host[host] for host in batch if host in self.records_by_host],
            },
            findings=[],
        )


def _service(
    subfinder_data,
    dns_records,
    *,
    snapshot=None,
    allowed=None,
    existing=None,
    dns_failures=None,
    persist_subfinder=None,
    persist_dnsx=None,
    policy_calls=None,
    on_dns_call=None,
):
    sub_calls = []
    dns_calls = []
    registry = ToolRegistry()
    registry.register(StubSubfinder(subfinder_data, sub_calls))
    registry.register(
        StubDnsx(
            dns_records,
            dns_calls,
            failures=dns_failures,
            policy_calls=policy_calls,
            on_call=on_dns_call,
        )
    )
    policy = Policy(
        allowed_targets=list(["example.com"] if allowed is None else allowed),
        max_danger="active_scan",
    )
    validator = SafetyValidator(registry, policy)
    service = DiscoveryService(
        registry=registry,
        validator=validator,
        persist_subfinder=persist_subfinder or (lambda session, scan, obs: 0),
        persist_dnsx=persist_dnsx or (lambda session, scan, result: 1),
        asset_hosts=lambda session, scan, hosts: set(hosts if existing is None else existing),
    )
    scan = SimpleNamespace(
        id="scan-1",
        project_id="project-1",
        target_snapshot=snapshot or [{"type": "domain", "value": "example.com"}],
    )
    return service, scan, sub_calls, dns_calls


def _run(service, scan, cancel=None):
    return service.run(
        session=object(),
        scan=scan,
        cancel=cancel,
        state=AgentState(run_id="test-run", goal="discover", max_steps=100),
    )


def test_authorized_parent_calls_subfinder_and_promotes_a_result():
    service, scan, sub_calls, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "app.example.com"}]}},
        {"app.example.com": {"host": "app.example.com", "a": ["192.0.2.10"]}},
        existing={"app.example.com"},
    )
    result = _run(service, scan)
    assert sub_calls == ["example.com"]
    assert dns_calls == [["app.example.com"]]
    assert result.discovered == ["app.example.com"]
    assert result.dns_verified == ["app.example.com"]
    assert result.promoted == ["app.example.com"]


def test_snapshot_parents_are_the_only_subfinder_targets():
    service, scan, sub_calls, _ = _service(
        {
            "example.com": {"domain": "example.com", "subdomains": []},
            "evil.com": {"domain": "evil.com", "subdomains": []},
        },
        {},
        snapshot=[
            {"type": "domain", "value": "example.com"},
            {"type": "domain", "value": "evil.com"},
        ],
        allowed=["example.com"],
    )
    result = _run(service, scan)
    assert sub_calls == ["example.com"]
    assert "evil.com" in result.policy_rejected


def test_invalid_snapshot_parent_shapes_are_never_queried():
    service, scan, sub_calls, _ = _service(
        {},
        {},
        snapshot=[
            {"type": "url", "value": "https://example.com"},
            {"type": "domain", "value": "10.0.0.1"},
            {"type": "domain", "value": "*.example.com"},
            {"type": "domain", "value": "example.com"},
        ],
    )
    _run(service, scan)
    assert sub_calls == ["example.com"]


def test_subfinder_policy_rejects_bad_descendants_and_deduplicates():
    service, scan, _, dns_calls = _service(
        {
            "example.com": {
                "domain": "example.com",
                "subdomains": [
                    {"host": "api.example.com"},
                    {"host": "API.EXAMPLE.COM."},
                    {"host": "evil-example.com"},
                    {"host": "example.com.evil.com"},
                    {"host": "https://api.example.com"},
                    {"host": "192.0.2.2"},
                    {"host": "*.example.com"},
                ],
            }
        },
        {"api.example.com": {"host": "api.example.com", "a": ["192.0.2.1"]}},
    )
    result = _run(service, scan)
    assert result.discovered == ["api.example.com"]
    assert result.policy_rejected == sorted([
        "evil-example.com",
        "example.com.evil.com",
        "https://api.example.com",
        "192.0.2.2",
        "*.example.com",
    ])
    assert dns_calls == [["api.example.com"]]


def test_subfinder_domain_mismatch_is_not_persisted_or_queried():
    persisted = []
    service, scan, _, dns_calls = _service(
        {
            "example.com": {
                "domain": "other-authorized.example",
                "subdomains": [{"host": "x.other-authorized.example"}],
            }
        },
        {},
        snapshot=[
            {"type": "domain", "value": "example.com"},
            {"type": "domain", "value": "other-authorized.example"},
        ],
        persist_subfinder=lambda *args: persisted.append(args) or 1,
    )
    result = _run(service, scan)
    assert persisted == []
    assert dns_calls == []
    assert result.discovered == []


def test_dnsx_batches_are_bounded_and_only_validated_hosts_are_sent():
    hosts = [f"h{i}.example.com" for i in range(41)]
    entries = [{"host": host} for host in hosts] + [{"host": "evil.com"}]
    records = {host: {"host": host, "a": [f"192.0.2.{(i % 200) + 1}"]} for i, host in enumerate(hosts)}
    service, scan, _, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": entries}},
        records,
        existing=set(hosts),
    )
    result = _run(service, scan)
    assert [len(batch) for batch in dns_calls] == [20, 20, 1]
    assert all(set(batch).issubset(set(hosts)) for batch in dns_calls)
    assert result.promoted == sorted(hosts)


def test_each_temporary_dnsx_policy_contains_only_its_validated_batch():
    hosts = [f"h{i}.example.com" for i in range(21)]
    policy_calls = []
    service, scan, _, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": h} for h in hosts]}},
        {h: {"host": h, "a": ["192.0.2.10"]} for h in hosts},
        allowed=["example.com", "203.0.113.10", "https://unrelated.test/path", "*.bad.test", "198.51.100.5"],
        existing=set(hosts),
        policy_calls=policy_calls,
    )
    result = _run(service, scan)
    assert [len(batch) for batch in dns_calls] == [20, 1]
    assert policy_calls == dns_calls
    forbidden = {"example.com", "203.0.113.10", "https://unrelated.test/path", "*.bad.test", "198.51.100.5"}
    for policy_batch, dns_batch in zip(policy_calls, dns_calls):
        assert policy_batch == dns_batch
        assert not forbidden.intersection(policy_batch)
    assert result.promoted == sorted(hosts)


def test_empty_discovery_does_not_call_dnsx():
    service, scan, _, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": []}}, {},
    )
    result = _run(service, scan)
    assert result.discovered == []
    assert result.dnsx_calls == 0
    assert dns_calls == []


def test_aaaa_promotes_but_dns_ip_is_never_promoted():
    service, scan, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "v6.example.com"}]}},
        {"v6.example.com": {"host": "v6.example.com", "aaaa": ["2001:db8::1"]}},
        existing={"v6.example.com"},
    )
    result = _run(service, scan)
    assert result.promoted == ["v6.example.com"]
    assert all("2001:db8::1" not in value for value in result.promoted)


def test_cname_only_does_not_promote_or_follow_target():
    service, scan, _, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "cdn.example.com"}]}},
        {"cdn.example.com": {"host": "cdn.example.com", "cname": ["internal.example.net"]}},
        existing={"cdn.example.com", "internal.example.net"},
    )
    result = _run(service, scan)
    assert dns_calls == [["cdn.example.com"]]
    assert result.dns_verified == []
    assert result.promoted == []
    assert "internal.example.net" not in result.discovered


def test_dnsx_failure_does_not_promote_batch():
    service, scan, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [
            {"host": "a.example.com"}, {"host": "b.example.com"}
        ]}},
        {
            "a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]},
            "b.example.com": {"host": "b.example.com", "a": ["192.0.2.2"]},
        },
        existing={"a.example.com", "b.example.com"},
        dns_failures={"b.example.com"},
    )
    result = _run(service, scan)
    assert result.promoted == []
    assert result.dns_verified == []
    assert result.dns_unverified == ["a.example.com", "b.example.com"]


def test_dnsx_persistence_noop_does_not_promote():
    service, scan, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "a.example.com"}]}},
        {"a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]}},
        existing={"a.example.com"},
        persist_dnsx=lambda *args: 0,
    )
    result = _run(service, scan)
    assert result.dns_verified == []
    assert result.promoted == []
    assert result.dns_unverified == ["a.example.com"]


def test_missing_asset_prevents_promotion_and_persistence_is_called():
    persisted = {"subfinder": 0, "dnsx": 0}
    service, scan, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "a.example.com"}]}},
        {"a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]}},
        existing=set(),
        persist_subfinder=lambda *args: persisted.__setitem__("subfinder", persisted["subfinder"] + 1) or 1,
        persist_dnsx=lambda *args: persisted.__setitem__("dnsx", persisted["dnsx"] + 1) or 1,
    )
    result = _run(service, scan)
    assert persisted == {"subfinder": 1, "dnsx": 1}
    assert result.dns_verified == ["a.example.com"]
    assert result.promoted == []


def test_validator_rejection_prevents_execution():
    service, scan, sub_calls, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": []}}, {}, allowed=[]
    )
    result = _run(service, scan)
    assert sub_calls == []
    assert dns_calls == []
    assert result.policy_rejected == ["example.com"]


def test_cancellation_before_subfinder_and_between_stages():
    cancel = threading.Event()
    cancel.set()
    service, scan, sub_calls, dns_calls = _service({}, {})
    result = _run(service, scan, cancel)
    assert result.cancelled is True
    assert sub_calls == [] and dns_calls == []

    class CancelAfterSubfinder:
        def __init__(self):
            self.event = threading.Event()
        def persist(self, *args):
            self.event.set()
            return 1

    cancellation = CancelAfterSubfinder()
    service, scan, sub_calls, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "a.example.com"}]}},
        {"a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]}},
        persist_subfinder=cancellation.persist,
    )
    result = _run(service, scan, cancellation.event)
    assert result.cancelled is True
    assert sub_calls == ["example.com"]
    assert dns_calls == []

    cancellation = threading.Event()
    dns_calls_after_first = []

    def cancel_after_first_dnsx():
        if len(dns_calls_after_first) == 1:
            cancellation.set()

    service, scan, _, dns_calls = _service(
        {"example.com": {"domain": "example.com", "subdomains": [
            {"host": "a.example.com"}, {"host": "b.example.com"}, {"host": "c.example.com"}
        ]}},
        {
            "a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]},
            "b.example.com": {"host": "b.example.com", "a": ["192.0.2.2"]},
            "c.example.com": {"host": "c.example.com", "a": ["192.0.2.3"]},
        },
        existing={"a.example.com", "b.example.com", "c.example.com"},
        policy_calls=dns_calls_after_first,
        on_dns_call=cancel_after_first_dnsx,
    )
    # Force one target per batch to exercise the between-batch check.
    import backend.services.discovery_service as discovery_module

    original_batch_size = discovery_module.MAX_DNSX_TARGETS
    discovery_module.MAX_DNSX_TARGETS = 1
    try:
        result = _run(service, scan, cancellation)
    finally:
        discovery_module.MAX_DNSX_TARGETS = original_batch_size
    assert result.cancelled is True
    assert len(dns_calls) == 1
    assert result.promoted == []


def test_result_is_deterministic_and_policy_objects_are_not_mutated():
    policy = Policy(allowed_targets=["example.com"], max_danger="active_scan")
    registry = ToolRegistry()
    sub_calls, dns_calls = [], []
    registry.register(StubSubfinder({"example.com": {
        "domain": "example.com",
        "subdomains": [{"host": "z.example.com"}, {"host": "a.example.com"}],
    }}, sub_calls))
    registry.register(StubDnsx({
        "a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]},
        "z.example.com": {"host": "z.example.com", "a": ["192.0.2.2"]},
    }, dns_calls))
    validator = SafetyValidator(registry, policy)
    original_allowed = list(policy.allowed_targets)
    original_policy = policy.model_dump(mode="json")
    service = DiscoveryService(
        registry=registry,
        validator=validator,
        persist_subfinder=lambda *args: 0,
        persist_dnsx=lambda *args: 1,
        asset_hosts=lambda *args: {"a.example.com", "z.example.com"},
    )
    scan = SimpleNamespace(id="s", target_snapshot=[{"type": "domain", "value": "example.com"}])
    first = _run(service, scan)
    second = _run(service, scan)
    assert first.promoted == ["a.example.com", "z.example.com"]
    assert first.__dict__ == second.__dict__
    assert policy.allowed_targets == original_allowed
    assert policy.model_dump(mode="json") == original_policy


def test_persistence_failure_removes_dns_verification_from_promotion():
    service, scan, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "a.example.com"}]}},
        {"a.example.com": {"host": "a.example.com", "a": ["192.0.2.1"]}},
        existing={"a.example.com"},
        persist_dnsx=lambda *args: (_ for _ in ()).throw(RuntimeError("db failed")),
    )
    result = _run(service, scan)
    assert result.dns_verified == []
    assert result.promoted == []
    assert result.dns_unverified == ["a.example.com"]


def test_default_persistence_enriches_existing_asset_without_scope_mutation(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.db import models  # noqa: F401
    from backend.db.base import Base
    from backend.db.models import Project, Scan, User

    engine = create_engine(f"sqlite:///{tmp_path}/discovery.db")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    scope = [{"type": "domain", "value": "example.com", "note": None}]
    with factory() as session:
        user = User(email="discovery@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="discovery", scope=scope)
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
        scan_id = scan.id
        project_id = project.id

    service, _, _, _ = _service(
        {"example.com": {"domain": "example.com", "subdomains": [{"host": "app.example.com"}]}},
        {"app.example.com": {"host": "app.example.com", "a": ["192.0.2.20"]}},
        existing={"app.example.com"},
        persist_subfinder=None,
        persist_dnsx=None,
    )
    # Replace the test-only persistence seams with the production defaults.
    service.persist_subfinder = service._persist_subfinder
    service.persist_dnsx = service._persist_dnsx
    service.asset_hosts = _default_asset_hosts
    with factory() as session:
        from backend.db.models import Asset

        scan = session.get(Scan, scan_id)
        result = service.run(
            session=session,
            scan=scan,
            state=AgentState(run_id="real-persist", goal="discover", max_steps=10),
        )
        session.commit()
        assert result.promoted == ["app.example.com"]
        assert session.get(Project, project_id).scope == scope
        assert scan.target_snapshot == scope
        row = session.query(Asset).filter(Asset.host == "app.example.com").one()
        assert row.attributes["dns_a"] == ["192.0.2.20"]
        assert row.attributes["verification_status"] == "resolved"
        assert session.query(Asset).count() == 2
