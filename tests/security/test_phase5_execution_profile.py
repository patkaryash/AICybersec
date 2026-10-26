"""Phase 5 Stage 2 (S2-2) unit/security tests: execution-profile contract.

Pure logic, no I/O: canonical rendering from the pinned constants,
strict-schema failures (extra=forbid), digest consistency only (never
authorization), §4.3 binding rules 1-3, budget/policy conformance, and
the §10 matrix rows T01-T04/T38 that need no database.

DB-backed behavior is covered by tests/integration/ (T03/T05/T06/T38@PG,
migration round trip, end-to-end refusal).
"""
from __future__ import annotations

import uuid

import pytest

from backend.services import live_probe_budgets as budgets
from backend.services import live_authorization_service as live
from backend.services.live_authorization_service import _digest

SCAN_ID = uuid.uuid4()
AUTH_ID = uuid.uuid4()
PROJECT_ID = uuid.uuid4()
PROFILE_ID = uuid.uuid4()
POLICY_VERSION = "live-probe/v1"


def _stub_settings(monkeypatch: pytest.MonkeyPatch, policy_version: str) -> None:
    from backend.core.config import BackendSettings

    monkeypatch.setattr(
        live,
        "get_backend_settings",
        lambda: BackendSettings(
            live_probe_enabled=False,
            live_probe_policy_version=policy_version,
        ),
    )


def _render(policy_version: str = POLICY_VERSION) -> dict:
    return budgets.render_execution_profile(
        profile_id=PROFILE_ID,
        scan_id=SCAN_ID,
        authorization_id=AUTH_ID,
        project_id=PROJECT_ID,
        policy_version=policy_version,
    )


def _scan_row(payload, digest, *, scan_id=SCAN_ID, auth_id=AUTH_ID, project_id=PROJECT_ID):
    """Duck-typed scan row for the pure verification function."""

    class _Row:
        pass

    row = _Row()
    row.id = scan_id
    row.live_authorization_id = auth_id
    row.project_id = project_id
    row.execution_profile = payload
    row.execution_profile_digest = digest
    return row


def _valid_scan(policy_version=POLICY_VERSION):
    payload = _render(policy_version)
    return _scan_row(payload, _digest(payload))


def _reforged(mutate, *, policy_version=POLICY_VERSION):
    """Attacker-style coordinated re-forge: mutate the payload AND
    recompute its digest (consistency holds; semantics decide)."""
    payload = _render(policy_version)
    mutate(payload)
    return _scan_row(payload, _digest(payload))


def _verify(monkeypatch: pytest.MonkeyPatch, scan, *, policy_version=POLICY_VERSION, snapshot_auth_id=AUTH_ID):
    _stub_settings(monkeypatch, policy_version)
    return live.verify_execution_profile(scan, snapshot_auth_id)


class TestProfileRendering:
    def test_canonical_shape_and_values_from_constants(self):
        payload = _render()
        assert set(payload) == {
            "profile_id",
            "scan_id",
            "authorization_id",
            "project_id",
            "policy_version",
            "mode",
            "steps",
            "executor",
            "budgets",
            "request_policy",
            "dns_policy",
        }
        assert payload["policy_version"] == POLICY_VERSION
        assert payload["mode"] == "pipeline"
        assert payload["steps"] == ["live_root_get"]
        assert payload["executor"] == "live_transport_v1"
        assert payload["budgets"] == {
            "max_requests_per_scan": 200,
            "requests_per_second": 1,
            "per_request_timeout_s": 30,
            "wall_clock_s": 600,
            "response_max_bytes": 262_144,
            "max_concurrent_connections": 2,
            "dns_timeout_s": 5,
        }
        assert payload["request_policy"] == {
            "methods": ["GET"],
            "paths": ["/"],
            "ports": [80, 443],
            "follow_redirects": False,
            "honor_env_proxies": False,
            "accept_encoding": "identity",
        }
        assert payload["dns_policy"] == {
            "record_groups": ["A", "AAAA"],
            "answer_set_policy": "all_answers_global",
            "cname_following": True,
            "cache": "none",
        }

    def test_render_is_deterministic_per_inputs(self):
        assert _render() == _render()
        other = budgets.render_execution_profile(
            profile_id=uuid.uuid4(),
            scan_id=SCAN_ID,
            authorization_id=AUTH_ID,
            project_id=PROJECT_ID,
            policy_version=POLICY_VERSION,
        )
        assert other != _render()  # profile_id binds the profile to a lifetime

    def test_no_digest_key_in_payload(self):
        # §4.2 lists exactly the canonical fields; the external anchor
        # column is the ONLY digest ("digest" keys are rejected as extra).
        assert "digest" not in _render()


class TestStrictSchema:
    def test_valid_profile_verifies(self, monkeypatch):
        assert _verify(monkeypatch, _valid_scan()) is not None

    def test_extra_top_level_field_rejected(self, monkeypatch):
        payload = _render()
        payload["digest"] = "0" * 64  # unknown field -> rejected, not ignored
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(payload, _digest(payload)))
        assert "schema" in e.value.message

    def test_extra_budget_field_rejected(self, monkeypatch):
        payload = _render()
        payload["budgets"]["extra_budget"] = 1
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(payload, _digest(payload)))
        assert "schema" in e.value.message

    def test_extra_step_rejected(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p.__setitem__("steps", ["live_root_get", "extra_step"])))
        assert "executor/steps" in e.value.message

    def test_renamed_step_rejected(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p.__setitem__("steps", ["live_root_get_renamed"])))
        assert "executor/steps" in e.value.message

    def test_string_budget_value_rejected(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p["budgets"].__setitem__("wall_clock_s", "600")))
        assert "schema" in e.value.message

    def test_int_bool_flag_rejected(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p["request_policy"].__setitem__("follow_redirects", 0)))
        assert "schema" in e.value.message

    def test_int_policy_version_rejected(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p.__setitem__("policy_version", 42)))
        assert "schema" in e.value.message

    def test_missing_budgets_rejected(self, monkeypatch):
        payload = _render()
        del payload["budgets"]
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(payload, _digest(payload)))
        assert "schema" in e.value.message

    def test_missing_dns_policy_rejected(self, monkeypatch):
        payload = _render()
        del payload["dns_policy"]
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(payload, _digest(payload)))
        assert "schema" in e.value.message


class TestProfileVerificationFailures:
    def test_T01_tampered_payload_stale_digest_fails_closed(self, monkeypatch):
        payload = _render()
        payload["request_policy"]["methods"] = ["GET", "POST"]
        with pytest.raises(Exception) as e:
            # digest stays the ORIGINAL (stale anchor)
            _verify(monkeypatch, _scan_row(payload, _digest(_render())))
        assert "integrity" in e.value.message

    def test_T01_garbage_anchor_fails_closed(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(_render(), "0" * 64))
        # a syntactically valid hex anchor that doesn't match = integrity
        assert "integrity" in e.value.message

    def test_T02_scan_id_mismatch_fails_closed(self, monkeypatch):
        scan = _scan_row(_render(), _digest(_render()), scan_id=uuid.uuid4())
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, scan)
        assert "scan row" in e.value.message

    def test_T03_missing_profile_fails_closed(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(None, _digest(_render())))
        assert "missing" in e.value.message

    def test_T03_missing_digest_fails_closed(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row(_render(), None))
        assert "missing" in e.value.message

    def test_T03_non_dict_profile_fails_closed(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _scan_row([], _digest(_render())))
        assert "missing" in e.value.message

    def test_T04_T38_reforged_authorization_id_fails_on_binding_not_digest(self, monkeypatch):
        scan = _reforged(lambda p: p.__setitem__("authorization_id", str(uuid.uuid4())))
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, scan)
        # A recomputed digest verifies; the BINDING rules fail.
        assert "authorization_id" in e.value.message
        assert "integrity" not in e.value.message

    def test_T04_T38_reforged_project_id_fails_on_binding_not_digest(self, monkeypatch):
        scan = _reforged(lambda p: p.__setitem__("project_id", str(uuid.uuid4())))
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, scan)
        assert "project_id" in e.value.message
        assert "integrity" not in e.value.message

    def test_T04_T38_reforged_scan_id_fails_on_binding_not_digest(self, monkeypatch):
        scan = _reforged(lambda p: p.__setitem__("scan_id", str(uuid.uuid4())))
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, scan)
        assert "scan row" in e.value.message
        assert "integrity" not in e.value.message

    def test_digest_consistency_never_authorizes(self, monkeypatch):
        # Coherent re-forge with all bindings swapped and a correctly
        # recomputed digest: must FAIL - digest equality never authorizes.
        def _swap(payload):
            payload["scan_id"] = str(uuid.uuid4())
            payload["authorization_id"] = str(uuid.uuid4())
            payload["project_id"] = str(uuid.uuid4())

        with pytest.raises(Exception):
            _verify(monkeypatch, _reforged(_swap))

    def test_snapshot_authorization_id_disagreement_fails(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _valid_scan(), snapshot_auth_id=uuid.uuid4())
        assert "authorization_id" in e.value.message


class TestPolicyVersionDrift:
    def test_profile_older_than_setting_drift_fails(self, monkeypatch):
        # Bump: profile rendered at v1, current setting now v2.
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _valid_scan(POLICY_VERSION), policy_version="live-probe/v2")
        assert "policy drift" in e.value.message

    def test_profile_newer_than_setting_fails(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _valid_scan("live-probe/v2"), policy_version=POLICY_VERSION)
        assert "policy drift" in e.value.message


class TestBudgetConformance:
    @pytest.mark.parametrize(
        "field,new_value",
        [
            ("max_requests_per_scan", 201),
            ("requests_per_second", 2),
            ("per_request_timeout_s", 29),
            ("wall_clock_s", 601),
            ("response_max_bytes", 262_145),
            ("max_concurrent_connections", 3),
            ("dns_timeout_s", 6),
        ],
    )
    def test_each_budget_field_altered_fails(self, monkeypatch, field, new_value):
        def _bump(payload):
            payload["budgets"][field] = new_value

        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(_bump))
        assert field in e.value.message

    def test_a_only_record_groups_fail(self, monkeypatch):
        with pytest.raises(Exception) as e:
            _verify(monkeypatch, _reforged(lambda p: p["dns_policy"].__setitem__("record_groups", ["A"])))
        assert "record_groups" in e.value.message

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda p: p["dns_policy"].__setitem__("answer_set_policy", "any"),
            lambda p: p["dns_policy"].__setitem__("cname_following", False),
            lambda p: p["dns_policy"].__setitem__("cache", "os"),
            lambda p: p["request_policy"].__setitem__("methods", ["POST"]),
            lambda p: p["request_policy"].__setitem__("paths", ["/admin"]),
            lambda p: p["request_policy"].__setitem__("ports", [8080]),
            lambda p: p["request_policy"].__setitem__("honor_env_proxies", True),
            lambda p: p["request_policy"].__setitem__("accept_encoding", "gzip"),
            lambda p: p.__setitem__("mode", "agent"),
        ],
    )
    def test_policy_field_altered_fails(self, monkeypatch, mutate):
        with pytest.raises(Exception):
            _verify(monkeypatch, _reforged(mutate))

    def test_executor_allowlist_enforced(self, monkeypatch):
        with pytest.raises(Exception):
            _verify(monkeypatch, _reforged(lambda p: p.__setitem__("executor", "vivisect")))
