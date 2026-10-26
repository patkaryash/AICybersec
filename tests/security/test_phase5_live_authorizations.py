"""Phase 5 Stage 1 unit/security tests: pure authorization logic.

No DB, no network: origin canonicalization/rejection, evidence rules,
lifetime cap, exclusion precedence, snapshot tamper detection (embedded
digest + external anchor), policy-version drift, window checks.

The DB-backed lifecycle/API behavior is covered by
tests/api/test_live_scan_authorizations.py and the PostgreSQL
integration tests (tests/integration/).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.core.config import BackendSettings, get_backend_settings
from backend.core.errors import ApiError, ErrorCode
from backend.schemas.scans import PROFILE_TOTAL_STEPS, ScanProfile
from backend.services import live_authorization_service as live
from backend.services.live_authorization_service import (
    _digest,
    _snapshot_core,
    authorization_payload,
    effective_origins,
    parse_origin,
    verify_snapshot_payload,
)

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)


def _settings(max_days: int = 90, policy_version: str = "live-probe/v1") -> BackendSettings:
    return BackendSettings(
        live_probe_enabled=False,
        live_probe_policy_version=policy_version,
        live_probe_max_authorization_days=max_days,
    )


class TestOriginValidation:
    def test_accepts_and_canonicalizes_exact_origins(self):
        o = parse_origin("https://Example.COM")
        assert o == {"origin": "https://example.com", "scheme": "https",
                     "host": "example.com", "port": 443}
        # explicit default port collapses onto the canonical spelling
        assert parse_origin("http://example.com:80")["origin"] == "http://example.com"
        assert parse_origin("https://example.com:443")["port"] == 443

    def test_rejects_ip_literals_f1(self):
        """F1: IP literals (IPv4, bracketed/bare IPv6, hex forms) and
        digits-only hostnames are rejected outright - no silent
        canonicalization, no bracket-stripping bugs possible."""
        raw_ips = [
            "http://127.0.0.1",
            "https://10.0.0.5",
            "http://169.254.169.254",          # metadata service
            "http://[::1]:80",
            "http://::1",                       # brackets stripped raw
            "https://[2001:db8::1]:443",
            "http://[::ffff:127.0.0.1]:80",     # IPv4-mapped IPv6
            "http://::ffff:127.0.0.1",
            "http://::ffff:169.254.169.254",
            "http://0x7f.0.0.1",                # hex-octet non-IP dotted
            "https://999.999.999.999",          # dotted-quad, invalid IP
            "http://0177.0.0.1",                # leading-zero octets
            "https://2130706433",               # digits-only integer form
            "https://12345",                    # digits-only hostname
        ]
        for raw in raw_ips:
            with pytest.raises(ApiError) as e:
                parse_origin(raw)
            # Rejections must either SAY they are IP-literal rejections,
            # or be structural invalids (e.g. "http://::1" never parses to
            # a usable host at all). Both fail closed; both are fine.
            assert (
                "IP-literal" in e.value.message or "Invalid live origin" in e.value.message
            ), raw

    @pytest.mark.parametrize("raw", [
        "https://a?.com", "https://a#.com", "https://a.com??", "https://a.com##",
    ])
    def test_rejects_delimiters_anywhere_f4(self, raw):
        with pytest.raises(ApiError):
            parse_origin(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            "https://*.example.com",        # wildcard
            "https://*.example.com/",       # wildcard + path
            "ftp://example.com",            # unsupported scheme
            "javascript:alert(1)",          # junk scheme
            "example.com",                  # missing scheme
            "http://user@example.com",      # userinfo
            "https://u:p@example.com",      # embedded credentials
            "https://example.com/path",     # path
            "https://example.com/",         # bare slash path
            "https://example.com/?q=1",     # query
            "https://example.com/#frag",    # fragment
            "https://example.com?q=1",      # query without path
            "https://example.com#frag",     # fragment without path
            # F4: EMPTY query/fragment delimiters parse as empty strings,
            # so truthiness checks must never be relied upon
            "https://example.com/?",        # empty query
            "https://example.com?#",        # empty query + fragment
            "http://example.com:8080",      # unsupported port
            "https://example.com:80",       # scheme/port mismatch
            "http://example.com:443",       # scheme/port mismatch
            "https://exa mple.com",         # whitespace
            "https://-bad-.example.com",    # invalid label
            "https://a" + ".b" * 200,       # oversized hostname
            "",
            None,
            42,
        ],
    )
    def test_rejects_invalid_origins(self, raw):
        with pytest.raises(ApiError):
            parse_origin(raw)

    def test_rejections_use_live_authorization_invalid(self):
        with pytest.raises(ApiError) as e:
            parse_origin("http://example.com:8080")
        assert e.value.code == ErrorCode.LIVE_AUTHORIZATION_INVALID


class TestEvidenceRequirement:
    def test_requires_evidence(self):
        with pytest.raises(ApiError) as e:
            live._validate_evidence(None, None)
        assert e.value.code == ErrorCode.LIVE_AUTHORIZATION_INVALID

    def test_accepts_ref_only_and_hash_only(self):
        assert live._validate_evidence("signed-agreement #4301", None) == (
            "signed-agreement #4301",
            None,
        )
        sha = "a" * 64
        assert live._validate_evidence(None, sha) == (None, sha)

    def test_rejects_non_sha256_hash(self):
        with pytest.raises(ApiError):
            live._validate_evidence(None, "not-a-hash")
        with pytest.raises(ApiError):
            live._validate_evidence(None, "g" * 64)


class TestExclusionPrecedence:
    def test_exclusions_override_allow_rules(self):
        allowed = [parse_origin("https://a.com"), parse_origin("https://b.com")]
        excluded = [parse_origin("https://a.com")]
        eff = effective_origins(allowed, excluded)
        assert [e["origin"] for e in eff] == ["https://b.com"]

    def test_exclusion_of_unknown_origin_is_harmless(self):
        allowed = [parse_origin("https://a.com")]
        excluded = [parse_origin("https://nope.com")]
        assert len(effective_origins(allowed, excluded)) == 1


def _auth_record(*, origins=("https://example.com",), exclusions=(), status="active",
                 valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=30),
                 policy_version="live-probe/v1", methods=("GET",)):
    """Duck-typed authorization record for payload rendering."""

    class A:
        pass

    a = A()
    a.id = "11111111-1111-1111-1111-111111111111"
    a.project_id = "22222222-2222-2222-2222-222222222222"
    a.status = status
    a.policy_version = policy_version
    a.valid_from = valid_from
    a.valid_until = valid_until
    a.origins = [parse_origin(x) for x in origins]
    a.exclusions = [parse_origin(x) for x in exclusions]
    a.methods = list(methods)
    return a


class TestAuthorizationPayload:
    def test_monkeypatched_settings_policy_version(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        payload = authorization_payload(_auth_record(), now=NOW)
        assert payload["policy_version"] == "live-probe/v1"
        assert payload["methods"] == ["GET"]
        assert payload["paths"] == ["/"]
        assert payload["follow_redirects"] is False
        assert payload["discovery"] is False

    def test_suspended_revoked_rejected(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        for status in ("suspended", "revoked"):
            with pytest.raises(ApiError) as e:
                authorization_payload(_auth_record(status=status), now=NOW)
            assert e.value.code == ErrorCode.LIVE_SCAN_NOT_PERMITTED

    def test_not_yet_valid_and_expired_rejected(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        fut = _auth_record(valid_from=NOW + timedelta(days=1),
                           valid_until=NOW + timedelta(days=10))
        with pytest.raises(ApiError) as e:
            authorization_payload(fut, now=NOW)
        assert "not yet valid" in e.value.message

        past = _auth_record(valid_from=NOW - timedelta(days=10),
                            valid_until=NOW - timedelta(days=1))
        with pytest.raises(ApiError) as e:
            authorization_payload(past, now=NOW)
        assert "expired" in e.value.message

    def test_policy_version_drift_rejected(self, monkeypatch):
        monkeypatch.setattr(
            live, "get_backend_settings", lambda: _settings(policy_version="live-probe/v2")
        )
        with pytest.raises(ApiError) as e:
            authorization_payload(_auth_record(), now=NOW)
        assert "policy drift" in e.value.message

    def test_effectively_empty_origins_rejected(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        a = _auth_record(origins=("https://example.com",),
                         exclusions=("https://example.com",))
        with pytest.raises(ApiError) as e:
            authorization_payload(a, now=NOW)
        assert "Exclusions remove every approved origin" in e.value.message

    def test_wrong_methods_rejected(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        with pytest.raises(ApiError):
            authorization_payload(_auth_record(methods=("POST",)), now=NOW)


class TestSnapshotIntegrity:
    """Tamper detection with fully forged snapshots (attacker-style)."""

    def _snapshot(self, monkeypatch):
        monkeypatch.setattr(live, "get_backend_settings", lambda: _settings())
        snapshot = dict(authorization_payload(_auth_record(), now=NOW))
        snapshot["digest"] = _digest(_snapshot_core(snapshot))
        return snapshot

    def test_valid_snapshot_verifies(self, monkeypatch):
        s = self._snapshot(monkeypatch)
        core = verify_snapshot_payload(s, s["digest"], now=NOW,
                                       policy_version="live-probe/v1")
        assert str(core["authorization_id"]) == "11111111-1111-1111-1111-111111111111"

    def test_field_mutation_without_digest_update_detected(self, monkeypatch):
        s = self._snapshot(monkeypatch)
        s["origins"] = [parse_origin("https://evil.com")]
        with pytest.raises(ApiError):
            verify_snapshot_payload(s, s["digest"], now=NOW,
                                    policy_version="live-probe/v1")

    def test_external_digest_anchor_mismatch_detected(self, monkeypatch):
        s = self._snapshot(monkeypatch)
        with pytest.raises(ApiError):
            verify_snapshot_payload(s, "0" * 64, now=NOW,
                                    policy_version="live-probe/v1")

    def test_missing_external_digest_detected(self, monkeypatch):
        s = self._snapshot(monkeypatch)
        with pytest.raises(ApiError):
            verify_snapshot_payload(s, None, now=NOW, policy_version="live-probe/v1")

    def test_non_dict_and_missing_fields_detected(self, monkeypatch):
        with pytest.raises(ApiError):
            verify_snapshot_payload(None, "a" * 64, now=NOW,
                                    policy_version="live-probe/v1")
        with pytest.raises(ApiError):
            verify_snapshot_payload({"digest": "b" * 64}, "b" * 64, now=NOW,
                                    policy_version="live-probe/v1")

    def test_removed_no_redirect_flag_rejected(self, monkeypatch):
        s = self._snapshot(monkeypatch)
        del s["follow_redirects"]
        s["digest"] = _digest(_snapshot_core(s))
        with pytest.raises(ApiError):
            verify_snapshot_payload(s, s["digest"], now=NOW,
                                    policy_version="live-probe/v1")

    def test_snapshot_window_expiry_detected(self, monkeypatch):
        from datetime import datetime as dt

        s = self._snapshot(monkeypatch)
        late = dt.fromisoformat(s["valid_until"].replace("Z", "+00:00")) + timedelta(seconds=1)
        with pytest.raises(ApiError) as e:
            verify_snapshot_payload(s, s["digest"], now=late,
                                    policy_version="live-probe/v1")
        assert "expired" in e.value.message


class TestStage1PolicyConstants:
    def test_live_probe_profile_registered_but_narrow(self):
        assert "live_probe" in PROFILE_TOTAL_STEPS
        assert ScanProfile is not None

    def test_stage1_policy_values(self):
        assert live.LIVE_PROBE_METHODS == ["GET"]
        assert live.LIVE_PROBE_PATHS == ["/"]
        assert live.LIVE_PROBE_FOLLOW_REDIRECTS is False
        assert live.LIVE_PROBE_DISCOVERY is False
