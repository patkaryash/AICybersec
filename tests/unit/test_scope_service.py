"""Unit tests: target scope validation and canonicalization."""
from __future__ import annotations

import pytest

from backend.core.errors import ApiError, ErrorCode
from backend.schemas.projects import ScopeEntry
from backend.services.scope_service import target_in_scope, validate_scope


def _entries(*triples: tuple[str, str]) -> list[ScopeEntry]:
    return [ScopeEntry(type=t, value=v) for t, v in triples]


class TestValidateScope:
    def test_hostname_valid_and_canonicalized(self):
        out = validate_scope(_entries(("host", "Juice-Shop.LOCAL")))
        assert out[0]["value"] == "juice-shop.local"
        assert out[0]["type"] == "host"

    def test_ipv4_valid(self):
        assert validate_scope(_entries(("host", "10.0.0.5")))[0]["value"] == "10.0.0.5"

    def test_ipv6_valid_and_canonicalized(self):
        out = validate_scope(_entries(("host", "2001:0DB8:0000::0001")))
        assert out[0]["value"] == "2001:db8::1"

    def test_cidr_canonicalized_host_bits_folded(self):
        assert validate_scope(_entries(("cidr", "10.0.0.5/24")))[0]["value"] == "10.0.0.0/24"

    def test_ipv6_cidr_valid(self):
        assert validate_scope(_entries(("cidr", "2001:db8::/32")))[0]["value"] == "2001:db8::/32"

    def test_url_valid_and_kept(self):
        out = validate_scope(_entries(("url", "http://Juice-Shop:3000/path")))
        assert out[0]["value"] == "http://Juice-Shop:3000/path"

    def test_note_preserved(self):
        out = validate_scope([ScopeEntry(type="host", value="a.local", note="lab")])
        assert out[0]["note"] == "lab"

    def test_malformed_hostname_rejected(self):
        for bad in ["not a host!", "-bad-", "bad-", "host..", "a" * 254]:
            with pytest.raises(ApiError) as exc:
                validate_scope(_entries(("host", bad)))
            assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_invalid_ip_rejected(self):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("host", "10.0.0.999")))
        assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_invalid_cidr_rejected(self):
        for bad in ["10.0.0.0/99", "notacidr", "10.0.0.0/-1"]:
            with pytest.raises(ApiError) as exc:
                validate_scope(_entries(("cidr", bad)))
            assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_unsupported_scheme_rejected(self):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("url", "ftp://host.local")))
        assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_embedded_credentials_rejected(self):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("url", "http://user:pass@host.local")))
        assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_invalid_port_rejected(self):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("url", "http://host.local:99999")))
        assert exc.value.code == ErrorCode.INVALID_TARGET

    def test_malformed_url_rejected(self):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("url", "http://")))
        assert exc.value.code == ErrorCode.INVALID_TARGET


class TestTargetInScope:
    SNAPSHOT = [
        {"type": "host", "value": "juice-shop.local"},
        {"type": "cidr", "value": "10.0.0.0/24"},
        {"type": "url", "value": "http://web.local:8080"},
    ]

    def test_host_entry_match(self):
        assert target_in_scope(self.SNAPSHOT, "juice-shop.local")

    def test_url_target_matches_host_entry(self):
        assert target_in_scope(self.SNAPSHOT, "http://juice-shop.local:3000/x")

    def test_cidr_member_match(self):
        assert target_in_scope(self.SNAPSHOT, "10.0.0.5")

    def test_url_target_with_ip_host_matches_cidr(self):
        assert target_in_scope(self.SNAPSHOT, "http://10.0.0.9:80")

    def test_out_of_scope_rejected(self):
        assert not target_in_scope(self.SNAPSHOT, "evil.example.com")
        assert not target_in_scope(self.SNAPSHOT, "10.1.0.5")

    def test_empty_snapshot_authorizes_nothing(self):
        assert not target_in_scope([], "anything.local")

    def test_none_like_target_rejected(self):
        assert not target_in_scope(self.SNAPSHOT, "")
