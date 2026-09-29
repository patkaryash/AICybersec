"""Unit tests: Phase 4A domain scope type (foundation only).

Covers: domain validation/canonicalization, invalid-domain rejection,
host/cidr/url compatibility, exact-match authorization (subdomains are
NOT implicitly in scope), and scope-resolution behavior for domains.
No tool integration, no promotion mechanism - that is a future phase.
"""
from __future__ import annotations

import pytest

from backend.core.errors import ApiError, ErrorCode
from backend.schemas.projects import ScopeEntry
from backend.services.scope_resolution import resolve_scope
from backend.services.scope_service import target_in_scope, validate_scope


def _entries(*triples: tuple[str, str]) -> list[ScopeEntry]:
    return [ScopeEntry(type=t, value=v) for t, v in triples]


def _resolver_of(*ips: str):
    def resolve(hostname: str) -> list[str]:
        return list(ips)

    return resolve


class TestValidateDomain:
    def test_domain_valid_and_canonicalized(self):
        out = validate_scope(_entries(("domain", "Example.COM")))
        assert out[0] == {"type": "domain", "value": "example.com", "note": None}

    def test_domain_trailing_dot_stripped(self):
        out = validate_scope(_entries(("domain", "example.com.")))
        assert out[0]["value"] == "example.com"

    def test_domain_single_label_allowed(self):
        out = validate_scope(_entries(("domain", "localhost")))
        assert out[0]["value"] == "localhost"

    def test_domain_note_preserved(self):
        out = validate_scope(
            [ScopeEntry(type="domain", value="example.com", note="client")]
        )
        assert out[0]["note"] == "client"

    def test_domain_with_subdomain_value_is_just_a_name(self):
        # A domain entry for a subdomain name is allowed (it authorizes
        # exactly that name); it still does not cover anything beneath it.
        out = validate_scope(_entries(("domain", "api.example.com")))
        assert out[0]["value"] == "api.example.com"

    @pytest.mark.parametrize(
        "bad",
        [
            "http://example.com",
            "https://example.com/path",
            "user@example.com",
            "user:pass@example.com",
            "*.example.com",
            "*",
            "-bad.com",
            "10.0.0.5",
            "2001:db8::1",
            "not a domain!",
            "bad..dots",
            # NOTE: "" is rejected one layer earlier (ScopeEntry
            # min_length=1 -> pydantic ValidationError), still rejected.
            "   ",
            "a" * 254,
            "host_name.com",
        ],
    )
    def test_invalid_domains_rejected(self, bad: str):
        with pytest.raises(ApiError) as exc:
            validate_scope(_entries(("domain", bad)))
        assert exc.value.code == ErrorCode.INVALID_TARGET


class TestExistingScopeCompatibility:
    def test_host_still_works(self):
        assert validate_scope(_entries(("host", "Juice-Shop.LOCAL")))[0][
            "value"
        ] == "juice-shop.local"

    def test_cidr_still_works(self):
        assert validate_scope(_entries(("cidr", "10.0.0.5/24")))[0][
            "value"
        ] == "10.0.0.0/24"

    def test_url_still_works(self):
        out = validate_scope(_entries(("url", "https://web.local:8443/app")))
        assert out[0]["value"] == "https://web.local:8443/app"

    def test_mixed_scope_all_types(self):
        out = validate_scope(
            _entries(
                ("host", "a.local"),
                ("cidr", "10.0.0.0/24"),
                ("url", "http://b.local/"),
                ("domain", "Example.COM"),
            )
        )
        assert [e["type"] for e in out] == ["host", "cidr", "url", "domain"]
        assert out[3]["value"] == "example.com"


class TestDomainAuthorizationIsExact:
    SNAPSHOT = [{"type": "domain", "value": "example.com", "note": None}]

    def test_exact_domain_matches(self):
        assert target_in_scope(self.SNAPSHOT, "example.com")

    def test_case_insensitive_match(self):
        assert target_in_scope(self.SNAPSHOT, "EXAMPLE.COM")

    def test_url_form_of_domain_matches(self):
        assert target_in_scope(self.SNAPSHOT, "https://example.com:443/app")

    def test_subdomain_does_not_match(self):
        assert not target_in_scope(self.SNAPSHOT, "sub.example.com")
        assert not target_in_scope(self.SNAPSHOT, "deep.sub.example.com")
        assert not target_in_scope(self.SNAPSHOT, "http://api.example.com/x")

    def test_parent_and_sibling_do_not_match(self):
        assert not target_in_scope(self.SNAPSHOT, "com")
        assert not target_in_scope(self.SNAPSHOT, "other.com")
        assert not target_in_scope(self.SNAPSHOT, "example.com.evil.com")

    def test_mixed_snapshot_each_type_intact(self):
        snapshot = [
            {"type": "host", "value": "juice-shop.local"},
            {"type": "cidr", "value": "10.0.0.0/24"},
            {"type": "url", "value": "http://web.local:8080"},
            {"type": "domain", "value": "example.com"},
        ]
        assert target_in_scope(snapshot, "juice-shop.local")
        assert target_in_scope(snapshot, "10.0.0.9")
        assert target_in_scope(snapshot, "http://web.local:8080/x")
        assert target_in_scope(snapshot, "example.com")
        assert not target_in_scope(snapshot, "sub.example.com")
        assert not target_in_scope(snapshot, "evil.example.com")
        assert not target_in_scope(snapshot, "10.1.0.5")

    def test_empty_snapshot_authorizes_nothing(self):
        assert not target_in_scope([], "example.com")


class TestDomainScopeResolution:
    def test_domain_contributes_host_and_dns_ips(self):
        snapshot = [{"type": "domain", "value": "example.com", "note": None}]
        allowed = resolve_scope(snapshot, resolver=_resolver_of("93.184.216.34"))
        assert "example.com" in allowed
        assert "93.184.216.34" in allowed

    def test_domain_does_not_expand_to_subdomains(self):
        snapshot = [{"type": "domain", "value": "example.com", "note": None}]
        allowed = resolve_scope(
            snapshot, resolver=_resolver_of("93.184.216.34", "93.184.216.35")
        )
        assert "sub.example.com" not in allowed
        assert "api.example.com" not in allowed

    def test_domain_case_normalized(self):
        snapshot = [{"type": "domain", "value": "Example.COM", "note": None}]
        allowed = resolve_scope(snapshot, resolver=_resolver_of())
        assert "example.com" in allowed

    def test_cidr_still_skipped_with_domain_present(self):
        snapshot = [
            {"type": "cidr", "value": "10.0.0.0/24"},
            {"type": "domain", "value": "example.com"},
        ]
        # The resolver maps example.com -> nothing here, so any 10.0.0.x
        # address in the output could only come from the CIDR entry.
        allowed = resolve_scope(snapshot, resolver=_resolver_of())
        assert "10.0.0.5" not in allowed
        assert "10.0.0.0/24" not in allowed
        assert "example.com" in allowed
