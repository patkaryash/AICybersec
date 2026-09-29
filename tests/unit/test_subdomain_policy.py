"""Unit tests: Phase 4B subdomain promotion policy (pure, no DB)."""
from __future__ import annotations

import pytest

from backend.services.subdomain_policy import (
    filter_descendants,
    is_within_domain,
    normalize_hostname,
    snapshot_parents,
)


class TestNormalizeHostname:
    def test_lowercase_and_trailing_dot(self):
        assert normalize_hostname("API.Example.COM.") == "api.example.com"
        assert normalize_hostname("  Example.COM  ") == "example.com"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "not a host",
            "http://example.com",
            "https://example.com/x",
            "user@example.com",
            "*.example.com",
            "*",
            "-bad.com",
            "10.0.0.5",
            "2001:db8::1",
            "a" * 254,
            None,
            123,
            ["example.com"],
            "example.com:8080",
            "exam ple.com",
        ],
    )
    def test_invalid_rejected(self, bad):
        assert normalize_hostname(bad) is None


class TestIsWithinDomain:
    def test_root_itself_recognized(self):
        assert is_within_domain("example.com", "example.com")

    def test_case_insensitive(self):
        assert is_within_domain("API.Example.COM", "example.COM")

    def test_proper_descendant(self):
        assert is_within_domain("api.example.com", "example.com")
        assert is_within_domain("deep.api.example.com", "example.com")
        assert is_within_domain("deep.api.example.com", "api.example.com")

    def test_similar_suffix_rejected(self):
        # The naive endswith("example.com") trap.
        assert not is_within_domain("evil-example.com", "example.com")
        assert not is_within_domain("notexample.com", "example.com")

    def test_parent_as_suffix_rejected(self):
        assert not is_within_domain("example.com.evil.com", "example.com")

    def test_sibling_and_parent_rejected(self):
        assert not is_within_domain("other.com", "example.com")
        assert not is_within_domain("com", "example.com")
        assert not is_within_domain("example.com", "api.example.com")

    def test_trailing_dot_normalizes(self):
        assert is_within_domain("api.example.com.", "example.com")

    def test_invalid_inputs_rejected(self):
        assert not is_within_domain("*.example.com", "example.com")
        assert not is_within_domain("http://api.example.com", "example.com")
        assert not is_within_domain("api.example.com", "not a domain")
        assert not is_within_domain(None, "example.com")
        assert not is_within_domain("api.example.com", None)


class TestFilterDescendants:
    def test_filters_and_dedupes(self):
        out = filter_descendants(
            [
                "api.example.com",
                "API.EXAMPLE.COM.",
                "example.com",  # root excluded
                "evil-example.com",
                "example.com.evil.com",
                "*.example.com",
                "  ",
                None,
                "dev.example.com",
            ],
            "example.com",
        )
        assert out == ["api.example.com", "dev.example.com"]

    def test_invalid_parent_yields_nothing(self):
        assert filter_descendants(["api.example.com"], "not a domain") == []
        assert filter_descendants(["api.example.com"], None) == []
        assert filter_descendants("not-a-list", "example.com") == []


class TestSnapshotParents:
    def test_domain_host_url_entries(self):
        snapshot = [
            {"type": "domain", "value": "Example.COM"},
            {"type": "host", "value": "api.example.com"},
            {"type": "url", "value": "https://web.example.com:8443/app"},
            {"type": "cidr", "value": "10.0.0.0/24"},
            {"type": "host", "value": "10.0.0.5"},
            {"type": "weird", "value": "example.com"},
            "not-a-dict",
            {"type": "domain", "value": "*.example.com"},
            {"type": "domain", "value": "example.com"},
        ]
        assert snapshot_parents(snapshot) == [
            "example.com",
            "api.example.com",
            "web.example.com",
        ]

    def test_non_list_snapshot(self):
        assert snapshot_parents(None) == []
        assert snapshot_parents("example.com") == []
