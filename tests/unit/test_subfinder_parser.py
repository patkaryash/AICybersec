"""Unit tests: subfinder JSONL parser (pure, no binary/network)."""
from __future__ import annotations

import json

from agent_core.tools.subfinder_parser import (
    MAX_STR,
    MAX_SUBDOMAINS,
    normalize_entry,
    parse_subfinder_jsonl,
)


def _line(obj: dict) -> str:
    return json.dumps(obj)


class TestValidJsonl:
    def test_default_shape(self):
        text = "\n".join(
            [
                _line({"host": "api.example.com", "input": "example.com", "source": "crtsh"}),
                _line({"host": "dev.example.com", "input": "example.com", "source": "github"}),
            ]
        )
        out = parse_subfinder_jsonl(text)
        assert out["skipped"] == 0
        assert [s["subdomain"] for s in out["subdomains"]] == [
            "api.example.com",
            "dev.example.com",
        ]
        assert out["subdomains"][0]["sources"] == ["crtsh"]
        assert out["subdomains"][0]["discovered_ips"] == []

    def test_collect_sources_shape(self):
        out = parse_subfinder_jsonl(
            _line({"host": "a.example.com", "input": "example.com", "sources": ["crtsh", "github"]})
        )
        assert out["subdomains"][0]["sources"] == ["crtsh", "github"]

    def test_ip_shape_carried_as_untrusted_data(self):
        out = parse_subfinder_jsonl(
            _line({
                "host": "a.example.com",
                "ip": "93.184.216.34",
                "input": "example.com",
                "source": "crtsh",
            })
        )
        assert out["subdomains"][0]["discovered_ips"] == ["93.184.216.34"]

    def test_wildcard_certificate_field_tolerated(self):
        out = parse_subfinder_jsonl(
            _line({
                "host": "a.example.com",
                "input": "example.com",
                "source": "crtsh",
                "wildcard_certificate": True,
            })
        )
        assert out["subdomains"][0]["subdomain"] == "a.example.com"


class TestMalformedJsonl:
    def test_empty_output_valid(self):
        assert parse_subfinder_jsonl("") == {"subdomains": [], "skipped": 0}
        assert parse_subfinder_jsonl("   \n\n  ") == {"subdomains": [], "skipped": 0}

    def test_bad_lines_skipped_not_fatal(self):
        text = "\n".join(
            [
                "not json at all",
                '{"host": "ok.example.com", "input": "example.com", "source": "crtsh"}',
                "[1, 2, 3]",
                '{"input": "example.com"}',
                '{"host": "   "}',
                '{"host": 123}',
                "",
            ]
        )
        out = parse_subfinder_jsonl(text)
        assert [s["subdomain"] for s in out["subdomains"]] == ["ok.example.com"]
        assert out["skipped"] == 5

    def test_deeply_nested_garbage_safe(self):
        assert parse_subfinder_jsonl('{"host": {"a": [1]}}')["skipped"] == 1


class TestCaps:
    def test_record_cap(self):
        lines = [
            _line({"host": f"h{i}.example.com", "input": "example.com", "source": "s"})
            for i in range(MAX_SUBDOMAINS + 25)
        ]
        out = parse_subfinder_jsonl("\n".join(lines))
        assert len(out["subdomains"]) == MAX_SUBDOMAINS
        assert out["skipped"] == 25

    def test_string_cap(self):
        long_host = "a" * (MAX_STR + 100) + ".example.com"
        out = parse_subfinder_jsonl(
            _line({"host": long_host, "input": "example.com", "source": "s"})
        )
        assert len(out["subdomains"][0]["subdomain"]) == MAX_STR

    def test_list_caps(self):
        out = parse_subfinder_jsonl(
            _line({
                "host": "a.example.com",
                "input": "example.com",
                "sources": [f"s{i}" for i in range(30)],
                "ip": [f"10.0.0.{i}" for i in range(30)],
            })
        )
        assert len(out["subdomains"][0]["sources"]) == 10
        assert len(out["subdomains"][0]["discovered_ips"]) == 10

    def test_normalize_entry_rejects_non_dict(self):
        assert normalize_entry(None) is None
        assert normalize_entry("x") is None
        assert normalize_entry([]) is None
