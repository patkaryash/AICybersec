"""Unit tests: dnsx JSONL parser (pure, no binary/network)."""
from __future__ import annotations

import json

from agent_core.tools.dnsx_parser import (
    MAX_LIST_ITEMS,
    MAX_RECORDS,
    MAX_STR,
    normalize_entry,
    parse_dnsx_jsonl,
)


def _line(obj: dict) -> str:
    return json.dumps(obj)


class TestValidRecords:
    def test_a_record(self):
        out = parse_dnsx_jsonl(
            _line({"host": "api.example.com", "a": ["93.184.216.34"]})
        )
        assert out["skipped"] == 0
        assert out["records"] == [
            {
                "host": "api.example.com",
                "a": ["93.184.216.34"],
                "aaaa": [],
                "cname": [],
                "status_code_raw": None,
            }
        ]

    def test_aaaa_record(self):
        out = parse_dnsx_jsonl(
            _line({"host": "api.example.com", "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"]})
        )
        assert out["records"][0]["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]
        assert out["records"][0]["a"] == []

    def test_cname_record(self):
        out = parse_dnsx_jsonl(
            _line({"host": "cdn.example.com", "cname": ["cdn.provider.net"]})
        )
        assert out["records"][0]["cname"] == ["cdn.provider.net"]

    def test_multiple_records(self):
        text = "\n".join(
            [
                _line({"host": "a.example.com", "a": ["1.1.1.1"]}),
                _line({"host": "b.example.com", "aaaa": ["::1"], "status_code_raw": 0}),
                _line({"host": "c.example.com", "cname": ["x.net"]}),
            ]
        )
        out = parse_dnsx_jsonl(text)
        assert [r["host"] for r in out["records"]] == [
            "a.example.com",
            "b.example.com",
            "c.example.com",
        ]
        assert out["records"][1]["status_code_raw"] == 0
        assert out["skipped"] == 0

    def test_extra_fields_ignored(self):
        out = parse_dnsx_jsonl(
            _line({
                "host": "a.example.com",
                "a": ["1.1.1.1"],
                "ttl": 300,
                "resolver": ["8.8.8.8:53"],
                "asn": {"as-number": "15169"},
                "cdn": True,
                "raw": "bulk",
                "trace": {"chain": []},
            })
        )
        assert set(out["records"][0]) == {"host", "a", "aaaa", "cname", "status_code_raw"}

    def test_string_record_wrapped_as_list(self):
        out = parse_dnsx_jsonl(_line({"host": "a.example.com", "a": "1.1.1.1"}))
        assert out["records"][0]["a"] == ["1.1.1.1"]

    def test_status_code_string_coerced(self):
        out = parse_dnsx_jsonl(_line({"host": "a.example.com", "status_code_raw": "0"}))
        assert out["records"][0]["status_code_raw"] == 0

    def test_status_code_garbage_is_none(self):
        out = parse_dnsx_jsonl(_line({"host": "a.example.com", "status_code_raw": "noerror?"}))
        assert out["records"][0]["status_code_raw"] is None
        out = parse_dnsx_jsonl(_line({"host": "a.example.com", "status_code_raw": True}))
        assert out["records"][0]["status_code_raw"] is None


class TestMalformedInput:
    def test_empty_output_valid(self):
        assert parse_dnsx_jsonl("") == {"records": [], "skipped": 0}
        assert parse_dnsx_jsonl("  \n\n ") == {"records": [], "skipped": 0}

    def test_malformed_line_skipped(self):
        text = "\n".join(
            [
                "not json",
                _line({"host": "ok.example.com", "a": ["1.1.1.1"]}),
                '{"host": "cut off...',
            ]
        )
        out = parse_dnsx_jsonl(text)
        assert [r["host"] for r in out["records"]] == ["ok.example.com"]
        assert out["skipped"] == 2

    def test_non_object_json_skipped(self):
        text = "\n".join(['[1, 2]', '"str"', "42", "null", _line({"host": "ok.example.com"})])
        out = parse_dnsx_jsonl(text)
        assert len(out["records"]) == 1
        assert out["skipped"] == 4

    def test_missing_or_empty_host_skipped(self):
        text = "\n".join(
            [
                _line({"a": ["1.1.1.1"]}),
                _line({"host": "   "}),
                _line({"host": 123}),
            ]
        )
        out = parse_dnsx_jsonl(text)
        assert out == {"records": [], "skipped": 3}


class TestCaps:
    def test_record_cap(self):
        lines = [
            _line({"host": f"h{i}.example.com", "a": ["1.1.1.1"]})
            for i in range(MAX_RECORDS + 15)
        ]
        out = parse_dnsx_jsonl("\n".join(lines))
        assert len(out["records"]) == MAX_RECORDS
        assert out["skipped"] == 15

    def test_string_cap(self):
        out = parse_dnsx_jsonl(_line({"host": "a" * (MAX_STR + 50)}))
        assert len(out["records"][0]["host"]) == MAX_STR

    def test_list_caps_and_dedup_sorted(self):
        out = parse_dnsx_jsonl(
            _line({
                "host": "a.example.com",
                "a": ["9.9.9.9", "1.1.1.1", "9.9.9.9"] + [f"10.0.0.{i}" for i in range(30)],
            })
        )
        kept = out["records"][0]["a"]
        assert len(kept) == MAX_LIST_ITEMS
        assert kept == sorted(kept)
        assert len(set(kept)) == len(kept)

    def test_normalize_entry_rejects_non_dict(self):
        assert normalize_entry(None) is None
        assert normalize_entry("x") is None
        assert normalize_entry([]) is None
