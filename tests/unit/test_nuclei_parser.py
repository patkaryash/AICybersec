"""Unit tests: nuclei JSONL parser (static fixtures, no binary/network)."""
from __future__ import annotations

import json

import pytest

from agent_core.tools.nuclei_parser import normalize_entry, parse_nuclei_jsonl

ONE = {
    "template": "http/cves/2021/CVE-2021-44228.yaml",
    "template-id": "CVE-2021-44228",
    "template-url": "https://example.com/t",
    "info": {
        "name": "Apache Log4j RCE",
        "author": "pdteam",
        "tags": ["cve"],
        "description": "Log4Shell RCE in Log4j.",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "severity": "critical",
    },
    "type": "http",
    "host": "https://demo.local",
    "matched-at": "https://demo.local/login",
    "ip": "10.0.0.5",
    "matcher-name": "status",
    "extracted-results": ["vulnerable"],
    "curl-command": "curl -X GET https://demo.local/login",
}


def test_one_valid_finding():
    data = parse_nuclei_jsonl(json.dumps(ONE))
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f.tool == "nuclei" and f.status == "open"
    assert f.title == "Apache Log4j RCE" and f.severity == "critical"
    assert f.confidence == "high"
    assert f.target == "https://demo.local/login"
    assert f.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    assert f.evidence["template_id"] == "CVE-2021-44228"
    assert f.evidence["matcher_name"] == "status"
    assert f.evidence["extracted_results"] == ["vulnerable"]
    assert f.id.startswith("nuclei:")


def test_multiple_findings_severity_normalization():
    med = dict(ONE)
    med["template-id"] = "misconfig-x"
    med["info"] = dict(ONE["info"], name="Exposed Panel", severity="MEDIUM", reference="https://example.com")
    unk = dict(ONE)
    unk["template-id"] = "weird"
    unk["info"] = {"name": "Weird", "severity": "unknown"}
    data = parse_nuclei_jsonl("\n".join([json.dumps(ONE), json.dumps(med), json.dumps(unk)]))
    assert [f.severity for f in data["findings"]] == ["critical", "medium", "info"]
    assert data["findings"][1].references == ["https://example.com"]
    assert data["findings"][1].confidence == "medium"
    assert data["findings"][2].confidence == "low"


def test_missing_optional_fields_no_fabrication():
    minimal = {"template-id": "t-min", "matched-at": "https://demo.local/"}
    f = normalize_entry(minimal)
    assert f is not None
    assert f.title == "t-min" and f.severity == "info"
    assert f.references == [] and f.description is None
    # no identity at all -> skipped, not invented
    assert normalize_entry({"host": "https://demo.local"}) is None
    assert normalize_entry("not-a-dict") is None  # type: ignore[arg-type]


def test_malformed_empty_and_bounds():
    assert parse_nuclei_jsonl("") == {"findings": [], "skipped": 0}
    assert parse_nuclei_jsonl("  \n ") == {"findings": [], "skipped": 0}
    data = parse_nuclei_jsonl(json.dumps(ONE) + "\nNOT JSON\n")
    assert len(data["findings"]) == 1 and data["skipped"] == 1
    with pytest.raises(ValueError):
        parse_nuclei_jsonl("GARBAGE\nMORE GARBAGE")
    big = "\n".join(json.dumps({"template-id": f"t-{i}", "matched-at": "https://demo.local/"}) for i in range(150))
    bounded = parse_nuclei_jsonl(big)
    assert len(bounded["findings"]) == 100
