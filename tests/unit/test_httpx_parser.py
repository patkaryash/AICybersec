"""Unit tests: httpx JSONL parser (static fixtures, no network/binary)."""
from __future__ import annotations

import json

import pytest

from agent_core.tools.httpx_parser import normalize_entry, parse_httpx_jsonl

ONE = {
    "url": "https://demo.local:443/login",
    "input": "https://demo.local",
    "final_url": "https://demo.local/login",
    "scheme": "https",
    "port": 443,
    "status_code": 200,
    "title": "Login",
    "webserver": "nginx",
    "content_type": "text/html",
    "content_length": 1234,
    "tech": ["nginx", "React"],
    "host_ip": "10.0.0.5",
    "cname": "demo.local",
    "cdn_name": "cloudflare",
    "location": "",
    "tls": {"subject_cn": "demo.local", "issuer": "LetsEncrypt", "dns_names": ["demo.local"]},
    "time": "120ms",
}


def test_one_result():
    data = parse_httpx_jsonl(json.dumps(ONE))
    assert len(data["services"]) == 1
    s = data["services"][0]
    assert s["url"] == "https://demo.local:443/login"
    assert s["status_code"] == 200
    assert s["title"] == "Login"
    assert s["tech"] == ["nginx", "React"]
    assert s["tls"] == {"subject_cn": "demo.local", "issuer": "LetsEncrypt", "dns_names": ["demo.local"]}


def test_multiple_results_redirect_and_minimal():
    lines = [
        json.dumps(ONE),
        json.dumps({"url": "http://demo.local", "input": "http://demo.local", "status_code": 301, "location": "https://demo.local/"}),
        json.dumps({"input": "https://demo.local:8443", "error": "timeout"}),
    ]
    data = parse_httpx_jsonl("\n".join(lines))
    assert len(data["services"]) == 3
    assert data["services"][1]["location"] == "https://demo.local/"
    assert data["services"][1]["tls"] is None
    assert data["services"][2]["error"] == "timeout"


def test_missing_optional_fields_and_kebab_case():
    obj = {"url": "https://demo.local", "status-code": 200, "web-server": "nginx", "content-type": "text/html"}
    s = normalize_entry(obj)
    assert s["status_code"] == 200 and s["webserver"] == "nginx"
    assert s["tech"] == [] and s["tls"] is None and s["cname"] is None


def test_malformed_and_empty():
    assert parse_httpx_jsonl("") == {"services": [], "skipped": 0}
    assert parse_httpx_jsonl("  \n  ") == {"services": [], "skipped": 0}
    data = parse_httpx_jsonl(json.dumps(ONE) + "\nNOT JSON\n")
    assert len(data["services"]) == 1 and data["skipped"] == 1
    with pytest.raises(ValueError):
        parse_httpx_jsonl("NOT JSON\nALSO NOT JSON")
