"""HTTPX JSONL parser: parse ``httpx -json`` output (one object per line).

Only the agent-relevant subset is retained - raw httpx JSON is never
passed through, so model context stays bounded.
"""
from __future__ import annotations

import json
from typing import Any

# Bound normalized output so a large httpx run cannot flood AgentState.
MAX_SERVICES = 100
MAX_TECH = 20
MAX_STR = 500


def _pick(obj: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return default


def _str(v: Any) -> Any:
    if v is None:
        return None
    s = str(v)
    return s[:MAX_STR] if len(s) > MAX_STR else s


def _normalize_tls(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    subject_cn = _pick(raw, "subject_cn", "subject-cn", "subjectCN", "subject")
    issuer = _pick(raw, "issuer", "issuer_cn", "issuer-cn", "issuerCN")
    dns_names = _pick(raw, "dns_names", "dns-names", "subject_an", "alternative_names", "sans", default=[])
    if isinstance(dns_names, str):
        dns_names = [dns_names]
    if not isinstance(dns_names, list):
        dns_names = []
    dns_names = [str(x)[:MAX_STR] for x in dns_names[:MAX_TECH]]
    if subject_cn is None and issuer is None and not dns_names:
        # Keep tls only when it carries something useful.
        return None
    if isinstance(subject_cn, dict):
        subject_cn = subject_cn.get("CN") or _str(subject_cn)
    if isinstance(issuer, dict):
        issuer = issuer.get("CN") or _str(issuer)
    return {
        "subject_cn": _str(subject_cn),
        "issuer": _str(issuer),
        "dns_names": dns_names,
    }


def normalize_entry(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalize one httpx JSON object to the agent schema."""
    tech_raw = _pick(obj, "tech", "technologies", default=[])
    if isinstance(tech_raw, str):
        tech_raw = [tech_raw]
    tech = [str(t)[:MAX_STR] for t in (tech_raw or [])[:MAX_TECH]]

    cname_raw = _pick(obj, "cname", "cnames", default=None)
    if isinstance(cname_raw, list):
        cname = _str(cname_raw[0]) if cname_raw else None
    else:
        cname = _str(cname_raw)

    return {
        "url": _str(_pick(obj, "url", "final-url", "final_url")),
        "input": _str(_pick(obj, "input")),
        "final_url": _str(_pick(obj, "final_url", "final-url")),
        "scheme": _str(_pick(obj, "scheme")),
        "port": _pick(obj, "port"),
        "status_code": _pick(obj, "status_code", "status-code", "status"),
        "title": _str(_pick(obj, "title")),
        "webserver": _str(_pick(obj, "webserver", "web-server", "server")),
        "content_type": _str(_pick(obj, "content_type", "content-type")),
        "content_length": _pick(obj, "content_length", "content-length", "length"),
        "tech": tech,
        "host_ip": _str(_pick(obj, "host_ip", "host-ip", "ip", "host")),
        "cname": cname,
        "cdn_name": _str(_pick(obj, "cdn_name", "cdn-name", "cdn")),
        "location": _str(_pick(obj, "location")),
        "tls": _normalize_tls(_pick(obj, "tls")),
        "time": _str(_pick(obj, "time", "response_time", "response-time", "duration")),
        "error": _str(_pick(obj, "error", "failed", "msg")),
    }


def parse_httpx_jsonl(text: str) -> dict[str, Any]:
    """Parse httpx ``-json`` stdout into ``{"services": [...], "skipped": n}``.

    Blank lines are ignored. Malformed lines are counted in ``skipped``
    (not fatal) as long as at least one valid object parses. Raises
    ValueError when output is non-empty but yields zero valid objects.
    """
    if not text or not text.strip():
        return {"services": [], "skipped": 0}
    services: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(obj, dict):
            skipped += 1
            continue
        services.append(normalize_entry(obj))
        if len(services) >= MAX_SERVICES:
            # Count the rest as skipped to keep state bounded.
            break
    if not services and skipped > 0:
        raise ValueError(f"no valid httpx JSON objects ({skipped} malformed line(s))")
    return {"services": services, "skipped": skipped}
