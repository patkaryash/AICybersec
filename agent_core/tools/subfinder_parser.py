"""Subfinder JSONL parser: parse ``subfinder -json`` stdout.

Accepted line shapes (all from pkg/runner/outputter.go):
- default: {"host": ..., "input": ..., "source": "..."}
- -cs variant: {"host": ..., "input": ..., "sources": [...]}
- -ip variant (never requested by our fixed argv, tolerated):
  {"host": ..., "ip": ..., "input": ..., "source": ...}

Normalized record: {"subdomain", "sources": [...], "discovered_ips": [...]}

This parser is SYNTACTIC only: it caps sizes, counts malformed lines,
and never fails the whole output on one bad line. Semantic filtering
(valid hostname? descendant of the requested domain?) happens in the
tool (needs the domain argument) and in persistence (promotion
policy) - never here.

Empty output is valid (0 subdomains, 0 skipped).
"""
from __future__ import annotations

import json
from typing import Any

# Upper bound on records per run (fail-closed, not lossy for labs).
MAX_SUBDOMAINS = 500
# Per-string cap inside normalized records.
MAX_STR = 500
# Upper bound on sources/IPs kept per record.
MAX_LIST_ITEMS = 10


def _clean_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:MAX_STR]


def _clean_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        cleaned = _clean_str(item)
        if cleaned is not None and cleaned not in out:
            out.append(cleaned)
        if len(out) >= MAX_LIST_ITEMS:
            break
    return out


def normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Normalize one decoded JSON line; None when unusable."""
    if not isinstance(entry, dict):
        return None
    host = _clean_str(entry.get("host"))
    if host is None:
        return None
    sources = _clean_str_list(entry.get("sources"))
    if not sources:
        primary = _clean_str(entry.get("source"))
        sources = [primary] if primary is not None else []
    return {
        "subdomain": host,
        "sources": sources,
        "discovered_ips": _clean_str_list(entry.get("ip")),
    }


def parse_subfinder_jsonl(text: str) -> dict[str, Any]:
    """Parse subfinder ``-json`` stdout.

    Returns ``{"subdomains": [...], "skipped": n}``. Malformed lines
    (bad JSON, non-object, missing host) increment ``skipped`` instead
    of failing. Records beyond MAX_SUBDOMAINS are dropped and counted
    in ``skipped`` as well.
    """
    subdomains: list[dict[str, Any]] = []
    skipped = 0
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):
            skipped += 1
            continue
        normalized = normalize_entry(entry)
        if normalized is None:
            skipped += 1
            continue
        if len(subdomains) >= MAX_SUBDOMAINS:
            skipped += 1
            continue
        subdomains.append(normalized)
    return {"subdomains": subdomains, "skipped": skipped}
