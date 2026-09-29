"""DNSX JSONL parser: parse ``dnsx -json`` stdout.

Accepted line shape (from internal/runner + libs/dnsx output structs;
every field is ``omitempty``, so missing records are ABSENT, never
null - absence means "no data for this type"):
    {"host": ..., "a": [...], "aaaa": [...], "cname": [...],
     "status_code_raw": ..., ...}

Only the enrichment-relevant subset is retained - the rest of the
dnsx record (resolver, ttl, asn, cdn, trace, raw, ...) is dropped so
model context stays bounded.

Normalized record: {"host", "a": [...], "aaaa": [...], "cname": [...],
"status_code_raw": int | None}

This parser is SYNTACTIC only: it caps sizes, sorts record lists for
deterministic output, counts malformed lines, and never fails the
whole output on one bad line. Semantic use (which hosts count as
verified, what gets persisted) happens in the tool and in
persistence - never here. DNS output is UNTRUSTED DATA: A/AAAA/CNAME
values are carried, never followed (CNAME targets especially so).

Empty output is valid (0 records, 0 skipped).
"""
from __future__ import annotations

import json
from typing import Any

# Upper bound on records per run (fail-closed; inputs are capped at 20
# targets so real runs stay far below this).
MAX_RECORDS = 100
# Per-string cap inside normalized records.
MAX_STR = 500
# Upper bound on values kept per record list.
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
    # Deterministic order: DNS answer order varies run to run, so sort
    # the deduplicated values instead of preserving arrival order.
    out.sort()
    return out[:MAX_LIST_ITEMS]


def _clean_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("+-").isdigit():
            try:
                return int(text)
            except ValueError:
                return None
    return None


def normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Normalize one decoded JSON line; None when unusable."""
    if not isinstance(entry, dict):
        return None
    host = _clean_str(entry.get("host"))
    if host is None:
        return None
    return {
        "host": host,
        "a": _clean_str_list(entry.get("a")),
        "aaaa": _clean_str_list(entry.get("aaaa")),
        "cname": _clean_str_list(entry.get("cname")),
        "status_code_raw": _clean_status(entry.get("status_code_raw")),
    }


def parse_dnsx_jsonl(text: str) -> dict[str, Any]:
    """Parse dnsx ``-json`` stdout.

    Returns ``{"records": [...], "skipped": n}``. Malformed lines
    (bad JSON, non-object, missing host) increment ``skipped`` instead
    of failing. Records beyond MAX_RECORDS are dropped and counted
    in ``skipped`` as well.
    """
    records: list[dict[str, Any]] = []
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
        if len(records) >= MAX_RECORDS:
            skipped += 1
            continue
        records.append(normalized)
    return {"records": records, "skipped": skipped}
