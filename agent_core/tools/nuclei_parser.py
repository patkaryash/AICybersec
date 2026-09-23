"""Nuclei JSONL parser: parse ``nuclei -jsonl`` output into Findings.

One JSON object per line; each object is a template match. Only the
agent-relevant subset is retained - raw nuclei JSON never reaches the
model context. No vulnerabilities are invented: lines without a template
identity are skipped, not fabricated.
"""
from __future__ import annotations

import json
from typing import Any

from agent_core.schemas.results import Finding

# Bound normalized output so a large nuclei run cannot flood AgentState.
MAX_FINDINGS = 100
MAX_STR = 500
MAX_LIST = 20

_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


def _pick(obj: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return default


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    return s[:MAX_STR] if len(s) > MAX_STR else s


def _slug(v: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in v.lower()).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:100] or "unknown"


def _normalize_severity(raw: Any) -> str:
    s = str(raw).strip().lower() if raw is not None else ""
    if s in _VALID_SEVERITIES:
        return s
    return "info"  # unknown/missing -> info, never dropped, never invented


def _confidence_for(severity: str) -> str:
    if severity in ("critical", "high"):
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _normalize_refs(raw: Any) -> list[str]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    out: list[str] = []
    for r in items:
        s = _str(r)
        if s and s not in out:
            out.append(s)
        if len(out) >= MAX_LIST:
            break
    return out


def normalize_entry(obj: dict[str, Any]) -> Finding | None:
    """Normalize one nuclei JSON object to a Finding.

    Returns None when the object carries no template identity
    (no ``template-id``/``template`` and no ``info.name``) - the caller
    counts it as skipped instead of fabricating a finding.
    """
    if not isinstance(obj, dict):
        return None
    info = obj.get("info")
    if not isinstance(info, dict):
        info = {}

    template_id = _str(_pick(obj, "template-id", "templateID", "template_id")) or _str(
        _pick(obj, "template")
    )
    name = _str(_pick(info, "name")) or template_id
    if name is None:
        return None  # no identity -> skip, do not invent

    severity = _normalize_severity(_pick(info, "severity", default=_pick(obj, "severity")))
    target = _str(_pick(obj, "matched-at", "matched_at", "host")) or _str(_pick(obj, "ip"))
    asset = _str(_pick(obj, "matched-at", "matched_at", "host", "url"))
    description = _str(_pick(info, "description"))

    extracted = _pick(obj, "extracted-results", "extracted_results", "extracted", default=[])
    if isinstance(extracted, str):
        extracted = [extracted]
    if not isinstance(extracted, list):
        extracted = []
    extracted = [_str(e) for e in extracted[:MAX_LIST] if _str(e)]

    tid_slug = _slug(template_id or name)
    tgt_slug = _slug(target or "unknown")
    finding_id = f"nuclei:{tid_slug}:{tgt_slug}"

    evidence: dict[str, Any] = {}
    for key, val in (
        ("template", _str(_pick(obj, "template"))),
        ("template_id", template_id),
        ("matched_at", _str(_pick(obj, "matched-at", "matched_at"))),
        ("host", _str(_pick(obj, "host"))),
        ("ip", _str(_pick(obj, "ip"))),
        ("type", _str(_pick(obj, "type"))),
        ("matcher_name", _str(_pick(obj, "matcher-name", "matcher_name"))),
        ("curl_command", _str(_pick(obj, "curl-command", "curl_command"))),
    ):
        if val is not None:
            evidence[key] = val
    if extracted:
        evidence["extracted_results"] = extracted

    return Finding(
        id=finding_id,
        title=name,
        severity=severity,  # type: ignore[arg-type]
        target=target,
        asset=asset,
        description=description,
        evidence=evidence,
        tool="nuclei",
        confidence=_confidence_for(severity),  # type: ignore[arg-type]
        status="open",
        references=_normalize_refs(_pick(info, "reference", "references")),
    )


def parse_nuclei_jsonl(text: str) -> dict[str, Any]:
    """Parse nuclei ``-jsonl`` stdout into ``{"findings": [...], "skipped": n}``.

    Blank lines are ignored. Malformed lines and identity-less objects are
    counted in ``skipped``. Empty input is valid (clean target, no
    findings). Raises ValueError when output is non-empty but yields zero
    valid findings.
    """
    if not text or not text.strip():
        return {"findings": [], "skipped": 0}
    findings: list[Finding] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        entry = normalize_entry(obj)
        if entry is None:
            skipped += 1
            continue
        findings.append(entry)
        if len(findings) >= MAX_FINDINGS:
            break
    if not findings and skipped > 0:
        raise ValueError(f"no valid nuclei findings ({skipped} malformed line(s))")
    return {"findings": findings, "skipped": skipped}
