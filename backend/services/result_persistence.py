"""Scan-result persistence helpers (Phase 3).

Pure mapping + bounded writes used by the DatabaseEventSink (live) and
the ScanManager (post-run assets). Scanner evidence and AI analysis stay
separated per the findings-table contract: parser output writes
scanner_* only; every ai_* column remains NULL until Phase 8.

All payloads are capped before persistence: event/finding evidence must
never carry unbounded scanner dumps or hidden model reasoning into the
database.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding

# Per-string cap inside persisted payloads (evidence, summaries, params).
MAX_STRING_CHARS = 8192
# Whole-dict cap for agent-event data payloads.
MAX_EVENT_DATA_CHARS = 32768
# Upper bound on assets derived from a single run (fail-closed, not lossy
# for labs: real runs stay far below this).
MAX_ASSETS_PER_RUN = 500

_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
_VALID_FINDING_STATUSES = ("open", "accepted_risk", "resolved", "false_positive")


def _cap_strings(value: Any, limit: int = MAX_STRING_CHARS, _seen: frozenset[int] | None = None) -> Any:
    """Recursively truncate long strings (dicts/lists rebuilt, scalars kept).

    Circular references collapse to a marker instead of recursing forever -
    event payloads originate outside our control.
    """
    seen = _seen or frozenset()
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "...[truncated]"
    if isinstance(value, dict):
        if id(value) in seen:
            return "...[circular]"
        seen = seen | {id(value)}
        return {k: _cap_strings(v, limit, seen) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if id(value) in seen:
            return ["...[circular]"]
        seen = seen | {id(value)}
        return [_cap_strings(v, limit, seen) for v in value]
    return value


def sanitize_event_data(data: dict[str, Any]) -> dict[str, Any]:
    """Bounded, secret-safe copy of an agent-event data payload.

    - Drops ``reasoning`` anywhere inside a ``decision`` mapping (debug
      trajectory content, never a DB/API payload).
    - Truncates long strings and caps the serialized whole.
    """
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if key == "decision" and isinstance(value, dict):
            value = {k: v for k, v in value.items() if k != "reasoning"}
        cleaned[key] = _cap_strings(value)
    try:
        serialized = json.dumps(cleaned, default=str)
    except (TypeError, ValueError):
        return {"_unserializable": True}
    if len(serialized) > MAX_EVENT_DATA_CHARS:
        return {
            "_truncated": True,
            "preview": serialized[:MAX_EVENT_DATA_CHARS],
        }
    return cleaned


def finding_fingerprint(
    source_tool: str | None, target: str | None, title: str | None, extra: str | None
) -> str:
    """Deterministic dedup key: SHA-256 over tool/target/title/extra.

    ``extra`` is the template id, port, or URL - whichever identifies the
    check. Matches the findings-table contract comment.
    """
    parts = [str(p or "") for p in (source_tool, target, title, extra)]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _finding_extra(evidence: dict[str, Any]) -> str:
    for key in ("template_id", "template", "curl_command"):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            return value[:200]
    port = evidence.get("port")
    if port is not None:
        return str(port)
    for key in ("matched_at", "url", "host"):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            return value[:200]
    return ""


def persist_finding(
    session: Session,
    *,
    scan_id,
    project_id,
    finding: dict[str, Any],
) -> Finding | None:
    """Persist one normalized finding dict; None when already recorded.

    Severity/status values outside the CHECK vocabularies fall back to
    safe defaults instead of failing the run. Duplicate fingerprints
    (unique index) roll back to the savepoint and return None.
    """
    evidence = finding.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {"evidence": str(evidence)[:MAX_STRING_CHARS]}
    severity = finding.get("severity")
    if severity not in _VALID_SEVERITIES:
        severity = "info"
    status = finding.get("status")
    if status not in _VALID_FINDING_STATUSES:
        status = "open"
    references = finding.get("references") or []
    if not isinstance(references, list):
        references = []
    row = Finding(
        scan_id=scan_id,
        project_id=project_id,
        asset_id=None,
        fingerprint=finding_fingerprint(
            finding.get("tool"),
            finding.get("target") or finding.get("asset"),
            finding.get("title"),
            _finding_extra(evidence),
        ),
        title=str(finding.get("title") or "Untitled finding")[:300],
        description=(str(finding.get("description"))[:10000] if finding.get("description") is not None else None),
        source_tool=str(finding.get("tool") or "unknown")[:50],
        scanner_severity=severity,
        scanner_evidence=_cap_strings(evidence),
        scanner_references=[str(r)[:500] for r in references[:20]],
        status=status,
    )
    # The tool's own confidence is scanner evidence, NOT AI analysis:
    # every ai_* column stays NULL until Phase 8.
    confidence = finding.get("confidence")
    if confidence in ("low", "medium", "high"):
        row.scanner_evidence = {**row.scanner_evidence, "tool_confidence": confidence}
    session.add(row)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        return None
    return row


def _service_assets(host_ip: str | None, ports: Any, tool: str) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    if host_ip:
        assets.append(
            {"asset_type": "host", "value": host_ip, "host": host_ip,
             "port": None, "scheme": None, "attributes": {}, "source_tool": tool}
        )
    if not isinstance(ports, list):
        return assets
    for port in ports:
        if not isinstance(port, dict) or port.get("state") != "open":
            continue
        try:
            port_no = int(port.get("port"))
        except (TypeError, ValueError):
            continue
        service = port.get("service") or {}
        assets.append(
            {
                "asset_type": "service",
                "value": f"{host_ip or 'unknown'}:{port_no}",
                "host": host_ip,
                "port": port_no,
                "scheme": None,
                "attributes": {
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if isinstance(service, dict) else None,
                },
                "source_tool": tool,
            }
        )
    return assets


def _url_assets(services: Any, tool: str) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    if not isinstance(services, list):
        return assets
    for svc in services:
        if not isinstance(svc, dict):
            continue
        url = svc.get("final_url") or svc.get("url")
        if not isinstance(url, str) or not url:
            continue
        try:
            parsed = urlparse(url)
            port = parsed.port
        except ValueError:
            port = None
        assets.append(
            {
                "asset_type": "url",
                "value": url,
                "host": parsed.hostname,
                "port": port,
                "scheme": parsed.scheme or None,
                "attributes": {
                    "status_code": svc.get("status_code"),
                    "title": svc.get("title"),
                    "tech": svc.get("tech") if isinstance(svc.get("tech"), list) else None,
                },
                "source_tool": tool,
            }
        )
    return assets


def assets_from_observation(observation: Any) -> list[dict[str, Any]]:
    """Derive asset dicts from one agent Observation (or equivalent mapping).

    Nmap hosts/ports become host/service assets; httpx services become
    URL assets. Only successful tool observations yield assets; anything
    malformed yields nothing rather than failing the run.
    """
    if isinstance(observation, dict):
        source, tool, data = (
            observation.get("source"),
            observation.get("tool"),
            observation.get("data") or {},
        )
    else:
        source, tool, data = (
            getattr(observation, "source", None),
            getattr(observation, "tool", None),
            getattr(observation, "data", None) or {},
        )
    if source != "tool" or not isinstance(data, dict):
        return []
    if tool == "nmap":
        assets: list[dict[str, Any]] = []
        hosts = data.get("hosts")
        if isinstance(hosts, list):
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                ip = host.get("ip") if isinstance(host.get("ip"), str) else None
                assets.extend(_service_assets(ip, host.get("ports"), str(tool or "nmap")))
        return assets
    if tool == "httpx":
        return _url_assets(data.get("services"), str(tool or "httpx"))
    return []


def persist_assets_from_observations(
    session: Session, *, scan, observations: list[Any]
) -> int:
    """Persist derived assets for a finished run; returns rows inserted.

    Existing (scan_id, asset_type, value) rows are skipped via a single
    pre-query, so reruns and retries never duplicate. Bounded at
    MAX_ASSETS_PER_RUN.
    """
    derived: list[dict[str, Any]] = []
    for obs in observations or []:
        derived.extend(assets_from_observation(obs))
        if len(derived) >= MAX_ASSETS_PER_RUN:
            break
    derived = derived[:MAX_ASSETS_PER_RUN]
    if not derived:
        return 0
    existing = {
        (row.asset_type, row.value)
        for row in session.query(Asset.asset_type, Asset.value).filter(
            Asset.scan_id == scan.id
        )
    }
    inserted = 0
    for asset in derived:
        value = str(asset["value"])[:500]
        if (asset["asset_type"], value) in existing:
            continue
        session.add(
            Asset(
                scan_id=scan.id,
                project_id=scan.project_id,
                asset_type=asset["asset_type"],
                value=value,
                host=(str(asset["host"])[:255] if asset["host"] else None),
                port=asset["port"],
                scheme=(str(asset["scheme"])[:10] if asset["scheme"] else None),
                attributes=_cap_strings(asset.get("attributes") or {}),
                source_tool=str(asset["source_tool"])[:50],
            )
        )
        existing.add((asset["asset_type"], value))
        inserted += 1
    session.flush()
    return inserted
