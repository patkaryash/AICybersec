"""Scan-result persistence helpers (Phase 3 + Phase 4A foundation).

Pure mapping + bounded writes used by the DatabaseEventSink (live) and
the ScanManager (post-run assets). Scanner evidence and AI analysis stay
separated per the findings-table contract: parser output writes
scanner_* only; every ai_* column remains NULL until Phase 8.

All payloads are capped before persistence: event/finding evidence must
never carry unbounded scanner dumps or hidden model reasoning into the
database.

Phase 4A additions (foundation only, no new tools):
- subdomain/endpoint/domain asset builders + parent-link resolution, so
  future discovery stages can populate the attack-surface graph.
- deterministic finding -> asset linkage (NULL unless an exact,
  unambiguous match exists - never guessed).
- DNS enrichment helper (writes DATA attributes only; never touches
  authorization, which stays snapshot-based in scope_resolution).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func
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
# Upper bound on DNS enrichment records applied in one call.
MAX_DNS_RECORDS = 500
# Upper bound on findings relinked in one backfill pass.
MAX_FINDING_LINKS = 2000

# Phase 4A attack-surface vocabulary (mirrors backend.db.models.ASSET_TYPES).
ASSET_TYPES = ("host", "subdomain", "domain", "service", "url", "endpoint")

# DNS enrichment attribute keys. DATA only - the authorization model
# (snapshot -> resolve_scope -> SafetyValidator) never reads them.
DNS_ATTR_KEYS = ("dns_a", "dns_aaaa", "dns_cname")

# Verification states for subdomain assets. New discoveries start
# unverified; future DNSX stages may advance them. Never authorization.
VERIFICATION_STATUSES = ("unverified", "resolved", "nxdomain", "error")

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


def build_domain_asset(
    *,
    domain: str,
    source_tool: str = "manual",
) -> dict[str, Any]:
    """Build a domain asset dict (Phase 4A foundation).

    Raises ValueError on malformed input - callers translating
    untrusted tool output must skip such items, never persist them.
    """
    name = (domain or "").strip().lower().rstrip(".")
    if not name or len(name) > 253 or " " in name or "://" in name or "*" in name:
        raise ValueError(f"Malformed domain asset: {domain!r}")
    return {
        "asset_type": "domain",
        "value": name,
        "host": name,
        "port": None,
        "scheme": None,
        "attributes": {},
        "source_tool": source_tool,
    }


def build_subdomain_asset(
    *,
    hostname: str,
    parent_domain: str | None = None,
    source: str = "manual",
    verification_status: str = "unverified",
    dns: dict[str, Any] | None = None,
    source_tool: str = "manual",
) -> dict[str, Any]:
    """Build a subdomain asset dict (Phase 4A foundation).

    The parent domain link is a (type, value) HINT resolved to
    parent_asset_id at persist time when the parent row exists in the
    same scan; otherwise it stays NULL. Raises ValueError on malformed
    hostnames.
    """
    name = (hostname or "").strip().lower().rstrip(".")
    if not name or len(name) > 253 or " " in name or "://" in name or "*" in name:
        raise ValueError(f"Malformed subdomain asset: {hostname!r}")
    if verification_status not in VERIFICATION_STATUSES:
        verification_status = "unverified"
    attributes: dict[str, Any] = {
        "source": source,
        "verification_status": verification_status,
    }
    if parent_domain:
        attributes["parent_domain"] = parent_domain.strip().lower().rstrip(".")
    for key in DNS_ATTR_KEYS:
        values = (dns or {}).get(key)
        if isinstance(values, list) and values:
            attributes[key] = [str(v)[:255] for v in values[:20]]
    asset: dict[str, Any] = {
        "asset_type": "subdomain",
        "value": name,
        "host": name,
        "port": None,
        "scheme": None,
        "attributes": attributes,
        "source_tool": source_tool,
    }
    if parent_domain:
        asset["parent_type"] = "domain"
        asset["parent_value"] = attributes["parent_domain"]
    return asset


def build_endpoint_asset(
    *,
    url: str,
    source_page: str | None = None,
    crawl_depth: int | None = None,
    http_method: str | None = None,
    source_tool: str = "manual",
) -> dict[str, Any]:
    """Build an endpoint asset dict (Phase 4A foundation).

    The parent URL link is a HINT (source_page -> url asset) resolved at
    persist time; NULL when unknown. Raises ValueError on malformed URLs.
    """
    candidate = (url or "").strip()
    try:
        parsed = urlparse(candidate)
    except ValueError:
        raise ValueError(f"Malformed endpoint asset: {url!r}") from None
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Malformed endpoint asset: {url!r}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    attributes: dict[str, Any] = {}
    if source_page:
        attributes["source_page"] = str(source_page)[:500]
    if crawl_depth is not None:
        try:
            attributes["crawl_depth"] = max(0, int(crawl_depth))
        except (TypeError, ValueError):
            pass
    if http_method:
        attributes["http_method"] = str(http_method).upper()[:10]
    asset: dict[str, Any] = {
        "asset_type": "endpoint",
        "value": candidate,
        "host": parsed.hostname,
        "port": port,
        "scheme": parsed.scheme or None,
        "attributes": attributes,
        "source_tool": source_tool,
    }
    if source_page:
        asset["parent_type"] = "url"
        asset["parent_value"] = str(source_page)[:500]
    return asset


def _finding_live_candidates(finding: dict[str, Any]) -> list[str]:
    """Ordered target candidates from a live finding dict."""
    candidates: list[str] = []
    for key in ("target", "asset"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for key in ("matched_at", "url", "host", "ip"):
            value = evidence.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _finding_row_candidates(row: Finding) -> list[str]:
    """Ordered target candidates reconstructed from a persisted row."""
    evidence = row.scanner_evidence or {}
    if not isinstance(evidence, dict):
        return []
    candidates: list[str] = []
    for key in ("matched_at", "url", "host", "ip"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    return candidates


def _candidate_host(candidate: str) -> str | None:
    """Reduce a candidate target to its host form for matching."""
    text_value = candidate.strip()
    if not text_value or " " in text_value:
        return None
    if "://" in text_value:
        try:
            host = urlparse(text_value).hostname
        except ValueError:
            return None
        return host.lower() if host else None
    return text_value.lower()


def resolve_finding_asset_id(
    session: Session, *, scan_id, candidates: list[str]
) -> Any | None:
    """Deterministically resolve a finding to one asset id in the scan.

    Match order: exact asset ``value`` hit first, then an exact ``host``
    hit ONLY when exactly one asset carries that host. Anything
    ambiguous or unknown returns None (never guessed). Read-only.
    """
    cleaned = [c for c in (candidates or []) if isinstance(c, str) and c.strip()]
    if not cleaned:
        return None
    for candidate in cleaned:
        row = (
            session.query(Asset.id)
            .filter(Asset.scan_id == scan_id, Asset.value == candidate[:500])
            .first()
        )
        if row is not None:
            return row[0]
    for candidate in cleaned:
        host = _candidate_host(candidate)
        if not host:
            continue
        rows = (
            session.query(Asset.id)
            .filter(Asset.scan_id == scan_id, Asset.host == host)
            .all()
        )
        if len(rows) == 1:
            return rows[0][0]
    return None


def link_findings_to_assets(session: Session, *, scan) -> int:
    """Backfill asset links for findings persisted before assets existed.

    Live findings are usually written (via the event sink) before the
    post-run asset pass, so their asset_id starts NULL. This matches
    them deterministically after assets exist. Returns rows linked.
    """
    rows = (
        session.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.asset_id.is_(None))
        .limit(MAX_FINDING_LINKS)
        .all()
    )
    linked = 0
    for row in rows:
        asset_id = resolve_finding_asset_id(
            session, scan_id=scan.id, candidates=_finding_row_candidates(row)
        )
        if asset_id is not None:
            row.asset_id = asset_id
            linked += 1
    session.flush()
    return linked


def apply_dns_enrichment(
    session: Session, *, scan, records: list[dict[str, Any]]
) -> int:
    """Merge DNS records into matching host/subdomain/domain attributes.

    DATA ONLY: writes attributes.dns_a/dns_aaaa/dns_cname on assets whose
    host exactly matches (case-insensitive). ``a``/``aaaa``/``cname``
    aliases are accepted for DNSX output, while the existing ``dns_*``
    names remain supported for older callers. Unknown hosts are skipped.
    Valid A/AAAA data advances an existing ``unverified`` asset to
    ``resolved``; CNAME-only data does not. Never touches scope,
    snapshots, or authorization state. Returns the number of matching
    assets enriched.
    """
    updated_ids: set[Any] = set()
    for record in (records or [])[:MAX_DNS_RECORDS]:
        if not isinstance(record, dict):
            continue
        raw_host = record.get("host")
        if not isinstance(raw_host, str) or not raw_host.strip():
            continue
        from backend.services.subdomain_policy import normalize_hostname

        hostname = normalize_hostname(raw_host)
        if hostname is None:
            continue
        enrichment, has_address = _normalize_dnsx_record(record)
        if not enrichment:
            continue
        rows = (
            session.query(Asset)
            .filter(
                Asset.scan_id == scan.id,
                Asset.asset_type.in_(("host", "subdomain", "domain")),
                func.lower(Asset.host) == hostname,
            )
            .all()
        )
        for row in rows:
            attributes = dict(row.attributes or {})
            for key, values in enrichment.items():
                existing = _normalize_dns_values(attributes.get(key), key)
                attributes[key] = _merge_dns_values(existing, values)
            if has_address and attributes.get("verification_status") == "unverified":
                attributes["verification_status"] = "resolved"
            row.attributes = _cap_strings(attributes)
            updated_ids.add(row.id)
    session.flush()
    return len(updated_ids)


def _normalize_dns_values(value: Any, key: str) -> list[str]:
    """Return bounded, valid, deterministic DNS values for one attribute."""
    if not isinstance(value, list):
        return []
    out: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text:
            continue
        if key == "dns_a":
            try:
                parsed = ipaddress.ip_address(text)
            except ValueError:
                continue
            if parsed.version != 4:
                continue
            text = str(parsed)
        elif key == "dns_aaaa":
            try:
                parsed = ipaddress.ip_address(text)
            except ValueError:
                continue
            if parsed.version != 6:
                continue
            text = str(parsed)
        elif key == "dns_cname":
            from backend.services.subdomain_policy import normalize_hostname

            text = normalize_hostname(text) or ""
            if not text:
                continue
        else:
            continue
        out.add(text[:255])
    return sorted(out)[:20]


def _merge_dns_values(existing: list[str], incoming: list[str]) -> list[str]:
    """Merge DNS values without order-dependent duplicates."""
    return sorted(set(existing).union(incoming))[:20]


def _normalize_dnsx_record(
    record: dict[str, Any],
) -> tuple[dict[str, list[str]], bool]:
    """Map one bounded DNSX record to persistence attributes.

    A/AAAA answers are accepted only when they are valid addresses of the
    corresponding family. CNAME values are retained as data, but are never
    resolved or used as lookup keys. The boolean reports whether this record
    contains at least one valid A or AAAA answer.
    """
    aliases = {
        "dns_a": ("dns_a", "a"),
        "dns_aaaa": ("dns_aaaa", "aaaa"),
        "dns_cname": ("dns_cname", "cname"),
    }
    enrichment: dict[str, list[str]] = {}
    for destination, keys in aliases.items():
        values: list[Any] = []
        for key in keys:
            raw = record.get(key)
            if isinstance(raw, list):
                values.extend(raw)
        normalized = _normalize_dns_values(values, destination)
        if normalized:
            enrichment[destination] = normalized
    return enrichment, bool(enrichment.get("dns_a") or enrichment.get("dns_aaaa"))


def _dnsx_observation_data(observation: Any) -> tuple[dict[str, Any], set[str]]:
    """Extract successful DNSX data and its trusted queried hostnames."""
    source = tool = status = ok = None
    if isinstance(observation, dict):
        source = observation.get("source")
        tool = observation.get("tool")
        status = observation.get("status")
        ok = observation.get("ok")
        data = observation.get("data") if "data" in observation else observation
    else:
        source = getattr(observation, "source", None)
        tool = getattr(observation, "tool", None)
        status = getattr(observation, "status", None)
        ok = getattr(observation, "ok", None)
        data = getattr(observation, "data", None)
    if source is not None and source != "tool":
        return {}, set()
    if tool is not None and tool != "dnsx":
        return {}, set()
    if status is not None and status != "ok":
        return {}, set()
    if ok is not None and ok is not True:
        return {}, set()
    if not isinstance(data, dict):
        return {}, set()
    from backend.services.subdomain_policy import normalize_hostname

    queried: set[str] = set()
    targets = data.get("targets")
    if isinstance(targets, list):
        for target in targets:
            normalized = normalize_hostname(target)
            if normalized is not None:
                queried.add(normalized)
    return data, queried


def apply_dnsx_enrichment(session: Session, *, scan, observation: Any) -> int:
    """Persist one successful DNSX ToolResult/Observation as data only.

    The DNSX result's validated ``targets`` list is the only lookup-key
    allowlist. Records for other hosts are ignored, and DNS values are never
    interpreted as assets, authorization targets, or follow-up work.
    """
    data, queried = _dnsx_observation_data(observation)
    records = data.get("records")
    if not isinstance(records, list) or not queried:
        return 0
    bounded_records: list[dict[str, Any]] = []
    from backend.services.subdomain_policy import normalize_hostname

    for record in records[:MAX_DNS_RECORDS]:
        if not isinstance(record, dict):
            continue
        host = normalize_hostname(record.get("host"))
        if host is None or host not in queried:
            continue
        bounded_records.append({**record, "host": host})
    return apply_dns_enrichment(session, scan=scan, records=bounded_records)


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
    # Deterministic asset link when the finding's target exactly matches
    # a known asset in this scan; NULL otherwise (never guessed). Live
    # findings usually precede assets, so link_findings_to_assets()
    # backfills the rest after the post-run asset pass.
    asset_id = resolve_finding_asset_id(
        session, scan_id=scan_id, candidates=_finding_live_candidates(finding)
    )
    row = Finding(
        scan_id=scan_id,
        project_id=project_id,
        asset_id=asset_id,
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


def _subfinder_assets(
    data: dict[str, Any], tool: str, *, snapshot: list[Any] | None = None
) -> list[dict[str, Any]]:
    """Map a subfinder observation to domain/subdomain assets (Phase 4B).

    Promotion gate (DISCOVERY IS NOT AUTHORIZATION):
    - the observation's ``domain`` must itself be valid AND, when a scan
      snapshot is available, an authorized snapshot parent; otherwise
      NOTHING from the observation is persisted (forged/mismatched).
    - each entry must be a valid descendant of that domain
      (label-aware); the root itself, wildcards, malformed and
      out-of-parent names are dropped.
    - verification_status/dns_a are carried as DATA with strict
      vocabularies; discovered IPs never become host assets here.
    The emitted domain asset lets same-batch parent_asset_id links
    resolve deterministically.
    """
    from backend.services.subdomain_policy import (
        is_within_domain,
        normalize_hostname,
        snapshot_parents,
    )

    norm_domain = normalize_hostname(data.get("domain"))
    if norm_domain is None:
        return []
    if snapshot is not None:
        parents = snapshot_parents(snapshot)
        if norm_domain not in parents:
            return []
    assets: list[dict[str, Any]] = []
    try:
        assets.append(build_domain_asset(domain=norm_domain, source_tool=tool))
    except ValueError:
        return []
    subdomains = data.get("subdomains")
    if not isinstance(subdomains, list):
        return assets
    for entry in subdomains:
        if not isinstance(entry, dict):
            continue
        host = normalize_hostname(entry.get("host"))
        if host is None or host == norm_domain:
            continue
        if not is_within_domain(host, norm_domain):
            continue
        status = entry.get("verification_status")
        if status not in VERIFICATION_STATUSES:
            status = "unverified"
        dns = entry.get("dns_a")
        try:
            assets.append(
                build_subdomain_asset(
                    hostname=host,
                    parent_domain=norm_domain,
                    source=str(entry.get("source") or "subfinder"),
                    verification_status=status,
                    dns={"dns_a": dns} if isinstance(dns, list) else None,
                    source_tool=tool,
                )
            )
        except ValueError:
            continue
    return assets


def _katana_assets(data: dict[str, Any], tool: str) -> list[dict[str, Any]]:
    """Map a future katana observation to endpoint assets.

    Dormant in Phase 4A (no katana tool is registered). Malformed
    entries are skipped. Endpoints link to their source page when it
    matches a known URL asset in the same scan, else parent stays NULL.
    """
    assets: list[dict[str, Any]] = []
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list):
        return []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        try:
            assets.append(
                build_endpoint_asset(
                    url=url,
                    source_page=(
                        entry.get("source_page")
                        if isinstance(entry.get("source_page"), str)
                        else None
                    ),
                    crawl_depth=entry.get("crawl_depth"),
                    http_method=(
                        entry.get("method")
                        if isinstance(entry.get("method"), str)
                        else None
                    ),
                    source_tool=tool,
                )
            )
        except ValueError:
            continue
    return assets


def assets_from_observation(
    observation: Any, *, snapshot: list[Any] | None = None
) -> list[dict[str, Any]]:
    """Derive asset dicts from one agent Observation (or equivalent mapping).

    Nmap hosts/ports become host/service assets; httpx services become
    URL assets; subfinder observations become domain/subdomain assets
    (promotion-gated); katana observations become endpoint assets
    (dormant until that tool exists). Only successful tool observations
    yield assets; anything malformed yields nothing rather than failing
    the run.

    ``snapshot`` (the scan's target_snapshot) authorizes the promotion
    gate for discovery observations; None means "no snapshot context"
    (the tool-validated domain in the observation is authoritative).
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
    if tool == "subfinder":
        return _subfinder_assets(data, str(tool), snapshot=snapshot)
    if tool == "katana":
        return _katana_assets(data, str(tool))
    # dnsx observations are enrichment input (apply_dns_enrichment), not
    # assets; nuclei observations become findings, not assets.
    return []


def persist_assets_from_observations(
    session: Session, *, scan, observations: list[Any]
) -> int:
    """Persist derived assets for a finished run; returns rows inserted.

    Existing (scan_id, asset_type, value) rows are skipped via a single
    pre-query, so reruns and retries never duplicate. Bounded at
    MAX_ASSETS_PER_RUN.

    Phase 4A: derived dicts may carry ``parent_type``/``parent_value``
    hints; these resolve to parent_asset_id when the parent row exists
    in the same scan (batch or pre-existing), else stay NULL.

    Phase 4B: the scan's target_snapshot is threaded through as the
    promotion gate for discovery observations (subfinder); observations
    whose domain is not an authorized snapshot parent yield nothing.
    """
    derived: list[dict[str, Any]] = []
    snapshot = getattr(scan, "target_snapshot", None)
    for obs in observations or []:
        derived.extend(assets_from_observation(obs, snapshot=snapshot))
        if len(derived) >= MAX_ASSETS_PER_RUN:
            break
    derived = derived[:MAX_ASSETS_PER_RUN]
    if not derived:
        return 0
    identity_to_id: dict[tuple[str, str], Any] = {
        (row.asset_type, row.value): row.id
        for row in session.query(Asset.id, Asset.asset_type, Asset.value).filter(
            Asset.scan_id == scan.id
        )
    }
    inserted = 0
    pending_links: list[tuple[Any, str, str]] = []
    for asset in derived:
        if asset.get("asset_type") not in ASSET_TYPES:
            continue
        value = str(asset["value"])[:500]
        identity = (asset["asset_type"], value)
        if identity in identity_to_id:
            continue
        row = Asset(
            scan_id=scan.id,
            project_id=scan.project_id,
            asset_type=asset["asset_type"],
            value=value,
            host=(str(asset["host"])[:255] if asset["host"] else None),
            port=asset["port"],
            scheme=(str(asset["scheme"])[:10] if asset["scheme"] else None),
            parent_asset_id=None,
            attributes=_cap_strings(asset.get("attributes") or {}),
            source_tool=str(asset["source_tool"])[:50],
        )
        session.add(row)
        session.flush()  # assign row.id for same-batch parent links
        identity_to_id[identity] = row.id
        parent_type = asset.get("parent_type")
        parent_value = asset.get("parent_value")
        if isinstance(parent_type, str) and isinstance(parent_value, str):
            pending_links.append((row, parent_type, str(parent_value)[:500]))
        inserted += 1
    for row, parent_type, parent_value in pending_links:
        parent_id = identity_to_id.get((parent_type, parent_value))
        if parent_id is not None and parent_id != row.id:
            row.parent_asset_id = parent_id
    session.flush()
    return inserted
