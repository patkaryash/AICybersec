"""Live website assessment authorization (Phase 5 Stage 1).

Stage 1 ships ONLY the authorization plane: admin-activated
authorization records, immutable per-scan snapshots, and verification.
There is NO live HTTP execution in Stage 1 - the ScanManager hard-refuses
``live_probe`` scans (see backend/services/scan_manager.py), so nothing
in this module performs network I/O and it must never grow one.

Security model (do not weaken):

- ``MODEL PROPOSES -> SAFETY VALIDATOR AUTHORIZES -> REGISTRY EXECUTES``
  is untouched; the live path (Stage 2+) will be a separate, dedicated
  execution path. Phase 4C discovery/promotion is NOT authorization and
  is not used here.
- Origins are EXACT normalized HTTP/HTTPS origins: no wildcards, ports
  80/443 only, no paths/query/fragments/userinfo, no scheme/port
  mismatches. Exclusions ALWAYS take precedence over allow rules.
- Evidence (reference or SHA-256 hash) is an audit pointer only; the
  platform does not claim it independently proves consent.
- Snapshots are copied at scan creation and verified against multiple
  independent anchors before every future use: the snapshot's own
  digest, an external digest column outside the snapshot, and a fresh
  render from the parent authorization record. Any drift, status
  change, expired/not-yet-valid window, policy-version mismatch, or
  empty effective origin set fails CLOSED (fail-closed, never
  fail-open).
- ``Project.scope`` / ``Scan.target_snapshot`` are never consulted or
  mutated for live scans; live scans carry ``target_snapshot=[]`` and
  authorize ONLY from the stored snapshot.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from pydantic import ValidationError

from agent_core.safety.policy import Policy

from backend.core.config import BackendSettings, get_backend_settings
from backend.core.errors import ApiError, ErrorCode
from backend.core.time import utc_iso
from backend.db.models import LiveAuthorization, Project, Scan, User
from backend.schemas.scans import ScanCreate
from backend.services import live_probe_budgets as budgets
from backend.services.project_service import get_project_for_user

# RFC 1123-style hostname (same strictness as scope_service: no
# non-ASCII, no wildcards, bounded label lengths, <= 253 total).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
# Stage 1 policy constants. The request-policy values (methods/paths/
# redirects) are sourced from the S2-2 single source in
# ``live_probe_budgets`` so authorization snapshots and execution
# profiles can never drift apart; ``discovery`` is a Stage-1-only fact
# (never any part of the live request policy). These are centrally
# enforced initial policy values, NOT proven safety guarantees.
LIVE_PROBE_PATHS = budgets.LIVE_PROBE_PATHS
LIVE_PROBE_METHODS = budgets.LIVE_PROBE_METHODS
LIVE_PROBE_FOLLOW_REDIRECTS = budgets.LIVE_PROBE_FOLLOW_REDIRECTS
LIVE_PROBE_DISCOVERY = False


def _ensure_utc(dt: datetime) -> datetime:
    """Treat naive datetimes as UTC (client clocks are not trusted)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Origin validation / canonicalization
# --------------------------------------------------------------------------
def parse_origin(value: object) -> dict[str, Any]:
    """Validate + canonicalize ONE exact HTTP/HTTPS origin.

    Accepted form: ``scheme://host[:port]`` where scheme is http/https,
    ``host`` is a valid DNS name (IP literals are REJECTED - see
    ``_canonical_origin_host``), and ``port`` (when explicit) equals the
    scheme's default (http -> 80, https -> 443); explicit mismatches are
    rejected as ambiguous. The canonical result is always the scheme's
    default-port origin, so two spellings of the same origin collapse to
    one entry.

    Rejected with LIVE_AUTHORIZATION_INVALID: wildcards, unsupported
    schemes, other ports, any path/query/fragment (including a bare
    "/" and even EMPTY query/fragments written as raw '?'/'#'
    delimiters), embedded credentials/userinfo, IP-literal hosts, and
    malformed or oversized hosts. No DNS resolution happens here
    (Stage 1 performs no network I/O).
    """
    invalid = ApiError(
        ErrorCode.LIVE_AUTHORIZATION_INVALID,
        f"Invalid live origin: {value!r}",
    )
    if not isinstance(value, str):
        raise invalid
    raw = value.strip()
    if not raw or "*" in raw or any(c.isspace() for c in raw):
        raise invalid
    # F4 hardening: reject raw '?'/'#' delimiters BEFORE parsing. An
    # EMPTY query or fragment parses as an empty string, so relying on
    # the parsed fields' truthiness would let "https://a.com?" and
    # "https://a.com#" slip through; mutation of the delimiters may
    # change what a request means, so we refuse the raw spellings.
    if "?" in raw or "#" in raw:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Live origin must not include a query/fragment delimiter: {raw!r}",
        )
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _DEFAULT_PORTS:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Unsupported scheme in live origin {raw!r}; use http or https",
        )
    scheme = parsed.scheme.lower()
    # Credentials/userinfo (any '@' in the netloc) are always rejected.
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Embedded credentials in live origin are not allowed: {raw!r}",
        )
    # Only empty path is accepted; "/" and every other path, query and
    # fragment are rejected (the v1 profile requests "/" centrally).
    if parsed.path not in ("",):
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Live origin must not include a path/query/fragment: {raw!r}",
        )
    if parsed.query or parsed.fragment or parsed.params:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Live origin must not include a path/query/fragment: {raw!r}",
        )
    host = parsed.hostname
    if host is None:
        raise invalid
    try:
        port = parsed.port  # raises ValueError on malformed ports
    except ValueError:
        raise invalid from None
    host = _canonical_origin_host(host, raw)
    default_port = _DEFAULT_PORTS[scheme]
    if port is not None and port != default_port:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"Live origin port must equal the scheme default ({default_port}) "
            f"for scheme {scheme!r}: {raw!r}",
        )
    origin = f"{scheme}://{host}"
    return {"origin": origin, "scheme": scheme, "host": host, "port": default_port}


def _canonical_origin_host(host: str, raw: str) -> str:
    """Validate + canonicalize the host part of a live origin.

    F1 hardening: ALL IP literals are REJECTED (IPv4 and IPv6, in any
    spelling). Rationale: IPv6 literals require bracket handling that
    v1 does not implement correctly, and staging-away IP-literal
    authorization eliminates the whole class of canonicalization bugs
    (bracket stripping, IPv4-mapped IPv6, hex/octal spellings) until
    Stage 2 implements the destination controls properly.

    Details:
    - ``urlparse`` strips IPv6 brackets, so ``[::1]`` arrives here as
      ``"::1"``; a colon can never be part of a DNS hostname, so any
      colonated host is rejected as an IP literal.
    - Digits-only hostnames are rejected too (they are not real DNS
      hostnames and exist only to smuggle addresses/ports).
    - dotted-quad shapes that are NOT valid IPs ("256.0.0.1") and
      octets with leading zeros ("0177.0.0.1", never parseable as an
      address either) are rejected by the strict hostname regex.
    """
    ip_literal = ApiError(
        ErrorCode.LIVE_AUTHORIZATION_INVALID,
        f"IP-literal live origins are not supported yet: {raw!r}; "
        "authorize an exact DNS hostname instead.",
    )
    lowered = host.lower()
    if ":" in lowered or lowered.isdigit():
        raise ip_literal
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        pass
    else:
        raise ip_literal
    if _IPV4_RE.match(lowered) or _ipish_host(lowered):
        raise ip_literal
    invalid = ApiError(
        ErrorCode.LIVE_AUTHORIZATION_INVALID,
        f"Invalid live origin: {raw!r}",
    )
    if len(lowered) > 253 or not _HOSTNAME_RE.match(lowered):
        raise invalid
    return lowered


def _ipish_host(host: str) -> bool:
    """True for dotted spellings OS resolvers would interpret as
    addresses WITHOUT a trailing dot: all-numeric labels (decimal or
    zero-padded octal, e.g. ``0177.0.0.1``) and hex labels (``0x7f.1``).
    No real hostname pattern is affected."""
    labels = host.split(".")
    if len(labels) > 1 and all(lbl.isdigit() for lbl in labels):
        return True
    return any(lbl.startswith("0x") for lbl in labels)


def _parse_origin_list(
    values: list[str],
    *,
    field: str,
    dedupe: bool = True,
) -> list[dict[str, Any]]:
    """Validate a list of origins; canonical, order-preserving / sorted."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for v in values:
        entry = parse_origin(v)
        if dedupe and entry["origin"] in seen:
            continue
        seen.add(entry["origin"])
        out.append(entry)
    if not out:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            f"At least one valid origin is required in {field!r}",
        )
    return sorted(out, key=lambda e: e["origin"])


# --------------------------------------------------------------------------
# Evidence validation
# --------------------------------------------------------------------------
def _validate_evidence(
    evidence_ref: str | None, evidence_sha256: str | None
) -> tuple[str | None, str | None]:
    """Require an auditable evidence reference or SHA-256 evidence hash.

    The evidence is an audit pointer only - it is never treated as
    independent proof of target-owner consent.
    """
    ref = evidence_ref.strip() if isinstance(evidence_ref, str) else None
    ref = ref or None
    sha = evidence_sha256.strip().lower() if isinstance(evidence_sha256, str) else None
    sha = sha or None
    if sha is not None and not _SHA256_RE.match(sha):
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            "evidence_sha256 must be a lowercase SHA-256 hex digest (64 hex chars).",
        )
    if ref is None and sha is None:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            "An evidence reference or SHA-256 evidence hash is required.",
        )
    return ref, sha


# --------------------------------------------------------------------------
# Authorization lifecycle
# --------------------------------------------------------------------------
def get_live_authorization_for_user(
    session: Session, authorization_id: uuid.UUID, user: User
) -> LiveAuthorization:
    """Ownership gate for authorizations (anti-enumeration).

    Consistent 404 LIVE_AUTHORIZATION_NOT_FOUND when the record is
    missing OR its project is invisible to the user (admins bypass).
    """
    auth = session.get(LiveAuthorization, authorization_id)
    if auth is None:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_NOT_FOUND, "Authorization does not exist."
        )
    project = session.get(Project, auth.project_id)
    if user.role != "admin" and (project is None or project.owner_id != user.id):
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_NOT_FOUND, "Authorization does not exist."
        )
    return auth


def _require_admin(user: User) -> None:
    """Activation-surface role gate: only admins may create, suspend or
    revoke authorizations (the existing role system provides the roles)."""
    if user.role != "admin":
        raise ApiError(
            ErrorCode.ADMIN_REQUIRED,
            "Only administrators may manage live authorizations.",
        )


def create_live_authorization(
    session: Session, *, user: User, data: Any, settings: BackendSettings | None = None
) -> LiveAuthorization:
    """Create (activate) one authorization record. Admin-only.

    The record is immutable after creation: no update endpoint exists;
    lifecycle movements are one-way (suspend/revoke); suspended records
    are not resumable in v1.
    """
    _require_admin(user)
    settings = settings or get_backend_settings()
    now = datetime.now(timezone.utc)

    project = session.get(Project, data.project_id)
    if project is None:
        raise ApiError(ErrorCode.PROJECT_NOT_FOUND, "Project does not exist.")

    origins = _parse_origin_list(list(data.origins), field="origins")
    exclusions = (
        _parse_origin_list(list(data.exclusions), field="exclusions")
        if data.exclusions
        else []
    )
    allowed = {e["origin"] for e in origins}
    excluded = {e["origin"] for e in exclusions}
    if allowed and not (allowed - excluded):
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            "Exclusions remove every approved origin; nothing would be authorized.",
        )

    evidence_ref, evidence_sha256 = _validate_evidence(data.evidence_ref, data.evidence_sha256)

    valid_from = _ensure_utc(data.valid_from) if data.valid_from is not None else now
    max_days = max(1, int(settings.live_probe_max_authorization_days))
    max_until = valid_from + timedelta(days=max_days)
    if data.valid_until is not None:
        valid_until = _ensure_utc(data.valid_until)
        if valid_until <= valid_from:
            raise ApiError(
                ErrorCode.LIVE_AUTHORIZATION_INVALID,
                "valid_until must be after valid_from.",
            )
        if valid_until > max_until:
            raise ApiError(
                ErrorCode.LIVE_AUTHORIZATION_INVALID,
                f"Authorization lifetime must not exceed {max_days} day(s).",
            )
    else:
        valid_until = max_until

    auth = LiveAuthorization(
        project_id=project.id,
        status="active",
        policy_version=settings.live_probe_policy_version,
        evidence_ref=evidence_ref,
        evidence_sha256=evidence_sha256,
        origins=origins,
        exclusions=exclusions,
        methods=list(LIVE_PROBE_METHODS),
        approved_by=user.id,
        approved_at=now,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    session.add(auth)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise ApiError(
            ErrorCode.DATABASE_ERROR, "Could not persist the authorization."
        ) from None
    session.refresh(auth)
    return auth


def suspend_live_authorization(
    session: Session, *, user: User, authorization_id: uuid.UUID
) -> LiveAuthorization:
    """active -> suspended (admin-only). NOT resumable in v1: a new
    authorization must be issued. Already suspended -> 409."""
    _require_admin(user)
    auth = get_live_authorization_for_user(session, authorization_id, user)
    if auth.status == "suspended":
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID_STATE,
            "Authorization is already suspended.",
        )
    if auth.status != "active":
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID_STATE,
            "Only active authorizations can be suspended.",
        )
    auth.status = "suspended"
    session.commit()
    session.refresh(auth)
    return auth


def revoke_live_authorization(
    session: Session, *, user: User, authorization_id: uuid.UUID
) -> LiveAuthorization:
    """active/suspended -> revoked (admin-only, one-way). Already
    revoked -> 409."""
    _require_admin(user)
    auth = get_live_authorization_for_user(session, authorization_id, user)
    if auth.status == "revoked":
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID_STATE,
            "Authorization is already revoked.",
        )
    auth.status = "revoked"
    session.commit()
    session.refresh(auth)
    return auth


def list_live_authorizations(
    session: Session,
    *,
    user: User,
    page: int,
    page_size: int,
    project_id: uuid.UUID | None = None,
) -> tuple[list[LiveAuthorization], int]:
    """Authorizations visible to the user: project-visibility filtered
    (owners see their own projects' records; admins see all). An
    explicit invisible project_id -> 404 (consistent with detail)."""
    query = select(LiveAuthorization).join(
        Project, LiveAuthorization.project_id == Project.id
    )
    if user.role != "admin":
        query = query.where(Project.owner_id == user.id)
    if project_id is not None:
        get_project_for_user(session, project_id, user)  # 404 when invisible
        query = query.where(LiveAuthorization.project_id == project_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(LiveAuthorization.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total


def effective_origins(origins: list[dict], exclusions: list[dict]) -> list[dict]:
    """Exclusions ALWAYS take precedence over allow rules (order stable)."""
    blocked = {e["origin"] for e in exclusions or []}
    return [e for e in origins or [] if e["origin"] not in blocked]


# --------------------------------------------------------------------------
# Immutable authorization snapshots
# --------------------------------------------------------------------------
def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def authorization_payload(
    auth: LiveAuthorization, *, now: datetime | None = None
) -> dict[str, Any]:
    """Validate the record's CURRENT use-worthiness and render its
    canonical snapshot payload.

    Checked here (and again at every verification, never trusted from
    the stored copy alone): status == active, valid_from <= now <
    valid_until, policy version matches the platform configuration, the
    effective (allow-minus-exclusion) origin set is non-empty, and the
    permitted methods/paths are the Stage-1 policy values. Raises
    LIVE_SCAN_NOT_PERMITTED (403) otherwise.
    """
    settings = get_backend_settings()
    now = now or datetime.now(timezone.utc)
    if auth.status != "active":
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            f"Live authorization is {auth.status}.",
        )
    valid_from = _ensure_utc(auth.valid_from)
    valid_until = _ensure_utc(auth.valid_until)
    if now < valid_from:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Live authorization is not yet valid.",
        )
    if now >= valid_until:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Live authorization has expired.",
        )
    if auth.policy_version != settings.live_probe_policy_version:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Live authorization policy version is not current (policy drift).",
        )
    if list(auth.methods) != LIVE_PROBE_METHODS:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Live authorization methods do not match the Stage 1 policy.",
        )
    effective = effective_origins(list(auth.origins or []), list(auth.exclusions or []))
    if not effective:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Exclusions remove every approved origin; nothing is authorized.",
        )
    # Verify the stored origin entries are still canonical (defense in
    # depth against DB-level edits; renders digests deterministic).
    render = _parse_origin_list(
        [e["origin"] for e in effective], field="snapshotted origins"
    )
    if [e["origin"] for e in render] != [e["origin"] for e in effective]:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Stored live origins are not canonical.",
        )
    return {
        "authorization_id": str(auth.id),
        "project_id": str(auth.project_id),
        "policy_version": auth.policy_version,
        "valid_from": utc_iso(valid_from),
        "valid_until": utc_iso(valid_until),
        "origins": list(auth.origins or []),
        "exclusions": list(auth.exclusions or []),
        "methods": list(auth.methods or []),
        "paths": list(LIVE_PROBE_PATHS),
        "follow_redirects": LIVE_PROBE_FOLLOW_REDIRECTS,
        "discovery": LIVE_PROBE_DISCOVERY,
    }


def build_authorization_snapshot(
    auth: LiveAuthorization, *, now: datetime | None = None
) -> dict[str, Any]:
    """Validate + copy an immutable snapshot of the authorization.

    The snapshot embeds its SHA-256 digest; the ScanManager keeps a
    SECOND copy of the digest in a separate column so silent snapshot
    edits are detected (snapshot integrity is verified against all
    anchors at use time, never assumed).
    """
    payload = authorization_payload(auth, now=now)
    payload["digest"] = _digest(_snapshot_core(payload))
    return payload


def _snapshot_core(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in snapshot.items() if k != "digest"}


def _err_tampered() -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        "Live authorization snapshot failed the integrity check.",
    )


def verify_snapshot_payload(
    snapshot: Any,
    stored_digest: str | None,
    *,
    now: datetime | None = None,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Pure snapshot verification (no DB): structure, embedded digest,
    external digest anchor, validity window, policy version, exclusions
    precedence. Returns the verified core payload; raises
    LIVE_SCAN_NOT_PERMITTED on any deviation (fail closed)."""
    if not isinstance(snapshot, dict):
        raise _err_tampered()
    try:
        embedded = snapshot.get("digest")
        core = _snapshot_core(snapshot)
        if not isinstance(embedded, str) or embedded != _digest(core):
            raise _err_tampered()
        if stored_digest is None or embedded != stored_digest:
            raise _err_tampered()
        authorization_id = uuid.UUID(str(core["authorization_id"]))
        project_id = uuid.UUID(str(core["project_id"]))
        if core.get("follow_redirects") is not False or core.get("discovery") is not False:
            raise _err_tampered()
        origins = core.get("origins")
        exclusions = core.get("exclusions")
        methods = core.get("methods")
        if core.get("policy_version") != (policy_version or get_backend_settings().live_probe_policy_version):
            raise ApiError(
                ErrorCode.LIVE_SCAN_NOT_PERMITTED,
                "Live authorization policy version is not current (policy drift).",
            )
        if core["methods"] != LIVE_PROBE_METHODS or core["paths"] != LIVE_PROBE_PATHS:
            raise _err_tampered()
        # Re-canonicalize; structural drift means tampering or corruption.
        rendered_origins = _parse_origin_list(
            [e["origin"] for e in origins], field="snapshotted origins"
        )
        if [e["origin"] for e in rendered_origins] != [e["origin"] for e in origins]:
            raise _err_tampered()
        if exclusions and [e["origin"] for e in _parse_origin_list(
            [e["origin"] for e in exclusions], field="snapshotted exclusions"
        )] != [e["origin"] for e in exclusions]:
            raise _err_tampered()
        if not effective_origins(origins, exclusions):
            raise ApiError(
                ErrorCode.LIVE_SCAN_NOT_PERMITTED,
                "Exclusions remove every approved origin; nothing is authorized.",
            )
        valid_from = _ensure_utc(
            datetime.fromisoformat(core["valid_from"].replace("Z", "+00:00"))
        )
        valid_until = _ensure_utc(
            datetime.fromisoformat(core["valid_until"].replace("Z", "+00:00"))
        )
        now_dt = now or datetime.now(timezone.utc)
        if now_dt < valid_from:
            raise ApiError(
                ErrorCode.LIVE_SCAN_NOT_PERMITTED,
                "Live authorization is not yet valid.",
            )
        if now_dt >= valid_until:
            raise ApiError(
                ErrorCode.LIVE_SCAN_NOT_PERMITTED,
                "Live authorization has expired.",
            )
        core["authorization_id"] = authorization_id
        core["project_id"] = project_id
        return core
    except ApiError:
        raise
    except Exception:
        raise _err_tampered() from None


def verify_live_scan_authorization(
    session: Session, scan: Scan, *, now: datetime | None = None
) -> dict[str, Any]:
    """FULL verification for one live scan, for use before ANY execution.

    Verifies (all must hold, else fail closed):
    1. snapshot structural integrity + embedded digest,
    2. the external digest anchor column,
    3. the parent authorization STILL EXISTS and a fresh render of it
       digests identically (detects authorization drift/tampering after
       snapshot creation),
    4. parent status/window/policy version (via authorization_payload),
    5. authorization id/project binding inside the snapshot,
    6. the scan row actually REFERENCES the authorization its snapshot
       identifies (F5 hardening: a valid snapshot whose authorization_id
       does not equal ``scan.live_authorization_id`` - or a snapshot
       missing the field - must not pass; a mismatch proves the snapshot
       was swapped/copied across scans or truncated).
    """
    settings = get_backend_settings()
    snapshot = scan.authorization_snapshot
    verified = verify_snapshot_payload(
        snapshot,
        scan.authorization_snapshot_digest,
        now=now,
        policy_version=settings.live_probe_policy_version,
    )
    if (
        scan.live_authorization_id is None
        or verified["authorization_id"] != scan.live_authorization_id
    ):
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Scan does not reference the authorization in its snapshot.",
        )
    auth = session.get(LiveAuthorization, verified["authorization_id"])
    if auth is None:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Live authorization no longer exists.",
        )
    fresh = authorization_payload(auth, now=now)
    if _digest(fresh) != _digest(_snapshot_core(snapshot)):
        raise _err_tampered()
    if verified["authorization_id"] != auth.id or verified["project_id"] != auth.project_id:
        raise _err_tampered()
    if scan.project_id != auth.project_id:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Authorization does not belong to this project.",
        )
    # Stage 2: execution-profile verification (ALL §4.3 rules), AFTER the
    # parent authorization re-verification, re-deriving the
    # authorization id from the STAGE-1-verified snapshot above (never
    # from the profile's own claims). No profile attribute may relax any
    # check below; every deviation fails closed.
    verify_execution_profile(scan, verified["authorization_id"])
    return verified


# --------------------------------------------------------------------------
# Execution-profile verification (Phase 5 Stage 2, §4.3)
# --------------------------------------------------------------------------
def _err_profile_missing() -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        "Execution profile missing: pre-migration queued rows must be re-issued.",
    )


def _err_profile_schema() -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        "Execution profile failed strict schema validation.",
    )


def _err_profile_integrity() -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        "Execution profile failed the integrity check.",
    )


def _err_profile_policy() -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        "Execution profile policy version is not current (policy drift).",
    )


def _err_profile_binding(detail: str) -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        f"Execution profile does not bind to this scan: {detail}",
    )


def _err_profile_budget(detail: str) -> ApiError:
    return ApiError(
        ErrorCode.LIVE_SCAN_NOT_PERMITTED,
        f"Execution profile budget/policy mismatch: {detail}",
    )


def verify_execution_profile(
    scan: Scan, snapshot_authorization_id: uuid.UUID
) -> dict[str, Any]:
    """Verify the scan's immutable execution profile against LIVE values.

    Implements ALL §4.3 rules, evaluated against the live database row
    and the CURRENT settings every time. The digest is a consistency
    check ONLY - never authorization and never a substitute for the
    semantic checks below:

    1. scan binding: profile.scan_id == the actual scan row id;
    2. authorization binding: profile.authorization_id ==
       scan.live_authorization_id AND == the STAGE-1-verified snapshot's
       authorization_id (all three must agree);
    3. project binding: profile.project_id == scan.project_id;
    4. policy conformance: policy_version == the current SETTING and
       EVERY budget field equals the server constants exactly,
       field-by-field, including dns_policy.record_groups == ["A","AAAA"];
    5. hardcoded shape: executor == "live_transport_v1" and
       steps == ["live_root_get"] (hardcoded allowlist);
    6. strict schema (``extra="forbid"``): missing/malformed/unknown
       fields fail closed.

    A forged profile whose digest was correctly RECOMPUTED still fails
    on the binding rules 1-3 here; a policy-version bump drift-fails
    rule 4 the same way Stage 1 snapshots do. Missing payload or digest
    (e.g. pre-migration queued rows) fails closed with an explicit
    refusal. There is NO live execution after a refusal.
    """
    payload = scan.execution_profile
    stored_digest = scan.execution_profile_digest
    # Rule 6 (presence) + rule 6 (shape) + rule 6 (extra=forbid) in one
    # strict validation; types are strict so wrong types fail parsing.
    if not isinstance(payload, dict) or isinstance(payload, bool):
        raise _err_profile_missing()
    if not isinstance(stored_digest, str) or not _SHA256_RE.match(stored_digest):
        raise _err_profile_missing()
    try:
        parsed = budgets.LiveProbeExecutionProfile.model_validate(payload)
    except ValidationError:
        raise _err_profile_schema() from None
    # Profile payloads carry NO digest key: §4.2 lists exactly the
    # canonical fields, and a "digest" key would be rejected by
    # extra="forbid" above. The external anchor is the only digest.
    if stored_digest != _digest(payload):
        # Consistency check only: detects accidental edits/stale-column
        # writes; semantic rules below run regardless and decide nothing
        # by absent digest equality.
        raise _err_profile_integrity()
    settings = get_backend_settings()
    if parsed.policy_version != settings.live_probe_policy_version:
        raise _err_profile_policy()
    # Rule 1-3: bindings against live DB values.
    if parsed.scan_id != scan.id:
        raise _err_profile_binding("scan_id does not match the scan row.")
    if (
        parsed.authorization_id != scan.live_authorization_id
        or parsed.authorization_id != snapshot_authorization_id
    ):
        raise _err_profile_binding(
            "authorization_id does not match the scan FK and snapshot."
        )
    if parsed.project_id != scan.project_id:
        raise _err_profile_binding("project_id does not match the scan row.")
    # Rule 4: budget conformance, EXACTLY field-by-field against the
    # pinned constants (never "digest-only").
    expected = {
        "max_requests_per_scan": budgets.LIVE_PROBE_SCAN_REQUEST_BUDGET,
        "requests_per_second": budgets.LIVE_PROBE_REQUESTS_PER_SECOND,
        "per_request_timeout_s": budgets.LIVE_PROBE_REQUEST_TIMEOUT_S,
        "wall_clock_s": budgets.LIVE_PROBE_SCAN_WALL_CLOCK_S,
        "response_max_bytes": budgets.LIVE_PROBE_RESPONSE_MAX_BYTES,
        "max_concurrent_connections": budgets.LIVE_PROBE_MAX_CONCURRENT_CONNECTIONS,
        "dns_timeout_s": budgets.LIVE_PROBE_DNS_TIMEOUT_S,
    }
    for field, value in expected.items():
        if getattr(parsed.budgets, field) != value:
            raise _err_profile_budget(f"{field} is not the server-pinned value.")
    # Rule 4 (DNS): BOTH families are ALWAYS queried; A-only profiles
    # are invalid, and the entire v1 DNS policy is pinned.
    if parsed.dns_policy.record_groups != list(budgets.LIVE_PROBE_DNS_RECORD_GROUPS):
        raise _err_profile_budget(
            "dns_policy.record_groups must be exactly ['A','AAAA']."
        )
    if parsed.dns_policy.answer_set_policy != budgets.LIVE_PROBE_DNS_ANSWER_SET_POLICY:
        raise _err_profile_budget(
            "dns_policy.answer_set_policy is not the server-pinned value."
        )
    if parsed.dns_policy.cname_following is not budgets.LIVE_PROBE_DNS_CNAME_FOLLOWING:
        raise _err_profile_budget(
            "dns_policy.cname_following is not the server-pinned value."
        )
    if parsed.dns_policy.cache != budgets.LIVE_PROBE_DNS_CACHE:
        raise _err_profile_budget("dns_policy.cache is not the server-pinned value.")
    # Request policy must equal the pinned constants too (v1 shape).
    if parsed.request_policy.methods != list(budgets.LIVE_PROBE_METHODS):
        raise _err_profile_budget("methods is not the server-pinned value.")
    if parsed.request_policy.paths != list(budgets.LIVE_PROBE_PATHS):
        raise _err_profile_budget("paths is not the server-pinned value.")
    if parsed.request_policy.ports != list(budgets.LIVE_PROBE_PORTS):
        raise _err_profile_budget("ports is not the server-pinned value.")
    if (
        parsed.request_policy.follow_redirects is not False
        or parsed.request_policy.honor_env_proxies is not False
    ):
        raise _err_profile_budget(
            "follow_redirects/honor_env_proxies must be false."
        )
    if parsed.request_policy.accept_encoding != budgets.LIVE_PROBE_ACCEPT_ENCODING:
        raise _err_profile_budget("accept_encoding is not the server-pinned value.")
    if parsed.mode != budgets.LIVE_PROBE_PINNED_MODE:
        raise _err_profile_budget("mode is not the server-pinned value.")
    # Rule 5: hardcoded executor + step allowlist (no unknown executor,
    # no extra/renamed steps).
    if (
        parsed.executor != budgets.LIVE_PROBE_EXECUTOR
        or parsed.steps != list(budgets.LIVE_PROBE_EXECUTOR_STEPS)
    ):
        raise _err_profile_binding(
            "executor/steps are not on the hardcoded allowlist."
        )
    return parsed.model_dump(mode="json")


# --------------------------------------------------------------------------
# Live scan creation (Stage 1: records + snapshots ONLY, no execution)
# --------------------------------------------------------------------------
def _require_flag(settings: BackendSettings) -> None:
    if not settings.live_probe_enabled:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            (
                "Live assessment is disabled "
                "(AICYBERSEC_LIVE_PROBE_ENABLED=false)."
            ),
        )


def create_live_scan(session: Session, *, user: User, data: ScanCreate) -> Scan:
    """Create a queued live_probe scan with an immutable authorization
    snapshot copied from the record. NO execution is scheduled and no
    discovery/planner path is involved.

    Gates: feature flag, exact project/authorization binding (consistent
    404 anti-enumeration + 403 on cross-project binding), record
    status/validity/policy version, and non-empty effective origins.
    ``target_snapshot`` stays EMPTY: the authorization anchor is the
    snapshot, never Project.scope.

    F3 hardening: execution parameters (mode/max_steps/tool_timeout_s)
    are PINNED server-side from ``live_probe_budgets`` constants; the
    client-supplied values are never honored and silently discarded, so
    no client input can ever differ from the pinned execution profile.

    S2-2 issuance: right after the authorization snapshot, the immutable
    execution profile is rendered EXACTLY ONCE from the pinned
    constants (plus the scan/authorization/project binding uuids and
    the current policy-version SETTING), digest-stamped with the same
    canonical-JSON algorithm as snapshots, and stored with the scan.
    No client field may influence any profile value; ``ScanCreate``
    inputs stay discarded.
    """
    settings = get_backend_settings()
    _require_flag(settings)
    if data.live_authorization_id is None:
        raise ApiError(
            ErrorCode.LIVE_AUTHORIZATION_INVALID,
            "live_authorization_id is required for live_probe scans.",
        )
    project = get_project_for_user(session, data.project_id, user)
    auth = get_live_authorization_for_user(session, data.live_authorization_id, user)
    if auth.project_id != project.id:
        raise ApiError(
            ErrorCode.LIVE_SCAN_NOT_PERMITTED,
            "Authorization does not belong to this project.",
        )
    snapshot = build_authorization_snapshot(auth)
    scan_id = uuid.uuid4()
    # S2-2: the execution profile is rendered ONCE, from constants only.
    profile_payload = budgets.render_execution_profile(
        profile_id=uuid.uuid4(),
        scan_id=scan_id,
        authorization_id=auth.id,
        project_id=project.id,
        policy_version=settings.live_probe_policy_version,
    )
    profile_digest = _digest(profile_payload)
    scan = Scan(
        id=scan_id,
        project_id=project.id,
        status="queued",
        profile="live_probe",
        goal=data.goal,
        target_snapshot=[],
        live_authorization_id=auth.id,
        authorization_snapshot=snapshot,
        authorization_snapshot_digest=snapshot["digest"],
        execution_profile=profile_payload,
        execution_profile_digest=profile_digest,
        # F3: pinned, client input NEVER honored for live scans.
        mode=budgets.LIVE_PROBE_PINNED_MODE,
        max_steps=budgets.LIVE_PROBE_PINNED_MAX_STEPS,
        tool_timeout_s=budgets.LIVE_PROBE_PINNED_TOOL_TIMEOUT_S,
    )
    session.add(scan)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        if _is_active_scan_unique_conflict(exc):
            raise ApiError(
                ErrorCode.SCAN_ALREADY_RUNNING, "Project already has an active scan."
            ) from None
        # Anything else (e.g. an FK RESTRICT integrity failure under the
        # 0004 semantics) is a database error, NOT a scan-already-running
        # conflict - mislabeling it as 409 would leak a wrong state code.
        raise ApiError(
            ErrorCode.DATABASE_ERROR,
            "Could not persist the live scan.",
        ) from None
    session.refresh(scan)
    return scan


def _is_active_scan_unique_conflict(exc: IntegrityError) -> bool:
    """True ONLY for the uq_scans_project_active partial-unique race.

    The active-scan conflict is identified by its constraint/index name
    (psycopg's diag.constraint_name when available, else the raw error
    text); every other IntegrityError is database/error-path territory,
    never SCAN_ALREADY_RUNNING."""
    orig = getattr(exc, "orig", None)
    constraint = None
    diag = getattr(orig, "diag", None)
    if diag is not None:
        constraint = getattr(diag, "constraint_name", None)
    if constraint is None and orig is not None:
        constraint = str(orig)
    return "uq_scans_project_active" in str(constraint or "")
