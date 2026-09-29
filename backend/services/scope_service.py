"""Target scope validation and canonicalization.

The project scope is the ONLY authorization source for scans; entries
are validated and canonicalized here before persistence. Host-shaped
matching reuses agent_core's Policy.normalize_target (backend ->
agent_core dependency only; agent_core is never modified).

Supported entry types:
    host:   hostname, IPv4, IPv6 (canonical: lowercase / compressed)
    cidr:   IPv4/IPv6 network (canonical: network address form)
    url:    http/https URL (validated; reduced to host form at MATCH time
            by Policy.normalize_target, so one entry covers the URL)
    domain: DNS domain name authorizing assessment of that exact domain
            (canonical: lowercase). A domain entry authorizes ONLY the
            exact domain itself - subdomains discovered later (e.g. via
            future Subfinder/DNSX stages) remain discovered CANDIDATES
            until an explicit promotion rule authorizes them; they are
            never implicitly in scope (see target_in_scope).

Rejects with INVALID_TARGET: malformed hostnames, invalid IPs, invalid
CIDR, unsupported schemes, embedded credentials, invalid ports,
malformed URLs.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from agent_core.safety.policy import Policy

from backend.core.errors import ApiError, ErrorCode
from backend.schemas.projects import ScopeEntry

# RFC 1123-style hostname: labels of letters/digits/hyphens, not starting
# or ending with a hyphen, total length <= 253.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)

ALLOWED_URL_SCHEMES = ("http", "https")

# A dotted quad that fails IP parsing is malformed, not a hostname.
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _validate_hostname(value: str) -> str:
    """Validate + canonicalize a hostname or IP literal entry."""
    v = value.strip()
    if v.endswith("."):  # strip at most one trailing root dot
        v = v[:-1]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if _IPV4_RE.match(v):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed IP: {value!r}")
    lowered = v.lower()
    if not lowered or len(lowered) > 253 or not _HOSTNAME_RE.match(lowered):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed host: {value!r}")
    return lowered


def _validate_domain(value: str) -> str:
    """Validate + canonicalize a domain scope entry (Phase 4A).

    Strict DNS-name-only rule: no URL scheme, no userinfo, no wildcard,
    no leading '-', no IP literal, bounded length, normalized case.
    Rejects with INVALID_TARGET like every other scope type.
    """
    v = value.strip()
    if not v:
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed domain: {value!r}")
    if "://" in v:
        raise ApiError(
            ErrorCode.INVALID_TARGET,
            f"Domain must not include a URL scheme: {value!r}",
        )
    if "@" in v:
        raise ApiError(
            ErrorCode.INVALID_TARGET, "Embedded credentials in domains are not allowed"
        )
    if "*" in v:
        raise ApiError(
            ErrorCode.INVALID_TARGET,
            f"Wildcard domains are not supported: {value!r}",
        )
    if v.endswith("."):  # strip at most one trailing root dot
        v = v[:-1]
    if v.startswith("-"):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed domain: {value!r}")
    try:
        ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        raise ApiError(
            ErrorCode.INVALID_TARGET,
            f"Domain must be a DNS name, not an IP literal: {value!r}",
        )
    lowered = v.lower()
    if _IPV4_RE.match(v):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed domain: {value!r}")
    if not lowered or len(lowered) > 253 or not _HOSTNAME_RE.match(lowered):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed domain: {value!r}")
    return lowered


def is_valid_hostname_syntax(value: str) -> bool:
    """Non-raising DNS-name syntax check (Phase 4B).

    Same strictness as domain scope validation (no scheme, no userinfo,
    no wildcard, no IP literal, bounded length, RFC 1123 labels) without
    raising: returns False for anything else, including non-strings.
    Used by the subdomain promotion policy to filter untrusted
    discovery names; authorization itself stays in validate_scope /
    target_in_scope / SafetyValidator.
    """
    if not isinstance(value, str):
        return False
    try:
        _validate_domain(value)
    except ApiError:
        return False
    return True


def _validate_cidr(value: str) -> str:
    """Validate + canonicalize a CIDR entry (host bits folded in)."""
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise ApiError(ErrorCode.INVALID_TARGET, f"Invalid CIDR: {value!r}") from None


def _validate_url(value: str) -> str:
    """Validate an http/https URL; the value is kept as provided.

    Matching later reduces both sides to host form (Policy.normalize_target).
    """
    v = value.strip()
    parsed = urlparse(v)
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ApiError(
            ErrorCode.INVALID_TARGET,
            f"Unsupported URL scheme in {value!r}; use http or https",
        )
    if parsed.username or parsed.password:
        raise ApiError(
            ErrorCode.INVALID_TARGET, "Embedded credentials in URLs are not allowed"
        )
    host = parsed.hostname
    if host is None:
        raise ApiError(ErrorCode.INVALID_TARGET, f"Malformed URL: {value!r}")
    try:
        port = parsed.port
    except ValueError:
        raise ApiError(ErrorCode.INVALID_TARGET, f"Invalid port in URL: {value!r}") from None
    if port is not None and not (1 <= port <= 65535):
        raise ApiError(ErrorCode.INVALID_TARGET, f"Invalid port in URL: {value!r}")
    _validate_hostname(host)  # host part must be a valid hostname/IP
    return v


def validate_scope(entries: list[ScopeEntry]) -> list[dict[str, Any]]:
    """Validate + canonicalize scope entries for persistence.

    Raises ApiError(INVALID_TARGET) on the first malformed entry.
    """
    out: list[dict[str, Any]] = []
    for entry in entries:
        if entry.type == "host":
            value = _validate_hostname(entry.value)
        elif entry.type == "cidr":
            value = _validate_cidr(entry.value)
        elif entry.type == "url":
            value = _validate_url(entry.value)
        elif entry.type == "domain":
            value = _validate_domain(entry.value)
        else:
            raise ApiError(ErrorCode.INVALID_TARGET, f"Unsupported scope type: {entry.type!r}")
        out.append({"type": entry.type, "value": value, "note": entry.note})
    return out


def target_in_scope(snapshot: list[dict[str, Any]], target: str) -> bool:
    """True when target is inside the snapshot's authorized scope.

    Host/URL/domain entries match by EXACT host-normalized comparison;
    CIDR entries match by subnet membership. Empty snapshot authorizes
    nothing.

    Phase 4A invariant: a ``domain`` entry authorizes ONLY the exact
    domain itself. ``sub.example.com`` is NOT in scope when the snapshot
    holds ``{"type": "domain", "value": "example.com"}`` - discovered
    subdomains stay unauthorized until an explicit promotion rule (a
    future Subfinder/DNSX phase) authorizes them.
    """
    normalized = Policy.normalize_target(target)
    if normalized is None:
        return False
    for entry in snapshot:
        etype = entry.get("type")
        value = str(entry.get("value", ""))
        if etype == "cidr":
            try:
                if ipaddress.ip_address(normalized) in ipaddress.ip_network(
                    value, strict=False
                ):
                    return True
            except ValueError:
                continue
        elif etype in ("host", "url", "domain"):
            if Policy.normalize_target(value) == normalized:
                return True
    return False
