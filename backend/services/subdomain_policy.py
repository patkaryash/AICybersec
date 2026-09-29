"""Subdomain promotion policy (Phase 4B).

Answers ONE question about untrusted discovery names:

    is this hostname a legitimate descendant of an authorized domain?

Fundamental rule: DISCOVERY IS NOT AUTHORIZATION. A name returned by
Subfinder (or any future source) never widens ``Project.scope``,
``Scan.target_snapshot``, or the SafetyValidator allowlist. This module
only decides which discovered names are ELIGIBLE to be recorded as
``subdomain`` assets (DATA) under an already-authorized domain.

Label-aware comparison (never naive ``endswith``):
    parent = "example.com"
    "example.com"          -> True  (the root itself)
    "api.example.com"      -> True  (proper descendant, dot boundary)
    "evil-example.com"     -> False (no dot boundary before parent)
    "example.com.evil.com" -> False (parent is not the rightmost labels)

Normalization: case-insensitive, one trailing root dot stripped,
strict hostname syntax (delegates to scope_service, so scope and
promotion can never disagree on what a valid name looks like).
"""
from __future__ import annotations

from agent_core.safety.policy import Policy

from backend.services.scope_service import is_valid_hostname_syntax


def normalize_hostname(value: object) -> str | None:
    """Canonicalize a candidate hostname; None when invalid.

    Accepts any input type (untrusted data); returns the lowercase,
    trailing-dot-stripped DNS name, or None for URL forms, wildcards,
    userinfo, IP literals, overlong or otherwise malformed names.
    Validity itself is delegated to scope_service so promotion policy
    and scope validation can never disagree.
    """
    if not isinstance(value, str):
        return None
    if not is_valid_hostname_syntax(value):
        return None
    normalized = value.strip()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    return normalized.lower()


def is_within_domain(candidate: object, domain: object) -> bool:
    """True when the normalized candidate is the domain itself or a
    proper label-boundary descendant of the normalized domain."""
    child = normalize_hostname(candidate)
    parent = normalize_hostname(domain)
    if child is None or parent is None:
        return False
    if child == parent:
        return True
    return child.endswith("." + parent)


def filter_descendants(candidates: object, domain: object) -> list[str]:
    """Normalized valid descendants of ``domain`` (order-preserving,
    deduplicated). The domain itself is EXCLUDED (it is the root asset,
    not a discovery). Invalid names never appear in the output."""
    parent = normalize_hostname(domain)
    if parent is None or not isinstance(candidates, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        name = normalize_hostname(candidate)
        if (
            name is None
            or name == parent
            or name in seen
            or not name.endswith("." + parent)
        ):
            continue
        seen.add(name)
        out.append(name)
    return out


def snapshot_parents(snapshot: object) -> list[str]:
    """Authorized name-shaped scope values from a scan/project snapshot.

    ``host`` and ``domain`` entries contribute their normalized value;
    ``url`` entries contribute their host form (same reduction the
    SafetyValidator uses). CIDR entries never contribute (networks are
    not names). Malformed values contribute nothing - fail closed.
    Order-preserving, deduplicated.
    """
    out: list[str] = []
    if not isinstance(snapshot, list):
        return out
    for entry in snapshot:
        if not isinstance(entry, dict):
            continue
        etype = entry.get("type")
        value = entry.get("value")
        if etype in ("host", "domain"):
            name = normalize_hostname(value)
        elif etype == "url":
            host = Policy.normalize_target(value) if isinstance(value, str) else None
            name = normalize_hostname(host)
        else:
            continue
        if name is not None and name not in out:
            out.append(name)
    return out
