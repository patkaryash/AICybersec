"""Unit tests: hostname -> resolved-IP scope authorization bridge.

Implements the Phase 3 security matrix (tests 1-7) with an INJECTABLE
resolver - deterministic, no real DNS required.
"""
from __future__ import annotations

from backend.services.scope_resolution import resolve_scope


def _snapshot(*entries: tuple[str, str]) -> list[dict]:
    return [{"type": t, "value": v, "note": None} for t, v in entries]


def _resolver_of(*ips: str):
    def resolve(hostname: str) -> list[str]:
        return list(ips)

    return resolve


# --- Test 1: authorized hostname -> resolved IP -> ALLOW -----------------
def test_authorized_hostname_resolved_ip_allowed():
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.3"))
    assert "juice-shop" in allowed
    assert "172.18.0.3" in allowed


# --- Test 2: unauthorized IP -> REJECT ------------------------------------
def test_unauthorized_ip_rejected():
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.3"))
    assert "172.18.0.99" not in allowed


# --- Test 3: literal authorized IP -> ALLOW (no DNS) ----------------------
def test_literal_authorized_ip_allowed():
    snapshot = _snapshot(("host", "172.18.0.3"))
    # resolver would return garbage if wrongly consulted; no DNS is used
    allowed = resolve_scope(snapshot, resolver=_resolver_of("999.999.999.999"))
    assert "172.18.0.3" in allowed
    assert "999.999.999.999" not in allowed


# --- Test 4: unrelated resolved/discovered IP -> REJECT -------------------
def test_nmap_discovered_unrelated_ip_rejected():
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.3"))
    # Nmap discovers 10.0.0.50 - discovery is evidence, NOT authorization
    assert "10.0.0.50" not in allowed


# --- Test 5: redirect target outside scope -> REJECT ----------------------
def test_redirect_outside_scope_rejected():
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.3"))
    assert "evil.example" not in allowed


# --- Test 6: Nmap observation must NOT override DNS authorization ---------
def test_nmap_observation_does_not_override_dns():
    """Regression test (Phase 3 §22): authorized juice-shop; Nmap reports
    172.18.0.3; DNS resolves juice-shop -> 172.18.0.4. Candidate
    172.18.0.3 must be REJECTED - provenance is DNS, never the scanner."""
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.4"))
    assert "juice-shop" in allowed
    assert "172.18.0.4" in allowed
    # 172.18.0.3 was only OBSERVED by Nmap - it must NOT be authorized
    assert "172.18.0.3" not in allowed


# --- Test 7: multiple DNS answers -> all authorized -----------------------
def test_multiple_dns_answers_allowed():
    snapshot = _snapshot(("host", "juice-shop"))
    allowed = resolve_scope(
        snapshot, resolver=_resolver_of("172.18.0.3", "172.18.0.4")
    )
    assert "172.18.0.4" in allowed
    assert "172.18.0.3" in allowed


# --- extra: URL entries + their hosts drive resolution --------------------
def test_url_entry_host_is_resolved():
    snapshot = _snapshot(("url", "http://juice-shop:3000"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("172.18.0.3"))
    assert "juice-shop" in allowed
    assert "172.18.0.3" in allowed


# --- extra: cidr entries are skipped (documented Phase 3 limitation) ------
def test_cidr_entries_skipped():
    snapshot = _snapshot(("cidr", "10.0.0.0/24"))
    allowed = resolve_scope(snapshot, resolver=_resolver_of("10.0.0.5"))
    assert allowed == []


# --- extra: empty snapshot authorizes nothing (fail-closed) ---------------
def test_empty_snapshot_authorizes_nothing():
    assert resolve_scope([], resolver=_resolver_of("1.2.3.4")) == []


# --- extra: real default_resolver never raises on bad input ---------------
def test_default_resolver_handles_garbage():
    from backend.services.scope_resolution import default_resolver

    assert default_resolver("not a real host!xyzzy") == []
