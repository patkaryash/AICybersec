"""Security regression tests: Phase 4A foundation invariants.

Proves the attack-surface foundation changes NOTHING about
authorization (all data paths stay fail-closed):

A. a discovered subdomain does not automatically become authorized
B. DNS enrichment does not automatically expand authorization
C. a redirect to another host does not become authorized
D. existing host/CIDR/URL scope behavior remains intact
E. SafetyValidator remains fail-closed
F. shell-injection / argument-validation protections remain intact

Pure unit level (no DB, no subprocess execution - validation only).
"""
from __future__ import annotations

import pytest

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.nmap import NmapTool
from agent_core.tools.registry import ToolRegistry
from backend.services.scope_resolution import resolve_scope
from backend.services.scope_service import target_in_scope


def _snapshot(*entries: tuple[str, str]) -> list[dict]:
    return [{"type": t, "value": v, "note": None} for t, v in entries]


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(NmapTool())
    registry.register(HTTPXTool())
    registry.register(NucleiTool())
    return registry


def _state() -> AgentState:
    return AgentState(run_id="phase4a", goal="foundation invariants")


def _allowed(snapshot: list[dict], dns: dict[str, list[str]] | None = None):
    def resolver(hostname: str) -> list[str]:
        return list((dns or {}).get(hostname, []))

    return resolve_scope(snapshot, resolver=resolver)


# --- A: discovered subdomains stay unauthorized ----------------------------


class TestDiscoveredSubdomainNotAuthorized:
    SNAPSHOT = _snapshot(("domain", "example.com"))

    def test_subdomain_not_in_scope(self):
        assert not target_in_scope(self.SNAPSHOT, "sub.example.com")
        assert not target_in_scope(self.SNAPSHOT, "http://api.example.com/x")

    def test_subdomain_not_in_resolved_allowlist(self):
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        assert "sub.example.com" not in allowed
        assert "93.184.216.34" in allowed  # the domain's own DNS IP is fine

    def test_validator_rejects_subdomain_tool_call(self):
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        validator = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": "sub.example.com"}), _state()
        )
        assert not outcome.accepted
        assert "not in the allowed targets list" in outcome.reason

    def test_validator_rejects_subdomain_url_targets(self):
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        validator = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        outcome = validator.validate(
            ToolCall(tool="httpx", params={"targets": ["https://api.example.com/app"]}),
            _state(),
        )
        assert not outcome.accepted


# --- B: DNS enrichment is data, not authorization ---------------------------


class TestDnsEnrichmentNotAuthorization:
    SNAPSHOT = _snapshot(("host", "juice-shop"))

    def test_dns_answer_for_unrelated_host_is_rejected(self):
        allowed = _allowed(self.SNAPSHOT, {"juice-shop": ["172.18.0.3"]})
        # A DNS enrichment record claiming evil.example -> 6.6.6.6 changes
        # nothing: neither name nor IP enters the allowlist.
        assert "evil.example" not in allowed
        assert "6.6.6.6" not in allowed
        policy = Policy(allowed_targets=allowed)
        assert not policy.target_allowed("evil.example")
        assert not policy.target_allowed("6.6.6.6")

    def test_scanner_observed_ip_without_dns_is_rejected(self):
        allowed = _allowed(self.SNAPSHOT, {"juice-shop": ["172.18.0.3"]})
        assert "10.0.0.50" not in allowed
        validator = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": "10.0.0.50"}), _state()
        )
        assert not outcome.accepted


# --- C: redirects stay unauthorized -----------------------------------------


class TestRedirectNotAuthorized:
    SNAPSHOT = _snapshot(("host", "juice-shop"), ("domain", "example.com"))

    def test_redirect_target_rejected_by_scope(self):
        assert not target_in_scope(self.SNAPSHOT, "evil.example")
        assert not target_in_scope(self.SNAPSHOT, "http://evil.example/login")

    def test_redirect_target_rejected_by_validator(self):
        allowed = _allowed(
            self.SNAPSHOT,
            {"juice-shop": ["172.18.0.3"], "example.com": ["93.184.216.34"]},
        )
        validator = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        outcome = validator.validate(
            ToolCall(
                tool="httpx",
                params={"targets": ["http://juice-shop/", "http://evil.example/phish"]},
            ),
            _state(),
        )
        # ONE out-of-scope entry fails the whole call (fail-closed).
        assert not outcome.accepted


# --- D: existing host/CIDR/URL behavior intact -------------------------------


class TestExistingScopeIntact:
    SNAPSHOT = _snapshot(
        ("host", "juice-shop.local"),
        ("cidr", "10.0.0.0/24"),
        ("url", "http://web.local:8080"),
    )

    def test_host_url_cidr_matches(self):
        assert target_in_scope(self.SNAPSHOT, "juice-shop.local")
        assert target_in_scope(self.SNAPSHOT, "http://juice-shop.local:3000/x")
        assert target_in_scope(self.SNAPSHOT, "10.0.0.5")
        assert target_in_scope(self.SNAPSHOT, "http://10.0.0.9:80")

    def test_out_of_scope_rejected(self):
        assert not target_in_scope(self.SNAPSHOT, "evil.example.com")
        assert not target_in_scope(self.SNAPSHOT, "10.1.0.5")

    def test_resolution_unchanged(self):
        allowed = _allowed(self.SNAPSHOT, {"juice-shop.local": ["172.18.0.3"]})
        assert "juice-shop.local" in allowed
        assert "172.18.0.3" in allowed
        assert "web.local" in allowed
        assert "10.1.0.5" not in allowed

    def test_cidr_still_skipped_in_resolution(self):
        assert _allowed([{"type": "cidr", "value": "10.0.0.0/24", "note": None}]) == []


# --- E: SafetyValidator fail-closed ------------------------------------------


class TestValidatorFailClosed:
    def test_unknown_tool_rejected(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=["a.local"]))
        outcome = validator.validate(
            ToolCall(tool="subfinder", params={"domain": "a.local"}), _state()
        )
        assert not outcome.accepted
        assert "unknown tool" in outcome.reason

    def test_extra_params_rejected(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=["a.local"]))
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": "a.local", "extra_flag": "--bad"}),
            _state(),
        )
        assert not outcome.accepted
        assert "invalid parameters" in outcome.reason

    def test_danger_cap_enforced(self):
        validator = SafetyValidator(
            _registry(), Policy(allowed_targets=["a.local"], max_danger="safe")
        )
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": "a.local"}), _state()
        )
        assert not outcome.accepted
        assert "exceeds policy cap" in outcome.reason

    def test_empty_allowlist_allows_nothing(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=[]))
        outcome = validator.validate(
            ToolCall(tool="httpx", params={"targets": ["http://a.local/"]}), _state()
        )
        assert not outcome.accepted

    def test_finish_always_accepted(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=[]))
        outcome = validator.validate(Finish(summary="done"), _state())
        assert outcome.accepted


# --- F: argument validation intact --------------------------------------------


class TestArgumentValidationIntact:
    @pytest.mark.parametrize(
        "target",
        [
            "",
            " ",
            "-target",
            "--verbose",
            "ta rget",
            "target;id",
            "target&&id",
            "target|id",
            "target$(id)",
            "target`id`",
            "a" * 254,
        ],
    )
    def test_nmap_rejects_malicious_targets(self, target: str):
        validator = SafetyValidator(
            _registry(), Policy(allowed_targets=[target, "a.local"])
        )
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": target}), _state()
        )
        assert not outcome.accepted

    def test_nmap_rejects_newline_target(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=["a.local"]))
        outcome = validator.validate(
            ToolCall(tool="nmap", params={"target": "target\nid"}), _state()
        )
        assert not outcome.accepted

    @pytest.mark.parametrize(
        "target",
        ["http://a.local/;id", "--flag", "-u", "http://a.local/x|y"],
    )
    def test_httpx_rejects_malicious_targets(self, target: str):
        validator = SafetyValidator(
            _registry(), Policy(allowed_targets=[target, "a.local"])
        )
        outcome = validator.validate(
            ToolCall(tool="httpx", params={"targets": [target]}), _state()
        )
        assert not outcome.accepted

    def test_nuclei_rejects_flag_like_target(self):
        validator = SafetyValidator(_registry(), Policy(allowed_targets=["--x"]))
        outcome = validator.validate(
            ToolCall(tool="nuclei", params={"targets": ["--x"]}), _state()
        )
        assert not outcome.accepted
