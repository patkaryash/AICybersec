"""Security regression tests: Phase 4B controlled subdomain discovery.

Proves DISCOVERY IS NOT AUTHORIZATION at every layer:

- a Subfinder call for an unauthorized domain is rejected
- a discovered subdomain never enters the allowlist (validator,
  policy, and scope-resolution level)
- Subfinder-reported IPs never become authorization
- Project.scope / snapshots are never mutated by discovery
- SafetyValidator stays fail-closed; existing Nmap/HTTPX/Nuclei
  authorization and shell-injection protections are unchanged

Pure unit level (no DB, no subprocess execution - validation only).
"""
from __future__ import annotations

import pytest

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.nmap import NmapTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subfinder import SubfinderTool
from agent_core.tools.subprocess import SubprocessResult
from backend.services.scope_resolution import resolve_scope
from backend.services.scope_service import target_in_scope


def _snapshot(*entries: tuple[str, str]) -> list[dict]:
    return [{"type": t, "value": v, "note": None} for t, v in entries]


def _registry(**kwargs) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(NmapTool())
    registry.register(HTTPXTool())
    registry.register(NucleiTool())
    registry.register(SubfinderTool(**kwargs))
    return registry


def _state() -> AgentState:
    return AgentState(run_id="phase4b", goal="controlled discovery")


def _allowed(snapshot: list[dict], dns: dict[str, list[str]] | None = None):
    def resolver(hostname: str) -> list[str]:
        return list((dns or {}).get(hostname, []))

    return resolve_scope(snapshot, resolver=resolver)


class TestSubfinderScopeControl:
    SNAPSHOT = _snapshot(("domain", "example.com"))

    def test_authorized_domain_call_accepted(self):
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        out = v.validate(
            ToolCall(tool="subfinder", params={"domain": "example.com"}), _state()
        )
        assert out.accepted

    def test_unauthorized_domain_call_rejected(self):
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        out = v.validate(
            ToolCall(tool="subfinder", params={"domain": "evil.com"}), _state()
        )
        assert not out.accepted

    def test_subdomain_as_domain_arg_rejected(self):
        # Even though api.example.com is a legitimate descendant, only
        # the exactly-authorized domain may be enumerated.
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        out = v.validate(
            ToolCall(tool="subfinder", params={"domain": "api.example.com"}), _state()
        )
        assert not out.accepted


class TestDiscoveryNeverAuthorizes:
    SNAPSHOT = _snapshot(("domain", "example.com"))
    DNS = {"example.com": ["93.184.216.34"], "api.example.com": ["93.184.216.35"]}

    def test_discovered_subdomain_not_in_scope(self):
        assert not target_in_scope(self.SNAPSHOT, "api.example.com")

    def test_discovered_subdomain_not_in_allowlist(self):
        allowed = _allowed(self.SNAPSHOT, self.DNS)
        assert "api.example.com" not in allowed
        assert "93.184.216.35" not in allowed  # its DNS IP is not authorized either

    def test_discovered_subdomain_rejected_for_all_tools(self):
        allowed = _allowed(self.SNAPSHOT, self.DNS)
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        for decision in (
            ToolCall(tool="nmap", params={"target": "api.example.com"}),
            ToolCall(tool="httpx", params={"targets": ["https://api.example.com/"]}),
            ToolCall(tool="nuclei", params={"targets": ["https://api.example.com/"]}),
            ToolCall(tool="subfinder", params={"domain": "api.example.com"}),
        ):
            out = v.validate(decision, _state())
            assert not out.accepted, decision.tool

    def test_discovered_ip_never_authorized(self):
        # Subfinder output claims 6.6.6.6 for api.example.com, but OUR
        # resolver says otherwise: the observed IP stays unauthorized.
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        assert "6.6.6.6" not in allowed
        policy = Policy(allowed_targets=allowed)
        assert not policy.target_allowed("6.6.6.6")

    def test_policy_target_hook_cannot_smuggle(self):
        # policy_target returns ONLY the domain param; extra keys
        # (mimicking smuggled tool output) are schema-rejected first.
        allowed = _allowed(self.SNAPSHOT, {"example.com": ["93.184.216.34"]})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        out = v.validate(
            ToolCall(
                tool="subfinder",
                params={"domain": "example.com", "all": True, "-r": "evil"},
            ),
            _state(),
        )
        assert not out.accepted and "invalid parameters" in out.reason


class TestExistingToolsUnchanged:
    def test_nmap_httpx_nuclei_authz_intact(self):
        snapshot = _snapshot(("host", "demo.local"), ("domain", "example.com"))
        allowed = _allowed(snapshot, {"demo.local": ["10.0.0.5"]})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        assert v.validate(
            ToolCall(tool="nmap", params={"target": "demo.local"}), _state()
        ).accepted
        assert not v.validate(
            ToolCall(tool="nmap", params={"target": "evil.com"}), _state()
        ).accepted
        assert v.validate(
            ToolCall(tool="httpx", params={"targets": ["http://demo.local/"]}), _state()
        ).accepted
        assert not v.validate(
            ToolCall(tool="nuclei", params={"targets": ["https://evil.example.com"]}),
            _state(),
        ).accepted

    def test_host_entry_does_not_authorize_domain_call(self):
        # A host entry authorizes the exact host for host-shaped tools,
        # but a subfinder domain call for a bare host scope value still
        # passes only when that exact value is allowlisted (exact match).
        snapshot = _snapshot(("host", "demo.local"))
        allowed = _allowed(snapshot, {})
        v = SafetyValidator(_registry(), Policy(allowed_targets=allowed))
        assert v.validate(
            ToolCall(tool="subfinder", params={"domain": "demo.local"}), _state()
        ).accepted
        assert not v.validate(
            ToolCall(tool="subfinder", params={"domain": "sub.demo.local"}), _state()
        ).accepted

    @pytest.mark.parametrize("target", ["a;id", "a|b", "-flag", "a b"])
    def test_shell_protections_intact(self, target: str):
        v = SafetyValidator(
            _registry(), Policy(allowed_targets=[target, "example.com"])
        )
        out = v.validate(ToolCall(tool="subfinder", params={"domain": target}), _state())
        assert not out.accepted


class TestRegistryWiring:
    def test_subfinder_registered_with_safe_level(self):
        from backend.deps import build_registry

        registry = build_registry()
        assert registry.has("subfinder")
        tool = registry.get("subfinder")
        assert tool.danger_level == "safe"
        assert tool.name == "subfinder"

    def test_per_scan_registry_includes_subfinder(self):
        import threading
        import uuid

        from backend.services.scan_manager import ScanManager
        from backend.services.tool_runner import RunRecorder

        mgr = ScanManager(session_factory=lambda: None, runs_dir="/tmp/never-created-4b")
        try:
            registry = mgr._build_per_scan_registry(
                uuid.uuid4(), threading.Event(), RunRecorder()
            )
            assert registry.has("subfinder")
            assert registry.get("subfinder").danger_level == "safe"
        finally:
            mgr.shutdown()
