"""Security tests: Phase 3 scan execution security invariants.

Covers the required security matrix (malformed targets, flag injection,
shell injection, redirect/discovered-target protection) plus the
standing invariants: no shell=True anywhere in the backend, argv stays
structured, the SafetyValidator chain stays fail-closed.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.tools.mocks import MockPortScan
from agent_core.tools.nmap import NmapParams, build_nmap_argv
from agent_core.tools.registry import ToolRegistry
from backend.services.scope_resolution import resolve_scope
from backend.services.tool_runner import make_cancelling_runner

# --- Test 8: malformed targets -> REJECT ----------------------------------
# NOTE: "/" is deliberately ABSENT from this list: the frozen agent_core
# NmapParams intentionally allows it (harmless - nmap fails to resolve
# such a string; the pipeline only ever constructs snapshot-derived
# targets, which never contain "/").
@pytest.mark.parametrize(
    "bad",
    ["", " ", "-target", "--verbose", "ta rget", "target;id", "a" * 254],
)
def test_malformed_targets_rejected(bad):
    with pytest.raises(ValidationError):
        NmapParams(target=bad)


# --- Test 9: flag injection -> REJECT --------------------------------------
@pytest.mark.parametrize(
    "flag",
    ["--script", "-oN", "--data", "-c", "-iL", "--excludefile", "-oG"],
)
def test_flag_injection_rejected(flag):
    """A target that looks like an nmap flag must never reach argv."""
    with pytest.raises(ValidationError):
        NmapParams(target=flag)


# --- Test 10: shell injection -> REJECT ------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        "host;id",
        "host&&id",
        "host|id",
        "host$(id)",
        "host`id`",
        "host>file",
        "host<file",
        "host\nid",
        "$(whoami)",
        "`whoami`",
        "127.0.0.1;rm -rf /",
    ],
)
def test_shell_injection_rejected(payload):
    """Shell metacharacters in targets are rejected before any argv is
    built - model/user input can never become a command."""
    with pytest.raises(ValidationError):
        NmapParams(target=payload)


# --- argv invariants: structured, fixed, no shell ---------------------------
def test_argv_is_structured_and_fixed():
    params = NmapParams(target="demo.local", ports="top-1000", profile="version")
    argv = build_nmap_argv(params)
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert argv[0] == "nmap"
    assert "-oX" in argv and "-" in argv
    # the target is a separate argv element, never concatenated
    assert argv[-1] == "demo.local"
    # no intrusive profiles in Phase 3
    assert "-O" not in argv
    assert "--script" not in argv


def test_runner_never_uses_shell(monkeypatch):
    seen = {}

    class _FakePopen:
        def __init__(self, argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            self.pid = 1
            self.returncode = 0

        def poll(self):
            return 0

        def communicate(self, timeout=None):
            return ("", "")

    monkeypatch.setattr(
        __import__("backend.services.tool_runner", fromlist=["subprocess"]).subprocess,
        "Popen",
        _FakePopen,
    )
    runner = make_cancelling_runner(__import__("threading").Event())
    runner("nmap", ["-oX", "-", "demo.local"], timeout_s=5)
    assert seen["kwargs"].get("shell") is False
    assert isinstance(seen["argv"], list)


def test_no_shell_true_anywhere_in_backend():
    """Security invariant: shell=True never appears in backend code.

    ast-based: precise over comments/docstrings (several backend
    docstrings mention the invariant itself)."""
    import ast
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parents[2] / "backend"
    offenders = []
    for py_file in backend_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in ("run", "Popen", "call", "check_output", "check_call")):
                continue
            for kw in node.keywords:
                if kw.arg == "shell":
                    value = getattr(kw.value, "value", None)
                    if value is True:
                        offenders.append(f"{py_file.name}:{node.lineno}")
    assert offenders == []


# --- scope chain: out-of-scope targets fail closed --------------------------
def _validator():
    reg = ToolRegistry()
    reg.register(MockPortScan())
    reg.register(_nmap_stub())
    return SafetyValidator(reg, Policy(allowed_targets=["demo.local"], max_danger="active_scan"))


def _nmap_stub():
    from agent_core.tools.nmap import NmapTool

    return NmapTool(runner=lambda *a, **k: None)


def test_out_of_scope_target_rejected_by_validator():
    from agent_core.schemas.actions import ToolCall
    from agent_core.schemas.state import AgentState

    state = AgentState(run_id="t", goal="g")
    outcome = _validator().validate(ToolCall(tool="nmap", params={"target": "evil.example.com"}), state)
    assert not outcome.accepted


def test_discovered_ip_not_authorized_by_validator():
    """Nmap-discovered IPs are evidence, not authorization: the validator
    rejects them (the DNS bridge is the ONLY way an IP is authorized)."""
    from agent_core.schemas.actions import ToolCall
    from agent_core.schemas.state import AgentState

    state = AgentState(run_id="t", goal="g")
    outcome = _validator().validate(ToolCall(tool="nmap", params={"target": "172.18.0.3"}), state)
    assert not outcome.accepted


def test_dns_resolved_ip_authorized_through_bridge():
    """With the DNS bridge, a resolved IP of an authorized hostname passes
    the SAME validator (deterministic provenance, not scanner observation)."""
    from agent_core.schemas.actions import ToolCall
    from agent_core.schemas.state import AgentState

    snapshot = [{"type": "host", "value": "juice-shop", "note": None}]
    allowed = resolve_scope(snapshot, resolver=lambda h: ["172.18.0.3"])
    policy = Policy(allowed_targets=allowed, max_danger="active_scan")
    reg = ToolRegistry()
    reg.register(_nmap_stub())
    validator = SafetyValidator(reg, policy)
    state = AgentState(run_id="t", goal="g")
    outcome = validator.validate(
        ToolCall(tool="nmap", params={"target": "172.18.0.3"}), state
    )
    assert outcome.accepted
    # the DNS-derived IP is NOT from the snapshot itself
    assert "172.18.0.3" not in [e["value"] for e in snapshot]


def test_redirect_target_fails_closed_through_validator():
    from agent_core.schemas.actions import ToolCall
    from agent_core.schemas.state import AgentState

    snapshot = [{"type": "host", "value": "juice-shop", "note": None}]
    allowed = resolve_scope(snapshot, resolver=lambda h: ["172.18.0.3"])
    policy = Policy(allowed_targets=allowed, max_danger="active_scan")
    reg = ToolRegistry()
    reg.register(_nmap_stub())
    validator = SafetyValidator(reg, policy)
    state = AgentState(run_id="t", goal="g")
    outcome = validator.validate(
        ToolCall(tool="nmap", params={"target": "evil.example"}), state
    )
    assert not outcome.accepted
