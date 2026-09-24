"""Unit tests: HTTPXTool (mocked runner, no binary/network)."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.httpx import HTTPXParams, HTTPXTool, build_httpx_argv
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

LINE1 = json.dumps({
    "url": "https://demo.local/login", "input": "https://demo.local",
    "status_code": 200, "title": "Login", "webserver": "nginx",
    "tech": ["nginx", "React"], "host_ip": "10.0.0.5",
})
LINE2 = json.dumps({
    "url": "https://demo.local:8443", "input": "https://demo.local:8443",
    "status_code": 403, "title": "Forbidden",
})


def _ctx(targets=("demo.local",)):
    return ToolContext(run_id="t", allowed_targets=list(targets), timeout_s=5)


def test_exact_argv_no_shell():
    argv = build_httpx_argv(HTTPXParams(targets=["https://demo.local", "https://demo.local:8443"]))
    assert argv[:5] == ["httpx", "-json", "-silent", "-nc", "-sc"]
    for flag in ("-cl", "-ct", "-title", "-server", "-method", "-td", "-ip",
                 "-cname", "-cdn", "-tls-probe", "-follow-redirects"):
        assert flag in argv
    assert argv[-4:] == ["-u", "https://demo.local", "-u", "https://demo.local:8443"]
    assert "-oX" not in argv and "|" not in " ".join(argv)


def test_params_reject_injection():
    with pytest.raises(ValidationError):
        HTTPXParams(targets=[])
    with pytest.raises(ValidationError):
        HTTPXParams(targets=["-json"])
    with pytest.raises(ValidationError):
        HTTPXParams(targets=["a; rm -rf /"])
    with pytest.raises(ValidationError):
        HTTPXParams(targets=["a|b"])
    with pytest.raises(ValidationError):
        HTTPXParams(targets=["https://demo.local"] * 21)
    with pytest.raises(ValidationError):
        HTTPXParams(targets=["https://demo.local"], extra_flag="x")  # type: ignore[call-arg]


def _runner_ok(exe, args, timeout_s, spill_dir=None):
    assert exe == "httpx" and "-json" in args
    # every target travels as the value after a -u element
    u_vals = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-u"]
    assert u_vals == ["https://demo.local", "https://demo.local:8443"]
    return SubprocessResult(stdout=LINE1 + "\n" + LINE2, stderr="", returncode=0)


def test_tool_success():
    tool = HTTPXTool(runner=_runner_ok)
    res = tool.execute(HTTPXParams(targets=["https://demo.local", "https://demo.local:8443"]), _ctx())
    assert res.status == "ok" and res.findings == []
    assert len(res.data["services"]) == 2
    assert "2 HTTP service" in res.summary and "Login" in res.summary
    assert "nginx, React" in res.summary
    assert res.data["truncated"] is False


def test_tool_errors():
    err = HTTPXTool(runner=lambda *a, **k: SubprocessResult("", "boom", 1))
    assert err.execute(HTTPXParams(targets=["https://demo.local"]), _ctx()).status == "error"
    to = HTTPXTool(runner=lambda *a, **k: SubprocessResult("", "", -1, timed_out=True))
    assert to.execute(HTTPXParams(targets=["https://demo.local"]), _ctx()).status == "timeout"
    bad = HTTPXTool(runner=lambda *a, **k: SubprocessResult("garbage", "", 0))
    assert bad.execute(HTTPXParams(targets=["https://demo.local"]), _ctx()).status == "error"


def test_safety_each_target_must_pass():
    reg = ToolRegistry()
    calls: list = []

    def spy(exe, args, timeout_s, spill_dir=None):
        calls.append(args)
        return SubprocessResult(stdout=LINE1, stderr="", returncode=0)

    reg.register(HTTPXTool(runner=spy))
    policy = Policy(allowed_targets=["demo.local"], max_danger="safe", max_steps=6)
    v = SafetyValidator(reg, policy)
    state = AgentState(run_id="t", goal="g", max_steps=6)

    ok = v.validate(ToolCall(tool="httpx", params={"targets": ["https://demo.local"]}), state)
    assert ok.accepted
    mixed = v.validate(
        ToolCall(tool="httpx", params={"targets": ["https://demo.local", "https://evil.example.com"]}), state
    )
    assert not mixed.accepted and "evil.example.com" in mixed.reason
    assert calls == []  # rejected before any subprocess call

    # tool-level defense in depth
    tool = HTTPXTool(runner=spy)
    res = tool.execute(HTTPXParams(targets=["https://demo.local", "https://evil.example.com"]), _ctx())
    assert res.status == "error" and "allowed targets" in res.summary
    assert calls == []
