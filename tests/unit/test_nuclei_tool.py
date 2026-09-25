"""Unit tests: NucleiTool (mocked runner, no binary/network)."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.nuclei import NucleiParams, NucleiTool, build_nuclei_argv
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

LINE = json.dumps({
    "template-id": "CVE-2021-44228",
    "template": "http/cves/2021/CVE-2021-44228.yaml",
    "info": {"name": "Apache Log4j RCE", "severity": "critical",
             "description": "RCE.", "reference": ["https://example.com/cve"]},
    "type": "http", "host": "https://demo.local",
    "matched-at": "https://demo.local/login", "ip": "10.0.0.5",
    "matcher-name": "status",
})


def _ctx(targets=("demo.local",)):
    return ToolContext(run_id="t", allowed_targets=list(targets), timeout_s=5)


def test_exact_argv_profile():
    argv = build_nuclei_argv(NucleiParams(targets=["https://demo.local", "https://demo.local:8443"]))
    assert argv[:4] == ["nuclei", "-jsonl", "-silent", "-nc"]
    assert argv[4:6] == ["-severity", "critical,high,medium"]
    assert argv[6:8] == ["-tags", "cve,misconfiguration,exposure,default-login"]
    for flag, value in (("-rate-limit", "150"), ("-bulk-size", "25"), ("-concurrency", "25"),
                      ("-timeout", "10"), ("-retries", "1")):
        assert flag in argv and value in argv
    assert "-omit-raw" in argv
    # -ni disables interactsh callbacks (lab diagnosis: their waits pushed
    # full runs past the tool timeout).
    assert "-ni" in argv
    assert argv[-4:] == ["-target", "https://demo.local", "-target", "https://demo.local:8443"]
    assert "-u" not in argv and "-oX" not in argv
    assert NucleiTool.danger_level == "active_scan"


def test_params_reject_injection():
    with pytest.raises(ValidationError):
        NucleiParams(targets=[])
    with pytest.raises(ValidationError):
        NucleiParams(targets=["-severity high"])
    with pytest.raises(ValidationError):
        NucleiParams(targets=["a; nuclei -h"])
    with pytest.raises(ValidationError):
        NucleiParams(targets=["a|b"])
    with pytest.raises(ValidationError):
        NucleiParams(targets=["https://demo.local"] * 21)
    with pytest.raises(ValidationError):
        NucleiParams(targets=["https://demo.local"], tags="cve")  # type: ignore[call-arg]


def _runner_ok(exe, args, timeout_s, spill_dir=None):
    assert exe == "nuclei" and "-jsonl" in args and "-omit-raw" in args
    vals = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-target"]
    assert vals == ["https://demo.local"]
    return SubprocessResult(stdout=LINE, stderr="", returncode=0)


def test_success_mapping():
    tool = NucleiTool(runner=_runner_ok)
    res = tool.execute(NucleiParams(targets=["https://demo.local"]), _ctx())
    assert res.status == "ok"
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.tool == "nuclei" and f.title == "Apache Log4j RCE"
    assert f.severity == "critical" and f.target == "https://demo.local/login"
    assert res.data["findings_count"] == 1
    assert res.data["findings"][0]["id"] == f.id
    assert "1 finding" in res.summary
    assert "nuclei" not in res.data.get("raw", "")  # no raw dump key


def test_empty_output_is_clean_not_error():
    tool = NucleiTool(runner=lambda *a, **k: SubprocessResult("", "", 0))
    res = tool.execute(NucleiParams(targets=["https://demo.local"]), _ctx())
    assert res.status == "ok" and res.findings == [] and res.data["findings_count"] == 0


def test_tool_errors_no_fabrication():
    err = NucleiTool(runner=lambda *a, **k: SubprocessResult("", "boom", 1))
    r = err.execute(NucleiParams(targets=["https://demo.local"]), _ctx())
    assert r.status == "error" and r.findings == []
    to = NucleiTool(runner=lambda *a, **k: SubprocessResult("", "", -1, timed_out=True))
    assert to.execute(NucleiParams(targets=["https://demo.local"]), _ctx()).status == "timeout"
    bad = NucleiTool(runner=lambda *a, **k: SubprocessResult("garbage", "", 0))
    r2 = bad.execute(NucleiParams(targets=["https://demo.local"]), _ctx())
    assert r2.status == "error" and r2.findings == []


def test_safety_rejects_before_runner():
    reg = ToolRegistry()
    calls: list = []

    def spy(exe, args, timeout_s, spill_dir=None):
        calls.append(args)
        return SubprocessResult(stdout=LINE, stderr="", returncode=0)

    reg.register(NucleiTool(runner=spy))
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    v = SafetyValidator(reg, policy)
    state = AgentState(run_id="t", goal="g", max_steps=6)
    assert v.validate(ToolCall(tool="nuclei", params={"targets": ["https://demo.local"]}), state).accepted
    bad = v.validate(ToolCall(tool="nuclei", params={"targets": ["https://evil.example.com"]}), state)
    assert not bad.accepted and "evil.example.com" in bad.reason
    mixed = v.validate(
        ToolCall(tool="nuclei", params={"targets": ["https://demo.local", "https://evil.example.com"]}), state
    )
    assert not mixed.accepted
    assert calls == []
    tool = NucleiTool(runner=spy)
    r = tool.execute(NucleiParams(targets=["https://demo.local", "https://evil.example.com"]), _ctx())
    assert r.status == "error" and r.findings == []
    assert calls == []
