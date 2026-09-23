"""Unit tests: NmapTool (mocked runner, no nmap/network)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.nmap import NmapParams, NmapTool, build_nmap_argv
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

XML_OK = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24" method="probed" conf="10"/></port>
</ports></host></nmaprun>"""


def _ctx(targets=("demo.local",)):
    return ToolContext(run_id="t", allowed_targets=list(targets), timeout_s=5)


def _ok_runner(xml=XML_OK):
    def run(exe, args, timeout_s, spill_dir=None):
        assert exe == "nmap"
        assert "-oX" in args and "-" in args  # XML stdout enforced
        assert args[-1] not in ("-oX", "-")  # target is separate last element
        return SubprocessResult(stdout=xml, stderr="", returncode=0)

    return run


def test_argv_per_profile():
    base = ["nmap", "-sV", "--reason", "--open", "-T4", "--host-timeout", "10m", "--max-retries", "2"]
    assert build_nmap_argv(NmapParams(target="demo.local", profile="safe")) == (
        base + ["--top-ports", "1000", "-oX", "-", "demo.local"]
    )
    assert "--version-intensity" in build_nmap_argv(NmapParams(target="demo.local", profile="version"))
    assert "-O" in build_nmap_argv(NmapParams(target="demo.local", profile="os"))
    vuln = build_nmap_argv(NmapParams(target="demo.local", profile="vuln"))
    assert "--script" in vuln and "default,vuln" in vuln
    custom = build_nmap_argv(NmapParams(target="demo.local", ports="80,443", profile="safe"))
    assert "-p" in custom and "80,443" in custom


def test_params_reject_injection():
    with pytest.raises(ValidationError):
        NmapParams(target="--script vuln")
    with pytest.raises(ValidationError):
        NmapParams(target="a; rm -rf /")
    with pytest.raises(ValidationError):
        NmapParams(target="demo.local", ports="--script vuln")
    with pytest.raises(ValidationError):
        NmapParams(target="demo.local", ports="80; rm")
    with pytest.raises(ValidationError):
        NmapParams(target="demo.local", profile="evil")  # type: ignore[arg-type]
    # extra "args"/"command" fields forbidden
    with pytest.raises(ValidationError):
        NmapParams(target="demo.local", args="-sS")  # type: ignore[call-arg]


def test_tool_success_normalized():
    tool = NmapTool(runner=_ok_runner())
    res = tool.execute(NmapParams(target="demo.local"), _ctx())
    assert res.status == "ok"
    assert res.findings == []  # recon only, no manufactured vulns
    assert res.data["hosts"][0]["ip"] == "10.0.0.5"
    assert "10.0.0.5 is up" in res.summary and "80/http" in res.summary
    assert res.data["profile"] == "safe"
    assert "raw" not in res.data and "<nmaprun" not in res.summary


def test_tool_errors_become_toolresult():
    err = NmapTool(runner=lambda *a, **k: SubprocessResult("", "nope", 1))
    assert err.execute(NmapParams(target="demo.local"), _ctx()).status == "error"
    to = NmapTool(runner=lambda *a, **k: SubprocessResult("", "", -1, timed_out=True))
    assert to.execute(NmapParams(target="demo.local"), _ctx()).status == "timeout"
    bad = NmapTool(runner=lambda *a, **k: SubprocessResult("garbage", "", 0))
    assert bad.execute(NmapParams(target="demo.local"), _ctx()).status == "error"
    missing = NmapTool(runner=lambda *a, **k: SubprocessResult("", "executable not found", 127))
    assert missing.execute(NmapParams(target="demo.local"), _ctx()).status == "error"


def test_safety_rejects_before_execution():
    reg = ToolRegistry()
    calls: list = []

    def spy(exe, args, timeout_s, spill_dir=None):
        calls.append(args)
        return SubprocessResult(stdout=XML_OK, stderr="", returncode=0)

    reg.register(NmapTool(runner=spy))
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    v = SafetyValidator(reg, policy)
    state = AgentState(run_id="t", goal="g", max_steps=6)
    out = v.validate(ToolCall(tool="nmap", params={"target": "evil.example.com"}), state)
    assert not out.accepted and "allowed targets" in out.reason
    assert calls == []  # never executed
    ok = v.validate(ToolCall(tool="nmap", params={"target": "demo.local"}), state)
    assert ok.accepted


def test_tool_defense_in_depth_allowlist():
    tool = NmapTool(runner=_ok_runner())
    res = tool.execute(NmapParams(target="evil.example.com"), _ctx(("demo.local",)))
    assert res.status == "error" and "allowed targets" in res.summary
