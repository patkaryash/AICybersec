"""M3-B: deterministic end-to-end planner-driven loop (mock only).

Proves the architecture executes a multi-step AI-driven workflow with
ModelPlanner + MockModelProvider (no real LLM, no network, no binaries):

    ModelPlanner -> SafetyValidator -> Nmap -> Observation
    -> ModelPlanner -> SafetyValidator -> HTTPX -> Observation
    -> ModelPlanner -> SafetyValidator -> Nuclei -> Observation
    -> ModelPlanner -> Finish
"""
from __future__ import annotations

import json

from agent_core.planner import ModelPlanner
from agent_core.providers.mock import MockModelProvider
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.nmap import NmapTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="demo.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.24" method="probed" conf="10"/></port>
</ports></host></nmaprun>"""

HTTPX_LINE = json.dumps({
    "url": "http://demo.local", "input": "http://demo.local",
    "status_code": 200, "title": "Welcome", "webserver": "nginx",
    "tech": ["nginx"], "host_ip": "10.0.0.5",
})

NUCLEI_LINE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Apache Log4j RCE", "severity": "critical"},
    "matched-at": "https://demo.local/login",
    "host": "https://demo.local",
})

CHAIN_RESPONSES = [
    '{"kind": "tool_call", "tool": "nmap", "params": {"target": "demo.local"}, '
    '"reasoning": "Map open ports first."}',
    '{"kind": "tool_call", "tool": "httpx", "params": {"targets": ["http://demo.local"]}, '
    '"reasoning": "Enumerate the HTTP surface on the open ports."}',
    '{"kind": "tool_call", "tool": "nuclei", "params": {"targets": ["https://demo.local"]}, '
    '"reasoning": "Check the web surface for known vulnerabilities."}',
    '{"kind": "finish", "summary": "Deterministic security assessment completed."}',
]


def _build(tmp_path, responses, max_steps=8):
    calls: dict[str, list] = {"nmap": [], "httpx": [], "nuclei": []}

    def nmap_runner(exe, args, timeout_s, spill_dir=None):
        calls["nmap"].append(args)
        return SubprocessResult(stdout=NMAP_XML, stderr="", returncode=0)

    def httpx_runner(exe, args, timeout_s, spill_dir=None):
        calls["httpx"].append(args)
        return SubprocessResult(stdout=HTTPX_LINE, stderr="", returncode=0)

    def nuclei_runner(exe, args, timeout_s, spill_dir=None):
        calls["nuclei"].append(args)
        return SubprocessResult(stdout=NUCLEI_LINE, stderr="", returncode=0)

    registry = ToolRegistry()
    registry.register(NmapTool(runner=nmap_runner))
    registry.register(HTTPXTool(runner=httpx_runner))
    registry.register(NucleiTool(runner=nuclei_runner))
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=max_steps)
    sink = InMemorySink()
    planner = ModelPlanner(
        MockModelProvider(list(responses)), registry, allowed_targets=["demo.local"]
    )
    runtime = AgentRuntime(
        planner=planner,
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[sink],
        policy=policy,
    )
    return runtime, sink, calls


def test_full_deterministic_chain(tmp_path):
    """A: nmap -> httpx -> nuclei -> Finish, exact sequence asserted."""
    runtime, sink, calls = _build(tmp_path, CHAIN_RESPONSES)
    state = runtime.run("Assess demo.local")

    assert state.status == "finished"
    assert state.step == 4

    # Exact decision/tool sequence, then Finish.
    tools = [obs.tool for obs in state.observations]
    assert tools == ["nmap", "httpx", "nuclei"]
    assert all(obs.source == "tool" and obs.ok for obs in state.observations)

    # Each observation carries its tool's normalized result.
    assert state.observations[0].data["hosts"][0]["ports"][0]["port"] == 80
    assert state.observations[1].data["services"][0]["status_code"] == 200
    assert state.observations[1].data["services"][0]["tech"] == ["nginx"]
    assert len(state.findings) == 1
    assert state.findings[0].tool == "nuclei"
    assert state.findings[0].severity == "critical"

    # Every tool executed exactly once through the controlled runner.
    assert len(calls["nmap"]) == 1
    assert len(calls["httpx"]) == 1
    assert len(calls["nuclei"]) == 1

    # Trajectory shows the full decision -> observation progression.
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 4
    assert [e["decision_raw"].get("tool") for e in traj[:3]] == ["nmap", "httpx", "nuclei"]
    assert traj[3]["decision_validated"]["kind"] == "finish"
    assert traj[0]["observation"]["tool"] == "nmap"
    assert traj[2]["observation"]["findings"][0]["tool"] == "nuclei"
    dumped = json.dumps(traj)
    assert "<nmaprun" not in dumped and "template-id" not in dumped

    # Events in lifecycle order, single terminal event.
    types = [e["type"] for e in sink.events]
    assert types[0] == "run.started" and types[-1] == "run.finished"
    assert types.count("tool.started") == 3
    assert "finding.recorded" in types


def test_planner_cannot_bypass_safety(tmp_path):
    """B: MODEL OUTPUT != AUTHORIZATION at full-loop level."""
    runtime, _, calls = _build(tmp_path, [
        '{"kind": "tool_call", "tool": "nuclei", "params": {"targets": ["https://evil.example"]}}',
        '{"kind": "finish", "summary": "Nothing authorized."}',
    ])
    state = runtime.run("Probe evil")
    assert state.status == "finished"
    assert state.observations[0].source == "rejected"
    assert "allowed targets" in state.observations[0].reason
    assert calls == {"nmap": [], "httpx": [], "nuclei": []}  # no runner invoked
    assert state.findings == []


def test_max_steps_still_protects(tmp_path):
    """C: planner that never finishes is stopped by existing max_steps."""
    runtime, _, _ = _build(
        tmp_path,
        ['{"kind": "tool_call", "tool": "nmap", "params": {"target": "demo.local"}}'] * 10,
        max_steps=3,
    )
    state = runtime.run("Loop forever")
    assert state.status == "failed"
    assert "max_steps" in state.error
    assert state.step == 3
