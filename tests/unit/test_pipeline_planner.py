"""Unit tests: PipelinePlanner sequencing and target derivation (no DB)."""
from __future__ import annotations

from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.results import Observation
from agent_core.schemas.state import AgentState
from backend.services.pipeline_planner import PipelinePlanner

SNAP = [
    {"type": "host", "value": "demo.local", "note": None},
    {"type": "url", "value": "http://other.local:8080/x", "note": None},
    {"type": "cidr", "value": "10.0.0.0/24", "note": None},
]


def _state(observations=None, step=0, max_steps=12):
    return AgentState(
        run_id="t", goal="g", max_steps=max_steps, step=step,
        observations=list(observations or []),
    )


def _obs(tool, data=None, source="tool", ok=True):
    return Observation(
        step=1, source=source, tool=tool, ok=ok,
        summary="s", data=data or {}, findings=[],
    )


def test_full_profile_sequence_and_derivation():
    planner = PipelinePlanner("full", SNAP)
    assert planner.hosts == ["demo.local", "other.local"]  # cidr skipped, url reduced

    d1 = planner.decide(_state())
    assert isinstance(d1, ToolCall) and d1.tool == "nmap"
    assert d1.params["target"] == "demo.local"

    nmap_obs = _obs("nmap", data={
        "target": "demo.local",
        "hosts": [{"ip": "10.0.0.5", "ports": [
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 22, "protocol": "tcp", "state": "closed"},
            {"port": 443, "protocol": "tcp", "state": "open"},
        ]}],
    })
    d2 = planner.decide(_state([nmap_obs]))
    assert isinstance(d2, ToolCall) and d2.tool == "nmap"
    assert d2.params["target"] == "other.local"  # second host next

    both = [nmap_obs, _obs("nmap", data={"target": "other.local", "hosts": []})]
    d3 = planner.decide(_state(both))
    assert isinstance(d3, ToolCall) and d3.tool == "httpx"
    assert d3.params["targets"] == ["http://10.0.0.5:80", "https://10.0.0.5:443"]

    httpx_obs = _obs("httpx", data={"services": [
        {"url": "http://10.0.0.5:80", "final_url": "http://10.0.0.5:80",
         "status_code": 404},
        {"url": "https://10.0.0.5:443", "final_url": "https://10.0.0.5:443",
         "status_code": 200},
    ]})
    d4 = planner.decide(_state(both + [httpx_obs]))
    assert isinstance(d4, ToolCall) and d4.tool == "nuclei"
    # 2xx first
    assert d4.params["targets"][0] == "https://10.0.0.5:443"

    d5 = planner.decide(_state(both + [httpx_obs, _obs("nuclei", data={})]))
    assert isinstance(d5, Finish)


def test_recon_and_web_profiles():
    assert isinstance(PipelinePlanner("recon", SNAP).decide(_state()), ToolCall)
    d = PipelinePlanner("recon", SNAP).decide(
        _state([_obs("nmap", data={"target": "demo.local", "hosts": []}),
                _obs("nmap", data={"target": "other.local", "hosts": []}),
                _obs("httpx", data={})])
    )
    assert isinstance(d, Finish)

    web = PipelinePlanner("web", SNAP)
    d1 = web.decide(_state())
    assert isinstance(d1, ToolCall) and d1.tool == "httpx"
    # URL scope entries carry the authoritative port: used verbatim.
    assert d1.params["targets"] == ["http://other.local:8080/x"]


def test_web_profile_uses_url_scope_ports_verbatim():
    """Regression: web profile (no nmap stage) must not fall back to
    port 80 when scope URLs carry an explicit non-standard port."""
    snap = [
        {"type": "host", "value": "demo.local", "note": None},
        {"type": "url", "value": "http://juice-shop:3000", "note": None},
    ]
    d = PipelinePlanner("web", snap).decide(_state())
    assert isinstance(d, ToolCall) and d.tool == "httpx"
    assert d.params["targets"] == ["http://juice-shop:3000"]

    # nuclei, without usable httpx observations, seeds the same way.
    d2 = PipelinePlanner("web", snap).decide(_state([_obs("httpx", data={})]))
    assert isinstance(d2, ToolCall) and d2.tool == "nuclei"
    assert d2.params["targets"] == ["http://juice-shop:3000"]

    # nmap-derived URLs still win when present (full profile path).
    d3 = PipelinePlanner("web", snap).decide(
        _state([_obs("nmap", data={"hosts": [
            {"ip": "172.18.0.3", "ports": [{"port": 3000, "state": "open"}]}
        ]})])
    )
    assert isinstance(d3, ToolCall)
    assert d3.params["targets"] == ["http://172.18.0.3:3000"]


def test_unknown_profile_falls_back_to_full():
    d = PipelinePlanner("stealth", SNAP).decide(_state())
    assert isinstance(d, ToolCall) and d.tool == "nmap"


def test_cidr_only_snapshot_finishes_explicitly():
    d = PipelinePlanner("full", [{"type": "cidr", "value": "10.0.0.0/24"}]).decide(_state())
    assert isinstance(d, Finish)
    assert "host/url" in d.summary


def test_error_observation_advances_without_retry_loop():
    planner = PipelinePlanner("recon", SNAP[:1])
    # Real tool errors always carry the target in data (fail-closed
    # ToolResults), so the host is covered and the pipeline advances.
    err = _obs("nmap", data={"target": "demo.local"}, source="error", ok=False)
    d = planner.decide(_state([err]))
    assert isinstance(d, ToolCall) and d.tool == "httpx"


def test_step_budget_finishes_instead_of_overrunning():
    planner = PipelinePlanner("full", SNAP[:1])
    d = planner.decide(_state(step=11, max_steps=12))
    assert isinstance(d, Finish)
    assert "Step budget" in d.summary


def test_nmap_params_match_tool_schema():
    from agent_core.tools.nmap import NmapTool

    d = PipelinePlanner("full", SNAP[:1]).decide(_state())
    assert isinstance(d, ToolCall)
    NmapTool().validate_params(d.params)  # must not raise
