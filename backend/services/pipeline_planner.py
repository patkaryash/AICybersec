"""Deterministic real-tool pipeline planner (Phase 3).

No model, no network, no execution: emits a fixed per-profile ToolCall
sequence, deriving each stage's targets from prior observations:

    recon: nmap -> httpx
    web:   httpx -> nuclei
    full:  nmap -> httpx -> nuclei

Target derivation (all values flow through SafetyValidator downstream):
- nmap: every snapshot host entry, one host per call, ports bounded by
  NMAP_PIPELINE_PORTS.
- httpx: http(s) URLs from nmap open ports (443 -> https, else http),
  capped; snapshot http-URL fallback when nmap yielded nothing usable.
- nuclei: httpx final URLs (2xx preferred), capped; same fallback.

Only host/url scope entries drive the pipeline. CIDR entries cannot be
expanded safely in Phase 3 v1: a snapshot with no host/url entries ends
the run with an explicit Finish (never a silent skip, never a guess).

A stage completes on ANY observation for its tool (ok, error, or
rejected) - the planner always advances, so runs terminate. Failures
are visible as observations/trajectory, not hidden retries.
"""
from __future__ import annotations

from typing import Any

from agent_core.safety.policy import Policy
from agent_core.schemas.actions import Decision, Finish, ToolCall
from agent_core.schemas.state import AgentState

# Bounded, lab-sensible port set for pipeline nmap calls (NOT top-1000:
# the pipeline must stay within the run's step/time budget).
NMAP_PIPELINE_PORTS = "80,443,3000,8000,8080"
MAX_STAGE_TARGETS = 10
MAX_PIPELINE_HOSTS = 10

_PROFILE_STAGES: dict[str, tuple[str, ...]] = {
    "recon": ("nmap", "httpx"),
    "web": ("httpx", "nuclei"),
    "full": ("nmap", "httpx", "nuclei"),
}


def _snapshot_hosts(snapshot: list[dict[str, Any]]) -> list[str]:
    """Host-form targets from host/url scope entries (order-preserving)."""
    hosts: list[str] = []
    for entry in snapshot or []:
        if not isinstance(entry, dict) or entry.get("type") not in ("host", "url"):
            continue
        host = Policy.normalize_target(entry.get("value"))
        if host and host not in hosts:
            hosts.append(host)
        if len(hosts) >= MAX_PIPELINE_HOSTS:
            break
    return hosts


def _nmap_http_urls(observations: list[Any]) -> list[str]:
    """http(s) URLs from nmap open ports (443 -> https, else http)."""
    urls: list[str] = []
    for obs in observations or []:
        data = obs.get("data") if isinstance(obs, dict) else getattr(obs, "data", None)
        if not isinstance(data, dict):
            continue
        for host in data.get("hosts") or []:
            if not isinstance(host, dict):
                continue
            ip = host.get("ip")
            if not isinstance(ip, str) or not ip:
                continue
            for port in host.get("ports") or []:
                if not isinstance(port, dict) or port.get("state") != "open":
                    continue
                try:
                    port_no = int(port.get("port"))
                except (TypeError, ValueError):
                    continue
                scheme = "https" if port_no == 443 else "http"
                url = f"{scheme}://{ip}:{port_no}"
                if url not in urls:
                    urls.append(url)
                if len(urls) >= MAX_STAGE_TARGETS:
                    return urls
    return urls


def _httpx_urls(observations: list[Any]) -> list[str]:
    """Final URLs from httpx observations (2xx first, then the rest)."""
    ok_urls: list[str] = []
    other_urls: list[str] = []
    for obs in observations or []:
        data = obs.get("data") if isinstance(obs, dict) else getattr(obs, "data", None)
        if not isinstance(data, dict):
            continue
        for svc in data.get("services") or []:
            if not isinstance(svc, dict):
                continue
            url = svc.get("final_url") or svc.get("url")
            if not isinstance(url, str) or not url or url in ok_urls or url in other_urls:
                continue
            status = svc.get("status_code")
            if isinstance(status, int) and 200 <= status < 300:
                ok_urls.append(url)
            else:
                other_urls.append(url)
    return (ok_urls + other_urls)[:MAX_STAGE_TARGETS]


class PipelinePlanner:
    """Fixed real-tool pipeline; implements the Planner protocol."""

    def __init__(
        self,
        profile: str,
        snapshot: list[dict[str, Any]],
        max_steps: int = 12,
    ) -> None:
        self.profile = profile if profile in _PROFILE_STAGES else "full"
        self.snapshot = list(snapshot or [])
        self.hosts = _snapshot_hosts(self.snapshot)
        self.max_steps = max_steps

    def _done_tools(self, state: AgentState) -> set[str]:
        done: set[str] = set()
        for obs in state.observations or []:
            tool = obs.get("tool") if isinstance(obs, dict) else getattr(obs, "tool", None)
            if isinstance(tool, str) and tool:
                done.add(tool)
        return done

    def _nmap_pending_hosts(self, state: AgentState) -> list[str]:
        """Snapshot hosts with no nmap attempt yet.

        Coverage comes from result targets AND from proposed decisions:
        a rejected call must not be retried forever - the rejection is
        already recorded as an observation for the planner to see.
        """
        covered: set[str] = set()
        for obs in state.observations or []:
            tool = obs.get("tool") if isinstance(obs, dict) else getattr(obs, "tool", None)
            if tool != "nmap":
                continue
            data = obs.get("data") if isinstance(obs, dict) else getattr(obs, "data", None)
            target = data.get("target") if isinstance(data, dict) else None
            if isinstance(target, str) and target:
                covered.add(target.lower())
        for step in state.steps or []:
            decision = step.get("decision") if isinstance(step, dict) else getattr(step, "decision", None)
            if not isinstance(decision, dict) or decision.get("tool") != "nmap":
                continue
            params = decision.get("params")
            target = params.get("target") if isinstance(params, dict) else None
            normalized = Policy.normalize_target(target) if isinstance(target, str) else None
            if normalized:
                covered.add(normalized)
        return [h for h in self.hosts if h not in covered]

    def _stage_targets(self, tool: str, state: AgentState) -> list[str]:
        if tool == "nmap":
            return list(self.hosts)
        if tool == "httpx":
            return _nmap_http_urls(state.observations) or [f"http://{h}" for h in self.hosts]
        if tool == "nuclei":
            return _httpx_urls(state.observations) or [f"http://{h}" for h in self.hosts]
        return []

    def decide(self, state: AgentState) -> Decision:
        if not self.hosts:
            return Finish(
                summary=(
                    "Phase 3 v1 supports host/url scope entries only; "
                    "this scan's snapshot has none, so no tools were run."
                )
            )
        done = self._done_tools(state)
        pending_nmap = (
            self._nmap_pending_hosts(state) if "nmap" in _PROFILE_STAGES[self.profile] else []
        )
        remaining_stages = (
            len(pending_nmap)
            + (1 if "httpx" in _PROFILE_STAGES[self.profile] and "httpx" not in done else 0)
            + (1 if "nuclei" in _PROFILE_STAGES[self.profile] and "nuclei" not in done else 0)
        )
        if remaining_stages == 0:
            return Finish(
                summary=(
                    f"Pipeline {self.profile} complete: "
                    f"{len(state.findings)} finding(s) recorded."
                )
            )
        if state.step + remaining_stages + 1 > state.max_steps:
            return Finish(
                summary=(
                    f"Step budget reached with {remaining_stages} pipeline stage(s) "
                    f"remaining; {len(state.findings)} finding(s) recorded."
                )
            )
        if pending_nmap:
            target = pending_nmap[0]
            return ToolCall(
                tool="nmap",
                params={"target": target, "ports": NMAP_PIPELINE_PORTS, "profile": "safe"},
                reasoning=f"Pipeline {self.profile}: map open ports on {target}.",
            )
        tool = next(
            t
            for t in _PROFILE_STAGES[self.profile]
            if t != "nmap" and t not in done
        )
        targets = self._stage_targets(tool, state)
        return ToolCall(
            tool=tool,
            params={"targets": targets},
            reasoning=f"Pipeline {self.profile}: probe {len(targets)} target(s) with {tool}.",
        )
