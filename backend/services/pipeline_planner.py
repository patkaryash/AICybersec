"""Deterministic real-tool pipeline planner (Phase 3 + Phase 4C Step 5).

No model, no network, no execution: emits a fixed per-profile ToolCall
sequence, deriving each stage's targets from prior observations:

    recon: nmap -> httpx
    web:   httpx -> nuclei
    full:  nmap -> httpx -> nuclei

Target derivation (all values flow through SafetyValidator downstream):
- nmap: every snapshot host entry, one host per call, ports bounded by
  NMAP_PIPELINE_PORTS. NEVER receives promoted discovery hosts.
- httpx: http(s) URLs from nmap open ports (443 -> https, else http),
  capped; snapshot http-URL fallback when nmap yielded nothing usable;
  PLUS run-local promoted discovery hosts (Phase 4C Step 5) as
  ``http://<host>`` seeds, deduped and capped. Promoted hosts are
  hostname-only, already DNS-verified/asset-backed by discovery_service;
  this planner re-validates syntax + snapshot-descendant relationship
  and never promotes by itself.
- nuclei: httpx final URLs (2xx preferred), capped; same fallback.
  NEVER receives promoted hosts directly (only via httpx observations,
  which is the pre-existing httpx->nuclei chaining).

Only host/url scope entries drive the pipeline, except that a
domain-only snapshot with a non-empty promoted set may still run the
HTTPX stage (the Phase 4C domain -> discovery -> httpx flow). CIDR-only
with no promoted hosts still ends with an explicit Finish.

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
# Bound on run-local promoted hosts accepted by the planner (before the
# final HTTPX merge, which is itself capped at MAX_STAGE_TARGETS).
MAX_PROMOTED_HOSTS = 50

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


def _snapshot_web_seeds(snapshot: list[dict[str, Any]]) -> list[str]:
    """Explicit http(s) URLs from url scope entries, verbatim.

    URL entries are the only scope entries that carry an authoritative
    scheme/port. The web profile has no nmap stage, so without these
    seeds it would fall back to ``http://<host>`` (port 80) and miss
    services on non-standard ports entirely.
    """
    seeds: list[str] = []
    for entry in snapshot or []:
        if not isinstance(entry, dict) or entry.get("type") != "url":
            continue
        value = entry.get("value")
        if (
            isinstance(value, str)
            and value.startswith(("http://", "https://"))
            and value not in seeds
        ):
            seeds.append(value)
        if len(seeds) >= MAX_STAGE_TARGETS:
            break
    return seeds


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


def sanitize_promoted_hosts(hosts: object, snapshot: object = None) -> list[str]:
    """Deterministic hostname-only filter for a run-local promoted set.

    Defense in depth behind discovery_service (which already guarantees
    DNS-verified, asset-backed, descendant-validated hostnames): drop
    anything that is not a valid DNS hostname, not a label-boundary
    descendant of a snapshot parent, or an exact duplicate. IPs, URLs,
    wildcards, CNAME/redirect-style values, and scanner blobs never
    survive. Sorted output; capped at MAX_PROMOTED_HOSTS.

    The planner itself never promotes: with ``snapshot=None`` only
    syntax is checked; with a snapshot the descendant gate also
    applies. Neither branch touches Project.scope, Scan.target_snapshot,
    or any Policy.
    """
    from backend.services.subdomain_policy import is_within_domain, normalize_hostname

    if not isinstance(hosts, (list, tuple)):
        return []
    parents: list[str] | None = None
    if isinstance(snapshot, list):
        from backend.services.subdomain_policy import snapshot_parents

        parents = snapshot_parents(snapshot)
        if not parents:
            # Snapshot with no name-shaped parents (e.g. CIDR-only):
            # nothing can be a valid descendant -> fail closed.
            return []
    out: list[str] = []
    seen: set[str] = set()
    for item in hosts:
        name = normalize_hostname(item)
        if name is None or name in seen:
            continue
        if parents is not None and not any(is_within_domain(name, p) for p in parents):
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= MAX_PROMOTED_HOSTS:
            break
    return sorted(out)


def _promoted_web_urls(promoted_hosts: list[str]) -> list[str]:
    """Run-local promoted hostnames as HTTPX seed URLs (``http://``)."""
    return [f"http://{h}" for h in promoted_hosts or []]


def _merge_httpx_targets(base: list[str], promoted_urls: list[str]) -> list[str]:
    """Original targets first, then promoted; exact-dedup, capped."""
    merged: list[str] = []
    seen: set[str] = set()
    for url in list(base or []) + list(promoted_urls or []):
        if not isinstance(url, str) or not url or url in seen:
            continue
        seen.add(url)
        merged.append(url)
        if len(merged) >= MAX_STAGE_TARGETS:
            break
    return merged


class PipelinePlanner:
    """Fixed real-tool pipeline; implements the Planner protocol."""

    def __init__(
        self,
        profile: str,
        snapshot: list[dict[str, Any]],
        max_steps: int = 12,
        discovered_hosts: object = None,
    ) -> None:
        self.profile = profile if profile in _PROFILE_STAGES else "full"
        self.snapshot = list(snapshot or [])
        self.hosts = _snapshot_hosts(self.snapshot)
        # Run-local promoted set for the HTTPX stage ONLY. Sanitized here
        # (syntax + snapshot-descendant); never persisted, never used for
        # nmap/nuclei targeting. Empty by default (backward compatible).
        self.discovered_hosts = sanitize_promoted_hosts(discovered_hosts, self.snapshot)
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
            # Promoted discovery hosts NEVER enter nmap (Step 5 scope).
            return list(self.hosts)
        if tool == "httpx":
            base = (
                _nmap_http_urls(state.observations)
                or _snapshot_web_seeds(self.snapshot)
                or [f"http://{h}" for h in self.hosts]
            )
            if not base and not self.discovered_hosts:
                return []
            return _merge_httpx_targets(base, _promoted_web_urls(self.discovered_hosts))
        if tool == "nuclei":
            # Promoted hosts NEVER enter nuclei directly; only via httpx
            # observations through the pre-existing httpx->nuclei chaining.
            return (
                _httpx_urls(state.observations)
                or _snapshot_web_seeds(self.snapshot)
                or [f"http://{h}" for h in self.hosts]
            )
        return []

    def decide(self, state: AgentState) -> Decision:
        if not self.hosts and not self.discovered_hosts:
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
