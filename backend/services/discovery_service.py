"""Deterministic Subfinder -> DNSX discovery orchestration.

This module is deliberately separate from ``AgentRuntime`` and
``ScanManager``.  It coordinates two already-registered, controlled tools,
passes every call through ``SafetyValidator``, persists through the existing
asset/enrichment helpers, and returns a run-local eligibility result.

Discovery is data, not authorization:

* ``scan.target_snapshot`` is read-only and supplies the only discovery
  parents;
* Subfinder names must pass the existing label-aware subdomain policy;
* DNSX receives only those validated names, in batches of at most 20;
* persistence records discovery/enrichment data; eligibility never changes
  scope, the caller's policy/validator, or persistent authorization;
* CNAME values and DNS IPs are observations only and are never followed or
  returned as promoted targets.

The service owns neither worker threads nor database/session lifecycle.  The
caller supplies a session, scan, registry, validator, and cancellation event.
"""
from __future__ import annotations

import copy
import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal

from sqlalchemy import func

from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.results import Observation, ToolResult
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.registry import ToolRegistry
from backend.db.models import Asset
from backend.services.result_persistence import (
    apply_dnsx_enrichment,
    persist_assets_from_observations,
)
from backend.services.subdomain_policy import is_within_domain, normalize_hostname

MAX_DNSX_TARGETS = 20
MAX_DISCOVERED_HOSTS = 500
MAX_ERROR_CHARS = 500

DiscoveryStatus = Literal["completed", "cancelled"]


@dataclass
class DiscoveryResult:
    """Bounded, deterministic output for a future ScanManager caller."""

    status: DiscoveryStatus = "completed"
    parents: list[str] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    policy_rejected: list[str] = field(default_factory=list)
    dns_verified: list[str] = field(default_factory=list)
    dns_unverified: list[str] = field(default_factory=list)
    promoted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    subfinder_calls: int = 0
    dnsx_calls: int = 0

    @property
    def cancelled(self) -> bool:
        return self.status == "cancelled"

    def finalize(self) -> "DiscoveryResult":
        """Sort and deduplicate all set-like fields for stable results."""
        for name in (
            "parents",
            "discovered",
            "policy_rejected",
            "dns_verified",
            "dns_unverified",
            "promoted",
        ):
            values = getattr(self, name)
            setattr(self, name, sorted(set(values)))
        self.errors = sorted(set(self.errors))
        return self


@dataclass
class _Invocation:
    accepted: bool
    result: ToolResult | None = None
    reason: str | None = None


PersistSubfinder = Callable[[Any, Any, Observation], int]
PersistDnsx = Callable[[Any, Any, ToolResult], int]
AssetHosts = Callable[[Any, Any, Iterable[str]], set[str]]


def _snapshot_discovery_parents(snapshot: object) -> list[str]:
    """Return normalized domain/host snapshot entries, order-preserving."""
    parents: list[str] = []
    if not isinstance(snapshot, list):
        return parents
    for entry in snapshot:
        if not isinstance(entry, dict) or entry.get("type") not in ("domain", "host"):
            continue
        name = normalize_hostname(entry.get("value"))
        if name is not None and name not in parents:
            parents.append(name)
    return parents


def _safe_text(value: object) -> str:
    """Bound a rejected candidate/error before it enters the result."""
    return str(value)[:MAX_ERROR_CHARS]


def _valid_address(value: object, version: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value.strip()).version == version
    except ValueError:
        return False


def _record_verified_host(record: object, *, allowed: set[str]) -> str | None:
    """Return a queried host with a valid A or AAAA answer, if any."""
    if not isinstance(record, dict):
        return None
    host = normalize_hostname(record.get("host"))
    if host is None or host not in allowed:
        return None
    a = record.get("a")
    aaaa = record.get("aaaa")
    has_a = isinstance(a, list) and any(_valid_address(item, 4) for item in a)
    has_aaaa = isinstance(aaaa, list) and any(_valid_address(item, 6) for item in aaaa)
    return host if has_a or has_aaaa else None


def _default_asset_hosts(session: Any, scan: Any, hosts: Iterable[str]) -> set[str]:
    """Find existing eligible asset hosts without creating or mutating rows."""
    wanted = {host for host in hosts if isinstance(host, str)}
    if not wanted:
        return set()
    rows = (
        session.query(Asset.host)
        .filter(
            Asset.scan_id == scan.id,
            Asset.asset_type.in_(("host", "subdomain", "domain")),
            func.lower(Asset.host).in_(sorted(wanted)),
        )
        .all()
    )
    return {
        normalized
        for (host,) in rows
        if (normalized := normalize_hostname(host)) is not None
    }


class DiscoveryService:
    """Run controlled, deterministic subdomain discovery for one scan.

    ``persist_subfinder``, ``persist_dnsx``, and ``asset_hosts`` are narrow
    injection points for isolated unit tests.  Production defaults use the
    existing persistence layer and SQLAlchemy asset model.

    Subfinder persistence returns rows INSERTED: zero is valid on a rerun.
    DNSX persistence returns assets ENRICHED, including idempotent merges.
    It is called per hostname so a positive count cannot mask another
    hostname's no-op. Only positive counts permit that host's promotion.
    """

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        validator: SafetyValidator,
        persist_subfinder: PersistSubfinder | None = None,
        persist_dnsx: PersistDnsx | None = None,
        asset_hosts: AssetHosts | None = None,
    ) -> None:
        self.registry = registry
        self.validator = validator
        self.persist_subfinder = persist_subfinder or self._persist_subfinder
        self.persist_dnsx = persist_dnsx or self._persist_dnsx
        self.asset_hosts = asset_hosts or _default_asset_hosts

    @staticmethod
    def _persist_subfinder(session: Any, scan: Any, observation: Observation) -> int:
        return persist_assets_from_observations(session, scan=scan, observations=[observation])

    @staticmethod
    def _persist_dnsx(session: Any, scan: Any, result: ToolResult) -> int:
        return apply_dnsx_enrichment(session, scan=scan, observation=result)

    def run(
        self,
        *,
        session: Any,
        scan: Any,
        cancel: Any = None,
        state: AgentState | None = None,
        run_id: str | None = None,
    ) -> DiscoveryResult:
        """Run discovery and return a temporary, non-authorizing result.

        Cancellation is represented as ``status == "cancelled"`` and stops
        all later tool calls, persistence, and promotion.  The service does
        not commit or close the supplied session.
        """
        cancel = cancel or threading.Event()
        result = DiscoveryResult()
        result.parents = _snapshot_discovery_parents(getattr(scan, "target_snapshot", None))
        result.finalize()
        if self._is_cancelled(cancel):
            result.status = "cancelled"
            return result.finalize()

        if state is None:
            state = AgentState(
                run_id=run_id or "discovery-run",
                goal="deterministic subdomain discovery",
                max_steps=self.validator.policy.max_steps,
            )

        discovered: set[str] = set()
        discovery_sources: dict[str, set[str]] = {}
        rejected: set[str] = set()
        parent_failures: set[str] = set()
        step = 0

        for parent in result.parents:
            if self._is_cancelled(cancel):
                result.status = "cancelled"
                return self._finish_result(result, discovered, rejected, set(), set())

            step += 1
            invocation = self._invoke(
                tool="subfinder",
                params={"domain": parent},
                state=state,
                cancel=cancel,
            )
            result.subfinder_calls += 1
            if not invocation.accepted:
                rejected.add(parent)
                result.errors.append(f"subfinder {parent}: {_safe_text(invocation.reason)}")
                continue
            if invocation.result is None or invocation.result.status != "ok":
                parent_failures.add(parent)
                if invocation.result is not None:
                    result.errors.append(
                        f"subfinder {parent}: {_safe_text(invocation.result.summary)}"
                    )
                continue

            observation = Observation.from_tool_result(step, "subfinder", invocation.result)
            data = invocation.result.data
            if normalize_hostname(data.get("domain")) != parent:
                parent_failures.add(parent)
                result.errors.append(f"subfinder {parent}: returned domain mismatch")
                continue
            valid, invalid = self._validated_discoveries(data, parent)
            discovered.update(valid)
            for host in valid:
                discovery_sources.setdefault(host, set()).add(parent)
            rejected.update(invalid)
            if self._is_cancelled(cancel):
                result.status = "cancelled"
                return self._finish_result(result, discovered, rejected, set(), set())
            try:
                self.persist_subfinder(session, scan, observation)
            except Exception as exc:
                parent_failures.add(parent)
                result.errors.append(f"subfinder persistence {parent}: {_safe_text(exc)}")

        if self._is_cancelled(cancel):
            result.status = "cancelled"
            return self._finish_result(result, discovered, rejected, set(), set())

        # Hosts from a failed parent are not eligible for DNSX or promotion.
        eligible_discovered = sorted(
            host
            for host in discovered
            if any(parent not in parent_failures for parent in discovery_sources.get(host, ()))
        )
        result.discovered = eligible_discovered
        result.policy_rejected = sorted(rejected)
        if not eligible_discovered:
            return result.finalize()

        dns_verified: set[str] = set()
        dns_unverified: set[str] = set()
        for offset in range(0, len(eligible_discovered), MAX_DNSX_TARGETS):
            if self._is_cancelled(cancel):
                result.status = "cancelled"
                return self._finish_result(result, discovered, rejected, dns_verified, dns_unverified)
            batch = eligible_discovered[offset : offset + MAX_DNSX_TARGETS]
            step += 1
            invocation = self._invoke(
                tool="dnsx",
                params={"targets": batch},
                state=state,
                cancel=cancel,
            )
            result.dnsx_calls += 1
            if not invocation.accepted:
                dns_unverified.update(batch)
                result.errors.append(f"dnsx batch rejected: {_safe_text(invocation.reason)}")
                continue
            if invocation.result is None or invocation.result.status != "ok":
                dns_unverified.update(batch)
                if invocation.result is not None:
                    result.errors.append(f"dnsx batch: {_safe_text(invocation.result.summary)}")
                continue

            records = invocation.result.data.get("records")
            if not isinstance(records, list):
                dns_unverified.update(batch)
                continue
            # Attribute the existing integer enrichment count to ONE host.
            # The lookup keys come from our validated call, not DNS answers.
            for host in batch:
                if self._is_cancelled(cancel):
                    result.status = "cancelled"
                    return self._finish_result(result, discovered, rejected, dns_verified, dns_unverified)
                host_records = [
                    record for record in records
                    if isinstance(record, dict) and normalize_hostname(record.get("host")) == host
                ]
                dns_unverified.add(host)
                if not host_records:
                    continue
                host_result = ToolResult(
                    status="ok", data={"targets": [host], "records": host_records}, findings=[]
                )
                try:
                    enriched = self.persist_dnsx(session, scan, host_result)
                except Exception as exc:
                    result.errors.append(f"dnsx persistence {host}: {_safe_text(exc)}")
                    continue
                if type(enriched) is not int or enriched <= 0:
                    result.errors.append(f"dnsx persistence {host}: no assets enriched")
                    continue
                if any(_record_verified_host(record, allowed={host}) for record in host_records):
                    dns_verified.add(host)
                    dns_unverified.discard(host)

        if self._is_cancelled(cancel):
            result.status = "cancelled"
            return self._finish_result(result, discovered, rejected, dns_verified, dns_unverified)

        existing = self.asset_hosts(session, scan, dns_verified)
        if self._is_cancelled(cancel):
            result.status = "cancelled"
            return self._finish_result(result, discovered, rejected, dns_verified, dns_unverified)
        promoted = {
            host
            for host in dns_verified
            if host in existing and any(is_within_domain(host, parent) for parent in result.parents)
        }
        return self._finish_result(result, discovered, rejected, dns_verified, dns_unverified, promoted)

    def _invoke(
        self,
        *,
        tool: str,
        params: dict[str, Any],
        state: AgentState,
        cancel: Any,
    ) -> _Invocation:
        """Validate then execute one structured ToolCall through the registry."""
        if self._is_cancelled(cancel):
            return _Invocation(accepted=False, reason="cancelled")
        call = ToolCall(tool=tool, params=params)
        # Only this fixed DNSX branch can obtain the query-only policy.
        # Its batch was derived by run() from policy-valid discoveries.
        if tool == "dnsx":
            validator = self._dnsx_validator(params["targets"])
        elif tool == "subfinder":
            validator = self.validator
        else:
            return _Invocation(accepted=False, reason="unsupported discovery tool")
        outcome = validator.validate(call, state)
        if not outcome.accepted:
            return _Invocation(accepted=False, reason=outcome.reason)
        if outcome.tool is None:
            return _Invocation(accepted=False, reason="validator returned no tool")
        if self._is_cancelled(cancel):
            return _Invocation(accepted=False, reason="cancelled")
        try:
            registered = self.registry.get(tool)
            result = registered.execute(
                outcome.validated_params,
                ToolContext(
                    run_id=state.run_id,
                    allowed_targets=list(validator.policy.allowed_targets),
                    timeout_s=validator.policy.timeout_s,
                    cancel=cancel,
                ),
            )
        except Exception as exc:
            return _Invocation(
                accepted=True,
                result=ToolResult(
                    status="error",
                    summary=f"{tool} raised: {_safe_text(exc)}",
                    data={},
                    findings=[],
                ),
            )
        return _Invocation(accepted=True, result=result)

    def _dnsx_validator(self, batch: list[str]) -> SafetyValidator:
        """Isolate DNS observation permission to exactly this validated batch.

        Always copy, even when every candidate was already in the caller's
        policy. Never inherit its IPs, URL seeds, or unrelated targets.
        This validator stays local to the DNSX invocation.
        """
        validator = copy.copy(self.validator)
        validator.policy = self.validator.policy.model_copy(
            deep=True,
            update={"allowed_targets": list(batch)},
        )
        return validator

    @staticmethod
    def _validated_discoveries(
        data: dict[str, Any], parent: str
    ) -> tuple[set[str], set[str]]:
        """Apply the existing hostname/descendant policy to Subfinder data."""
        valid: set[str] = set()
        rejected: set[str] = set()
        if normalize_hostname(data.get("domain")) != parent:
            return valid, rejected
        entries = data.get("subdomains")
        if not isinstance(entries, list):
            return valid, rejected
        for entry in entries[:MAX_DISCOVERED_HOSTS]:
            raw = entry.get("host") if isinstance(entry, dict) else entry
            host = normalize_hostname(raw)
            if host is None or host == parent or not is_within_domain(host, parent):
                rejected.add(_safe_text(raw))
                continue
            valid.add(host)
        return valid, rejected

    @staticmethod
    def _is_cancelled(cancel: Any) -> bool:
        return bool(getattr(cancel, "is_set", lambda: False)())

    @staticmethod
    def _finish_result(
        result: DiscoveryResult,
        discovered: set[str],
        rejected: set[str],
        dns_verified: set[str],
        dns_unverified: set[str],
        promoted: set[str] | None = None,
    ) -> DiscoveryResult:
        result.discovered = sorted(discovered)
        result.policy_rejected = sorted(rejected)
        result.dns_verified = sorted(dns_verified)
        result.dns_unverified = sorted(dns_unverified - dns_verified)
        result.promoted = sorted(promoted or set())
        return result.finalize()


__all__ = ["DiscoveryResult", "DiscoveryService", "MAX_DNSX_TARGETS"]
