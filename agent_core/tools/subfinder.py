"""SubfinderTool: controlled passive subdomain discovery (Phase 4B).

Mirrors the Nmap/HTTPX/Nuclei pattern with no runtime changes:
- validated SubfinderParams (single domain only) - NO arbitrary flags
- fixed argv construction (JSONL stdout only)
- controlled subprocess runner (no shell)
- strict JSONL parsing into normalized ToolResult.data
- promotion filtering: only valid descendants of the requested domain
  survive into the observation (label-aware, never naive endswith)
- DNS verification via an injectable TRUSTED resolver (stdlib
  getaddrinfo by default): establishes "currently resolves" as DATA.
  Subfinder-reported IPs are never trusted and never authorize.
- concise summary, zero manufactured Findings (recon only)

Trust boundaries (DISCOVERY IS NOT AUTHORIZATION):
- the requested domain must be validator-authorized AND re-checked
  inside execute(); a discovered subdomain is DATA, never allowlisted
- verification IPs are stored as attributes only; resolve_scope (scan
  start, snapshot + OUR forward DNS) is the only authorization path
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from pydantic import BaseModel, Field, field_validator

from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.subfinder_parser import parse_subfinder_jsonl
from agent_core.tools.subprocess import run_pinned_binary

SUBFINDER_BINARY = "subfinder"

# Pinned subfinder v2.16.0 CLI surface (verified against the local
# ../subfinder tree: pkg/runner/options.go flag definitions).
_SUBFINDER_TIMEOUT_S = "30"  # -timeout: seconds per source
_SUBFINDER_MAX_TIME_M = "5"  # -max-time: minutes for enumeration

# Hostname shape mirrors backend scope validation (RFC 1123 labels);
# the backend promotion policy stays authoritative for persistence.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
# The domain travels as ONE argv element after "-d" (StringSlice would
# split on commas), so reject commas plus every shell/flag/URL vector.
_DOMAIN_BAD_RE = re.compile(r"[\s;,|&`$()<>!\\'\"*?~#@/:+=]")

# DNS verification bounds (in-process enrichment, NOT covered by the
# subprocess runner timeout - hence explicit caps).
MAX_VERIFY_HOSTS = 100
VERIFY_WORKERS = 8
VERIFY_PER_HOST_S = 5.0


def _check_domain_shape(value: str) -> str:
    """Validate + canonicalize a domain argument (lowercase DNS name)."""
    v = value.strip()
    if not v:
        raise ValueError("domain must be non-empty")
    if len(v) > 253:
        raise ValueError("domain too long (max 253 chars)")
    if v.startswith("-"):
        raise ValueError("domain must not look like a flag")
    if "://" in v:
        raise ValueError("domain must not include a URL scheme")
    if _DOMAIN_BAD_RE.search(v):
        raise ValueError(f"domain contains disallowed characters: {v!r}")
    if v.endswith("."):  # strip at most one trailing root dot
        v = v[:-1]
    try:
        ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        raise ValueError("domain must be a DNS name, not an IP literal")
    lowered = v.lower()
    if not _HOSTNAME_RE.match(lowered):
        raise ValueError(f"malformed domain: {value!r}")
    return lowered


class SubfinderParams(BaseModel):
    """Validated subfinder parameters. Extra keys forbidden."""

    model_config = {"extra": "forbid"}

    domain: str = Field(min_length=1, max_length=253)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return _check_domain_shape(v)


def build_subfinder_argv(params: SubfinderParams) -> list[str]:
    """Build the FULL fixed argv (including binary).

    Fixed (no caller influence):
        subfinder -d <domain> -silent -nc -json
                  -timeout 30 -max-time 5 -duc
    Deliberately NOT exposed: -s/-es (sources), -r (custom resolvers),
    -o/-oD (output paths), -pc (provider config), -all, -recursive,
    -cs, -ip/-oI, -m/-f (match/filter files), -rls, -stats.
    -duc disables the version-update check (uncontrolled latency).
    """
    return [
        SUBFINDER_BINARY,
        "-d",
        params.domain,
        "-silent",
        "-nc",
        "-json",
        "-timeout",
        _SUBFINDER_TIMEOUT_S,
        "-max-time",
        _SUBFINDER_MAX_TIME_M,
        "-duc",
    ]


def _normalize_name(value: Any) -> str | None:
    """Canonicalize a discovered name; None when unusable.

    Agent-core mirror of the backend promotion policy (backend stays
    authoritative at persistence; this keeps observations clean).
    """
    if not isinstance(value, str):
        return None
    try:
        return _check_domain_shape(value)
    except ValueError:
        return None


def _is_within_domain(candidate: str, domain: str) -> bool:
    """Label-aware descendant-or-self check (never naive endswith)."""
    if candidate == domain:
        return True
    return candidate.endswith("." + domain)


def default_resolver(hostname: str) -> list[str]:
    """Trusted forward-DNS resolution via the stdlib (injectable).

    Same semantics as the backend scope bridge: OUR lookup, never
    scanner output. Empty on any failure (unverified, not an error).
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return []
    out: list[str] = []
    for info in infos:
        raw = str(info[4][0])
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


ResolverFn = Callable[[str], list[str]]
RunnerFn = Callable[..., Any]


def verify_hosts(
    hosts: list[str],
    resolver: ResolverFn,
    *,
    cancel: Any = None,
    max_hosts: int = MAX_VERIFY_HOSTS,
    workers: int = VERIFY_WORKERS,
    per_host_s: float = VERIFY_PER_HOST_S,
) -> dict[str, list[str]]:
    """Resolve each host via the TRUSTED resolver; return {host: ips}.

    Bounded best-effort enrichment: at most ``max_hosts`` lookups,
    ``workers`` parallel, ``per_host_s`` each. Failures/timeouts mean
    "unverified" (absent from the result), never an error. Straggler
    threads are detached, never awaited past their timeout.
    """
    selected = hosts[:max_hosts]
    resolved: dict[str, list[str]] = {}
    if cancel is not None and getattr(cancel, "is_set", lambda: False)():
        return resolved
    executor = ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="subfinder-verify"
    )
    try:
        future_to_host = {}
        for host in selected:
            if cancel is not None and getattr(cancel, "is_set", lambda: False)():
                break
            future_to_host[executor.submit(resolver, host)] = host
        for future, host in future_to_host.items():
            try:
                ips = future.result(timeout=per_host_s)
            except Exception:
                continue
            if isinstance(ips, list) and ips:
                resolved[host] = [str(ip)[:255] for ip in ips[:10]]
    finally:
        # Never block tool completion on straggler lookups; their threads
        # finish on OS DNS timeouts and are reaped at process exit.
        executor.shutdown(wait=False, cancel_futures=True)
    return resolved


def _summarize(domain: str, subdomains: list[dict[str, Any]], verified: int) -> str:
    if not subdomains:
        return f"Subfinder on {domain}: no subdomains discovered."
    return (
        f"Subfinder on {domain}: {len(subdomains)} subdomain(s) discovered "
        f"({verified} resolving)."
    )


class SubfinderTool(Tool):
    """Passive subfinder wrapper behind the Tool interface."""

    name = "subfinder"
    description = (
        "Passive subdomain enumeration for ONE authorized domain. "
        "Returns normalized subdomain names with trusted-DNS verification "
        "status (JSONL parsed). Discovery only - results never authorize "
        "further scanning by themselves."
    )
    input_model = SubfinderParams
    danger_level = "safe"

    def __init__(
        self,
        binary: str = SUBFINDER_BINARY,
        runner: RunnerFn | None = None,
        resolver: ResolverFn | None = None,
    ) -> None:
        self.binary = binary
        self._runner = runner or run_pinned_binary
        self._resolver = resolver or default_resolver

    def policy_target(self, params: dict[str, Any]) -> str | None:
        """Singular target hook consumed by SafetyValidator."""
        raw = params.get("domain")
        return str(raw) if isinstance(raw, str) else None

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(params, SubfinderParams)
        # Defense-in-depth: re-check the exact domain inside the tool
        # (validator already enforces this; direct callers stay safe).
        if ctx.allowed_targets:
            from agent_core.safety.policy import Policy

            if not Policy(allowed_targets=ctx.allowed_targets).target_allowed(
                params.domain
            ):
                return ToolResult(
                    status="error",
                    summary=f"target {params.domain!r} is not in the allowed targets list",
                    data={"domain": params.domain},
                    findings=[],
                )

        argv = build_subfinder_argv(params)
        try:
            res = self._runner(self.binary, argv[1:], timeout_s=ctx.timeout_s)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"subfinder runner error: {exc}",
                data={"domain": params.domain},
                findings=[],
            )
        timed_out = bool(getattr(res, "timed_out", False))
        returncode = int(getattr(res, "returncode", -1))
        stdout = str(getattr(res, "stdout", "") or "")
        stderr = str(getattr(res, "stderr", "") or "")
        truncated = bool(getattr(res, "truncated", False))

        if timed_out:
            return ToolResult(
                status="timeout",
                summary=f"Subfinder enumeration of {params.domain} timed out after {ctx.timeout_s}s.",
                data={"domain": params.domain, "stderr": stderr[:2000]},
                findings=[],
            )
        if returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return ToolResult(
                status="error",
                summary=f"Subfinder enumeration of {params.domain} failed: {detail[:500]}",
                data={
                    "domain": params.domain,
                    "returncode": returncode,
                    "stderr": stderr[:2000],
                },
                findings=[],
            )
        try:
            parsed = parse_subfinder_jsonl(stdout)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"Subfinder enumeration returned unparsable output: {exc}",
                data={"domain": params.domain},
                findings=[],
            )

        # Promotion filtering (tool layer): keep only valid descendants
        # of the requested domain. Out-of-parent, wildcard and malformed
        # names are counted as filtered, never emitted.
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        filtered = 0
        for entry in parsed["subdomains"]:
            name = _normalize_name(entry.get("subdomain"))
            if (
                name is None
                or name == params.domain
                or name in seen
                or not _is_within_domain(name, params.domain)
            ):
                filtered += 1
                continue
            seen.add(name)
            sources = entry.get("sources") or []
            candidates.append(
                {
                    "host": name,
                    "source": str(sources[0]) if sources else "subfinder",
                    "sources": [str(s) for s in sources[:10]],
                }
            )

        # DNS verification (trusted resolver only; subfinder-reported IPs
        # are carried as untrusted data and never used here).
        verified = verify_hosts(
            [c["host"] for c in candidates],
            self._resolver,
            cancel=ctx.cancel,
        )
        subdomains: list[dict[str, Any]] = []
        for candidate in candidates:
            ips = verified.get(candidate["host"], [])
            record: dict[str, Any] = {
                "host": candidate["host"],
                "source": candidate["source"],
                "sources": candidate["sources"],
                "verification_status": "resolved" if ips else "unverified",
            }
            if ips:
                record["dns_a"] = ips
            subdomains.append(record)

        data: dict[str, Any] = {
            "domain": params.domain,
            "subdomains": subdomains,
            "verified_count": len(verified),
            "unverified_count": len(subdomains) - len(verified),
            "skipped": parsed["skipped"],
            "filtered": filtered,
            "truncated": truncated,
        }
        # Reconnaissance only: never manufacture Findings.
        return ToolResult(
            status="ok", summary=_summarize(params.domain, subdomains, len(verified)),
            data=data, findings=[],
        )
