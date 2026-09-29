"""DNSXTool: controlled DNS enrichment (Phase 4C, step 1).

Mirrors the HTTPX/Subfinder pattern with no runtime changes:
- validated DNSXParams (hostname list only) - NO arbitrary flags
- fixed argv construction (JSONL stdout only, ``-l`` comma-list mode)
- controlled subprocess runner (no shell)
- strict JSONL parsing into normalized ToolResult.data
- concise summary, zero manufactured Findings (enrichment only)

Trust boundaries (DNS OUTPUT IS UNTRUSTED DATA):
- every target must be validator-authorized AND re-checked inside
  execute(); A/AAAA/CNAME values are carried as observation data
  only - they never authorize targets, are never followed (CNAME
  targets especially so), and never create assets here.
- the future discovery_service decides whether a verified hostname is
  promotable; this tool only returns observations.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

from pydantic import BaseModel, Field, field_validator

from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.dnsx_parser import parse_dnsx_jsonl
from agent_core.tools.subprocess import run_pinned_binary

DNSX_BINARY = "dnsx"

# Pinned DNSX v1.3.1 CLI surface (verified against the local
# ../dnsx tree: internal/runner/options.go flag definitions).
_DNSX_TIMEOUT = "3s"  # -timeout: Go duration per DNS query
_DNSX_RETRY = "1"  # -retry: attempts per query (fail fast)
_DNSX_THREADS = "25"  # -threads: concurrency (default 100)

MAX_TARGETS = 20

# Hostname shape mirrors backend scope validation (RFC 1123 labels);
# the backend promotion policy stays authoritative for persistence.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
# Targets travel joined by commas in ONE argv element after "-l", so
# reject commas plus every shell/flag/URL/IP-literal vector. Hostnames
# carry no URL characters at all (unlike httpx targets).
_TARGET_BAD_RE = re.compile(r"[\s;,|&`$()<>!\\'\"*?~#@/:+=]")


def _check_target_shape(value: str) -> str:
    """Validate + canonicalize one DNSX target (lowercase DNS name)."""
    v = str(value).strip()
    if not v:
        raise ValueError("targets must not contain empty values")
    if len(v) > 253:
        raise ValueError("target too long (max 253 chars)")
    if v.startswith("-"):
        raise ValueError("target must not look like a flag")
    if "://" in v:
        raise ValueError("target must not include a URL scheme")
    if _TARGET_BAD_RE.search(v):
        raise ValueError(f"target contains disallowed characters: {v!r}")
    if v.endswith("."):  # strip at most one trailing root dot
        v = v[:-1]
    try:
        ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        raise ValueError("target must be a DNS name, not an IP literal")
    lowered = v.lower()
    if not _HOSTNAME_RE.match(lowered):
        raise ValueError(f"malformed hostname: {value!r}")
    return lowered


class DNSXParams(BaseModel):
    """Validated dnsx parameters. Extra keys forbidden (injection-safe)."""

    model_config = {"extra": "forbid"}

    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)

    @field_validator("targets")
    @classmethod
    def _check_targets(cls, v: list[str]) -> list[str]:
        cleaned = [_check_target_shape(item) for item in v]
        if not cleaned:
            raise ValueError("targets must not be empty")
        return cleaned


def build_dnsx_argv(params: DNSXParams) -> list[str]:
    """Build the FULL fixed argv (including binary).

    Fixed (no caller influence):
        dnsx -json -silent -nc -duc -timeout 3s -retry 1 -threads 25
             -a -aaaa -cname -omit-raw -l h1,h2,...
    Input uses ``-l`` comma-list mode (file/stdin/bruteforce variants
    never used, so tool_runner needs no stdin support). Record types
    are fixed to A/AAAA/CNAME (the enrichment vocabulary). ``-omit-raw``
    drops the bulk ``all`` blob from JSONL lines.
    Deliberately NOT exposed: -r (custom resolvers), -axfr, -trace,
    -recon/-all, -any, -d/-w (bruteforce inputs), -proxy, -resp/-resp-only,
    -raw, -cdn, -asn, -wd/-auto-wildcard, -o (output paths), -stats,
    -stream, -resume, -hostsfile, -rcode/-rtf, -e, -rl, -ot, -v.
    -duc disables the version-update check (uncontrolled latency).
    """
    return [
        DNSX_BINARY,
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-timeout",
        _DNSX_TIMEOUT,
        "-retry",
        _DNSX_RETRY,
        "-threads",
        _DNSX_THREADS,
        "-a",
        "-aaaa",
        "-cname",
        "-omit-raw",
        "-l",
        ",".join(params.targets),
    ]


def _summarize(data: dict[str, Any]) -> str:
    records = data.get("records", [])
    if not records:
        return "DNSX probe: no DNS records returned."
    resolved = sum(
        1 for r in records if r.get("a") or r.get("aaaa") or r.get("cname")
    )
    return (
        f"DNSX resolved {resolved} of {len(records)} host(s) "
        f"({len(records) - resolved} without records)."
    )


RunnerFn = Callable[..., Any]


class DNSXTool(Tool):
    """Controlled dnsx DNS-enrichment wrapper behind the Tool interface."""

    name = "dnsx"
    description = (
        "Controlled dnsx DNS enrichment for authorized hostnames. "
        "Returns normalized A/AAAA/CNAME records (JSONL parsed). "
        "Enrichment only: records are untrusted observation data - they "
        "never authorize targets and CNAMEs are never followed."
    )
    input_model = DNSXParams
    danger_level = "safe"

    def __init__(
        self,
        binary: str = DNSX_BINARY,
        runner: RunnerFn | None = None,
    ) -> None:
        self.binary = binary
        self._runner = runner or run_pinned_binary

    def policy_targets(self, params: dict[str, Any]) -> list[str | None]:
        """Plural target hook consumed by SafetyValidator."""
        raw = params.get("targets", [])
        if isinstance(raw, list):
            return [str(t) for t in raw]
        return [None]

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(params, DNSXParams)
        # Defense-in-depth: re-check EVERY allowlisted target inside the
        # tool (validator already enforces this; direct callers stay safe).
        if ctx.allowed_targets:
            from agent_core.safety.policy import Policy

            policy = Policy(allowed_targets=ctx.allowed_targets)
            for t in params.targets:
                if not policy.target_allowed(t):
                    return ToolResult(
                        status="error",
                        summary=f"target {t!r} is not in the allowed targets list",
                        data={"targets": params.targets},
                        findings=[],
                    )

        argv = build_dnsx_argv(params)
        executable = self.binary
        args = argv[1:]

        try:
            res = self._runner(executable, args, timeout_s=ctx.timeout_s)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"dnsx runner error: {exc}",
                data={"targets": params.targets},
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
                summary=f"DNSX probe timed out after {ctx.timeout_s}s.",
                data={"targets": params.targets, "stderr": stderr[:2000]},
                findings=[],
            )
        if returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return ToolResult(
                status="error",
                summary=f"DNSX probe failed: {detail[:500]}",
                data={"targets": params.targets, "returncode": returncode, "stderr": stderr[:2000]},
                findings=[],
            )
        try:
            parsed = parse_dnsx_jsonl(stdout)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"DNSX probe returned unparsable output: {exc}",
                data={"targets": params.targets},
                findings=[],
            )
        data: dict[str, Any] = {
            "targets": params.targets,
            "records": parsed["records"],
            "skipped": parsed["skipped"],
            "truncated": truncated,
        }
        # Enrichment only: never manufacture Findings, never create
        # assets here (persistence decides that later, deterministically).
        return ToolResult(status="ok", summary=_summarize(data), data=data, findings=[])
