"""HTTPXTool: the second REAL security tool (M2-A).

Mirrors the NmapTool pattern with no runtime changes:
- validated HTTPXParams (targets list only) - NO arbitrary flags
- fixed argv construction (JSONL stdout only)
- controlled subprocess runner (no shell)
- JSONL parsing into normalized ToolResult.data
- concise summary, zero manufactured vulnerability Findings
"""
from __future__ import annotations

import re
from typing import Any, Callable

from pydantic import BaseModel, Field, field_validator

from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.httpx_parser import parse_httpx_jsonl
from agent_core.tools.subprocess import run_pinned_binary

HTTPX_BINARY = "httpx"

MAX_TARGETS = 20

# Targets travel as separate argv elements (no shell), so the only real
# injection vector is a value httpx itself parses as a flag. Reject
# leading "-" plus whitespace/shell metachars; URL chars (?&=#%+:@/._-)
# remain allowed.
_TARGET_BAD_RE = re.compile(r"[\s;|&`$()<>!\\'\"~]")


class HTTPXParams(BaseModel):
    """Validated httpx parameters. Extra keys forbidden (injection-safe)."""

    model_config = {"extra": "forbid"}

    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)

    @field_validator("targets")
    @classmethod
    def _check_targets(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in v:
            t = str(item).strip()
            if not t:
                raise ValueError("targets must not contain empty values")
            if len(t) > 2048:
                raise ValueError("target too long (max 2048 chars)")
            if t.startswith("-"):
                raise ValueError("target must not look like a flag")
            if _TARGET_BAD_RE.search(t):
                raise ValueError(f"target contains disallowed characters: {t!r}")
            cleaned.append(t)
        if not cleaned:
            raise ValueError("targets must not be empty")
        return cleaned


def build_httpx_argv(params: HTTPXParams) -> list[str]:
    """Build the FULL fixed argv (including binary).

    Base (fixed, no caller influence):
        httpx -json -silent -nc -sc -cl -ct -title -server -method
              -td -ip -cname -cdn -tls-probe -follow-redirects
              -timeout 10 -retries 1 -threads 50 -rate-limit 150 -duc
    Targets: repeated ``-u <target>`` pairs, each a separate element.

    -duc disables the automatic version-update check, which would add
    uncontrolled external-network latency to every run.
    """
    argv: list[str] = [
        HTTPX_BINARY,
        "-json",
        "-silent",
        "-nc",
        "-sc",
        "-cl",
        "-ct",
        "-title",
        "-server",
        "-method",
        "-td",
        "-ip",
        "-cname",
        "-cdn",
        "-tls-probe",
        "-follow-redirects",
        "-timeout",
        "10",
        "-retries",
        "1",
        "-threads",
        "50",
        "-rate-limit",
        "150",
        "-duc",
    ]
    for t in params.targets:
        argv += ["-u", t]
    return argv


def _summarize(data: dict[str, Any]) -> str:
    services = data.get("services", [])
    if not services:
        return "HTTPX probe: no HTTP services discovered."
    parts = [f"Discovered {len(services)} HTTP service(s)."]
    for s in services[:5]:
        label = s.get("input") or s.get("url") or "unknown"
        bits = []
        if s.get("status_code") is not None:
            bits.append(f"returned {s['status_code']}")
        if s.get("title"):
            bits.append(f"title {s['title']!r}")
        if s.get("tech"):
            bits.append(f"technology detected: {', '.join(s['tech'][:5])}")
        elif s.get("webserver"):
            bits.append(f"server: {s['webserver']}")
        detail = (" " + " with ".join(bits)) if bits else ""
        parts.append(f"{label}{detail}.")
    if len(services) > 5:
        parts.append(f"({len(services) - 5} more not shown.)")
    return " ".join(parts)


RunnerFn = Callable[..., Any]


class HTTPXTool(Tool):
    """Real httpx wrapper behind the Tool interface."""

    name = "httpx"
    description = (
        "Controlled httpx HTTP/service probe against authorized targets. "
        "Returns normalized URL/status/title/tech/TLS observations (JSONL parsed). "
        "Reconnaissance only - no exploitation."
    )
    input_model = HTTPXParams
    danger_level = "safe"

    def __init__(
        self,
        binary: str = HTTPX_BINARY,
        runner: RunnerFn | None = None,
    ) -> None:
        self.binary = binary
        self._runner = runner or run_pinned_binary

    def policy_targets(self, params: dict[str, Any]) -> list[str | None]:
        """Plural target hook consumed by SafetyValidator (M2-A)."""
        raw = params.get("targets", [])
        if isinstance(raw, list):
            return [str(t) for t in raw]
        return [None]

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(params, HTTPXParams)
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

        argv = build_httpx_argv(params)
        executable = self.binary
        args = argv[1:]

        try:
            res = self._runner(executable, args, timeout_s=ctx.timeout_s)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"httpx runner error: {exc}",
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
                summary=f"HTTPX probe timed out after {ctx.timeout_s}s.",
                data={"targets": params.targets, "stderr": stderr[:2000]},
                findings=[],
            )
        if returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return ToolResult(
                status="error",
                summary=f"HTTPX probe failed: {detail[:500]}",
                data={"targets": params.targets, "returncode": returncode, "stderr": stderr[:2000]},
                findings=[],
            )
        try:
            parsed = parse_httpx_jsonl(stdout)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"HTTPX probe returned unparsable output: {exc}",
                data={"targets": params.targets},
                findings=[],
            )
        data: dict[str, Any] = {
            "services": parsed["services"],
            "skipped": parsed["skipped"],
            "targets": params.targets,
            "truncated": truncated,
        }
        return ToolResult(status="ok", summary=_summarize(data), data=data, findings=[])
