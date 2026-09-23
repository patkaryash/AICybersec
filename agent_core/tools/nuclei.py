"""NucleiTool: controlled vulnerability scanning (M2-B).

Mirrors the Nmap/HTTPX pattern with no runtime changes:
- validated NucleiParams (targets list only) - NO arbitrary flags
- fixed argv construction (JSONL stdout only)
- controlled subprocess runner (no shell)
- JSONL parsing into Finding objects (no raw JSON to the model)
- failures map to error/timeout with zero fabricated findings
"""
from __future__ import annotations

import re
from typing import Any, Callable

from pydantic import BaseModel, Field, field_validator

from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.nuclei_parser import parse_nuclei_jsonl
from agent_core.tools.subprocess import run_pinned_binary

NUCLEI_BINARY = "nuclei"

MAX_TARGETS = 20

# Same rationale as HTTPXParams: targets are separate argv elements (no
# shell), so reject leading "-" plus whitespace/shell metachars while
# allowing URL chars (?&=#%+:@/._-).
_TARGET_BAD_RE = re.compile(r"[\s;|&`$()<>!\\'\"~]")


class NucleiParams(BaseModel):
    """Validated nuclei parameters. Extra keys forbidden (injection-safe)."""

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


def build_nuclei_argv(params: NucleiParams) -> list[str]:
    """Build the FULL fixed argv (including binary).

    Fixed profile (no caller influence):
        nuclei -jsonl -silent -nc -severity critical,high,medium
               -tags cve,misconfiguration,exposure,default-login
               -rate-limit 150 -bulk-size 25 -concurrency 25
               -timeout 10 -retries 1 -omit-raw
    Targets: repeated ``-target <target>`` pairs, each a separate element.
    """
    argv: list[str] = [
        NUCLEI_BINARY,
        "-jsonl",
        "-silent",
        "-nc",
        "-severity",
        "critical,high,medium",
        "-tags",
        "cve,misconfiguration,exposure,default-login",
        "-rate-limit",
        "150",
        "-bulk-size",
        "25",
        "-concurrency",
        "25",
        "-timeout",
        "10",
        "-retries",
        "1",
        "-omit-raw",
    ]
    for t in params.targets:
        argv += ["-target", t]
    return argv


def _summarize(findings_count: int, skipped: int, findings: list) -> str:
    if findings_count == 0:
        return "Nuclei scan complete: no findings (no matched templates)."
    top = ", ".join(f"{f.title} [{f.severity}]" for f in findings[:5])
    extra = f" ({findings_count - 5} more not shown.)" if findings_count > 5 else ""
    skipped_note = f" ({skipped} line(s) skipped.)" if skipped else ""
    return f"Nuclei scan found {findings_count} finding(s): {top}.{extra}{skipped_note}"


RunnerFn = Callable[..., Any]


class NucleiTool(Tool):
    """Real nuclei wrapper behind the Tool interface."""

    name = "nuclei"
    description = (
        "Controlled nuclei vulnerability scan against authorized targets. "
        "Returns normalized findings (JSONL parsed, template matches only). "
        "Active scan - allowlisted targets only."
    )
    input_model = NucleiParams
    danger_level = "active_scan"

    def __init__(
        self,
        binary: str = NUCLEI_BINARY,
        runner: RunnerFn | None = None,
    ) -> None:
        self.binary = binary
        self._runner = runner or run_pinned_binary

    def policy_targets(self, params: dict[str, Any]) -> list[str | None]:
        """Plural target hook consumed by SafetyValidator (M2-A pattern)."""
        raw = params.get("targets", [])
        if isinstance(raw, list):
            return [str(t) for t in raw]
        return [None]

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(params, NucleiParams)
        # Defense-in-depth: re-check EVERY allowlisted target inside the
        # tool (validator already enforces this; direct callers stay safe).
        # Fail closed on the first disallowed target - never execute.
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

        argv = build_nuclei_argv(params)
        executable = self.binary
        args = argv[1:]

        try:
            res = self._runner(executable, args, timeout_s=ctx.timeout_s)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"nuclei runner error: {exc}",
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
                summary=f"Nuclei scan timed out after {ctx.timeout_s}s.",
                data={"targets": params.targets, "stderr": stderr[:2000]},
                findings=[],
            )
        if returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return ToolResult(
                status="error",
                summary=f"Nuclei scan failed: {detail[:500]}",
                data={"targets": params.targets, "returncode": returncode, "stderr": stderr[:2000]},
                findings=[],
            )
        # Empty stdout is valid: clean target, zero findings.
        if not stdout.strip():
            return ToolResult(
                status="ok",
                summary=_summarize(0, 0, []),
                data={"targets": params.targets, "findings_count": 0, "findings": [], "skipped": 0, "truncated": truncated},
                findings=[],
            )
        try:
            parsed = parse_nuclei_jsonl(stdout)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"Nuclei scan returned unparsable output: {exc}",
                data={"targets": params.targets},
                findings=[],
            )
        findings = parsed["findings"]
        compact = [
            {"id": f.id, "title": f.title, "severity": f.severity, "target": f.target}
            for f in findings
        ]
        data: dict[str, Any] = {
            "targets": params.targets,
            "findings_count": len(findings),
            "findings": compact,
            "skipped": parsed["skipped"],
            "truncated": truncated,
        }
        return ToolResult(
            status="ok",
            summary=_summarize(len(findings), parsed["skipped"], findings),
            data=data,
            findings=findings,
        )
