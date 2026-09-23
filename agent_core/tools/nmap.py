"""NmapTool: the first REAL security tool (M1).

Fits the existing Tool interface with no runtime changes:
- validated NmapParams (target/ports/profile) - NO arbitrary flags
- fixed argv construction per profile (XML stdout only)
- controlled subprocess runner (no shell)
- stdlib XML parsing into normalized ToolResult.data
- concise summary, zero manufactured vulnerability Findings
"""
from __future__ import annotations

import re
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field, field_validator

from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.nmap_parser import parse_nmap_xml
from agent_core.tools.subprocess import run_pinned_binary

NMAP_BINARY = "nmap"

NmapProfile = Literal["safe", "version", "os", "vuln"]

# ports: "top-100"/"top-1000"/"top-65535" or explicit "80,443" / "1-1024".
_PORTS_RE = re.compile(r"^(top-\d+|[0-9,\-]+)$")
# Reject shell metachars / whitespace / flag injection in targets.
_TARGET_BAD_RE = re.compile(r"[\s;|&`$()<>!\\'\"*?~#]")


class NmapParams(BaseModel):
    """Validated Nmap parameters. Extra keys forbidden (injection-safe)."""

    model_config = {"extra": "forbid"}

    target: str = Field(min_length=1, max_length=253)
    ports: str = Field(default="top-1000")
    profile: NmapProfile = "safe"

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        t = v.strip()
        if not t:
            raise ValueError("target must be non-empty")
        if t.startswith("-"):
            raise ValueError("target must not look like a flag")
        if _TARGET_BAD_RE.search(t):
            raise ValueError("target contains disallowed characters")
        return t

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, v: str) -> str:
        p = v.strip()
        if not _PORTS_RE.match(p):
            raise ValueError("ports must be 'top-<n>' or digits/commas/dashes like '80,443' or '1-1024'")
        if p.startswith("top-"):
            try:
                n = int(p[4:])
            except ValueError:
                raise ValueError("invalid top-ports value")
            if n <= 0 or n > 65535:
                raise ValueError("top-ports must be 1..65535")
        return p


def _ports_argv(ports: str) -> list[str]:
    """Map validated ``ports`` to fixed argv (no pass-through)."""
    if ports.startswith("top-"):
        return ["--top-ports", ports[4:]]
    return ["-p", ports]


def build_nmap_argv(params: NmapParams) -> list[str]:
    """Build the FULL fixed argv (including binary) for a profile.

    Base (all profiles):
        nmap -sV --reason --open -T4 --host-timeout 10m --max-retries 2
             <ports> -oX - <target>
    Profile extras:
        safe:    (base only)
        version: + --version-intensity 5
        os:      + -O
        vuln:    + --script default,vuln
    """
    argv: list[str] = [
        NMAP_BINARY,
        "-sV",
        "--reason",
        "--open",
        "-T4",
        "--host-timeout",
        "10m",
        "--max-retries",
        "2",
    ]
    if params.profile == "version":
        argv += ["--version-intensity", "5"]
    elif params.profile == "os":
        argv += ["-O"]
    elif params.profile == "vuln":
        argv += ["--script", "default,vuln"]
    argv += _ports_argv(params.ports)
    argv += ["-oX", "-", params.target]
    return argv


def _summarize(data: dict[str, Any], target: str) -> str:
    hosts = data.get("hosts", [])
    if not hosts:
        return f"Nmap scan of {target}: no hosts found."
    parts: list[str] = []
    for h in hosts:
        label = h.get("ip") or target
        if h.get("status") != "up":
            parts.append(f"Host {label} is {h.get('status')}.")
            continue
        open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
        if not open_ports:
            parts.append(f"Host {label} is up. No open TCP ports found.")
        else:
            desc = ", ".join(
                f"{p['port']}/{(p.get('service') or {}).get('name') or p.get('protocol')}"
                for p in open_ports
            )
            parts.append(
                f"Host {label} is up. Found {len(open_ports)} open TCP port(s): {desc}."
            )
    return " ".join(parts)


RunnerFn = Callable[..., Any]


class NmapTool(Tool):
    """Real Nmap wrapper behind the Tool interface."""

    name = "nmap"
    description = (
        "Controlled Nmap service/version scan against an authorized target. "
        "Returns normalized hosts/ports/services (XML parsed). No exploitation."
    )
    input_model = NmapParams
    danger_level = "active_scan"

    def __init__(
        self,
        binary: str = NMAP_BINARY,
        runner: RunnerFn | None = None,
    ) -> None:
        self.binary = binary
        self._runner = runner or run_pinned_binary

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(params, NmapParams)
        # Defense-in-depth: re-check allowlist inside the tool (validator
        # already enforces this; a direct Tool.execute caller still stays safe).
        if ctx.allowed_targets:
            from agent_core.safety.policy import Policy

            if not Policy(allowed_targets=ctx.allowed_targets).target_allowed(params.target):
                return ToolResult(
                    status="error",
                    summary=f"target {params.target!r} is not in the allowed targets list",
                    data={"target": params.target, "profile": params.profile},
                    findings=[],
                )

        argv = build_nmap_argv(params)
        executable = self.binary
        args = argv[1:]  # argv[0] is NMAP_BINARY; keep fixed args, swap binary only

        try:
            res = self._runner(executable, args, timeout_s=ctx.timeout_s)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"nmap runner error: {exc}",
                data={"target": params.target, "profile": params.profile},
                findings=[],
            )
        # Support both SubprocessResult and test doubles exposing same attrs.
        timed_out = bool(getattr(res, "timed_out", False))
        returncode = int(getattr(res, "returncode", -1))
        stdout = str(getattr(res, "stdout", "") or "")
        stderr = str(getattr(res, "stderr", "") or "")
        truncated = bool(getattr(res, "truncated", False))

        if timed_out:
            return ToolResult(
                status="timeout",
                summary=f"Nmap scan of {params.target} timed out after {ctx.timeout_s}s.",
                data={"target": params.target, "profile": params.profile, "stderr": stderr[:2000]},
                findings=[],
            )
        if returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return ToolResult(
                status="error",
                summary=f"Nmap scan of {params.target} failed: {detail[:500]}",
                data={"target": params.target, "profile": params.profile, "returncode": returncode, "stderr": stderr[:2000]},
                findings=[],
            )
        try:
            data = parse_nmap_xml(stdout)
        except ValueError as exc:
            return ToolResult(
                status="error",
                summary=f"Nmap scan of {params.target} returned unparsable XML: {exc}",
                data={"target": params.target, "profile": params.profile},
                findings=[],
            )
        data["target"] = params.target
        data["profile"] = params.profile
        data["truncated"] = truncated
        # Reconnaissance only: never manufacture vulnerability Findings.
        return ToolResult(status="ok", summary=_summarize(data, params.target), data=data, findings=[])
