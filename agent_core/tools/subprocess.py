"""Controlled subprocess runner: the ONLY way real tools invoke binaries.

Safety properties (M1):
- NEVER uses ``shell=True``.
- NEVER accepts a raw shell command string.
- Caller passes an already-split ``args`` list; the executable is argv[0].
- Timeout comes from ToolContext (via the tool).
- stdout/stderr captured, output capped (Strix-inspired: 50 KB / 2000 lines).
- Missing binary, timeout, and non-zero exits are data, not crashes.

This module knows nothing about nmap/FastAPI/AgentState - it is a tiny
helper used by Tool implementations inside agent_core.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT_BYTES = 50 * 1024
MAX_OUTPUT_LINES = 2000

# Sentinel return code when the executable cannot be started.
MISSING_EXECUTABLE_RC = 127


@dataclass
class SubprocessResult:
    """Outcome of one pinned-binary invocation."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    truncated: bool = False
    spill_path: str | None = None


def truncate_output(text: str) -> tuple[str, bool]:
    """Cap ``text`` to MAX_OUTPUT_BYTES / MAX_OUTPUT_LINES.

    Returns (possibly-truncated text, was_truncated).
    Byte limit is applied on UTF-8 encoding; line limit keeps the head
    so the most relevant scan header survives.
    """
    if not text:
        return text, False
    truncated = False
    lines = text.splitlines()
    if len(lines) > MAX_OUTPUT_LINES:
        lines = lines[:MAX_OUTPUT_LINES]
        truncated = True
    out = "\n".join(lines)
    # Preserve trailing newline semantics loosely: not critical for XML/JSONL.
    encoded = out.encode("utf-8", errors="replace")
    if len(encoded) > MAX_OUTPUT_BYTES:
        out = encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore")
        truncated = True
    if truncated:
        out += "\n...[truncated: output exceeded 50KB/2000-line cap]..."
    return out, truncated


def run_pinned_binary(
    executable: str,
    args: list[str],
    timeout_s: float,
    spill_dir: str | Path | None = None,
) -> SubprocessResult:
    """Execute ``[executable, *args]`` without a shell.

    Args:
        executable: binary name or absolute path (e.g. "nmap"). Must be
            non-empty and must not contain whitespace - a cheap guard
            against accidental command-string passing.
        args: already-split argument list (targets must be separate
            elements, never concatenated into a command string).
        timeout_s: subprocess timeout in seconds (from ToolContext).
        spill_dir: optional directory; when output is truncated the FULL
            stdout is written to ``<spill_dir>/subprocess_stdout.txt``
            and the path returned as ``spill_path``.

    Never raises for missing binaries, timeouts, or non-zero exits -
    those are encoded in the returned SubprocessResult.
    """
    if not executable or not executable.strip():
        raise ValueError("executable must be a non-empty string")
    if any(c.isspace() for c in executable):
        raise ValueError(f"executable must not contain whitespace: {executable!r}")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("args must be a list[str] of pre-split arguments")
    if timeout_s is None or float(timeout_s) <= 0:
        raise ValueError("timeout_s must be a positive number")

    argv = [executable, *args]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=float(timeout_s),
            check=False,
            shell=False,
            text=True,
            errors="replace",
        )
    except FileNotFoundError:
        return SubprocessResult(
            stdout="",
            stderr=f"executable not found: {executable!r}",
            returncode=MISSING_EXECUTABLE_RC,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        raw_out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        raw_err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        out, t1 = truncate_output(raw_out)
        err, t2 = truncate_output(raw_err)
        spill_path = _maybe_spill(raw_out, spill_dir)
        return SubprocessResult(
            stdout=out,
            stderr=err,
            returncode=-1,
            timed_out=True,
            truncated=t1 or t2,
            spill_path=spill_path,
        )

    out, t1 = truncate_output(proc.stdout or "")
    err, t2 = truncate_output(proc.stderr or "")
    spill_path = _maybe_spill(proc.stdout or "", spill_dir) if (t1 or t2) else None
    return SubprocessResult(
        stdout=out,
        stderr=err,
        returncode=proc.returncode,
        timed_out=False,
        truncated=t1 or t2,
        spill_path=spill_path,
    )


def _maybe_spill(full_stdout: str, spill_dir: str | Path | None) -> str | None:
    """Write full stdout to disk when truncation occurred, if requested."""
    if spill_dir is None or not full_stdout:
        return None
    try:
        d = Path(spill_dir)
        d.mkdir(parents=True, exist_ok=True)
        p = d / "subprocess_stdout.txt"
        p.write_text(full_stdout, encoding="utf-8", errors="replace")
        return str(p)
    except OSError:
        return None
