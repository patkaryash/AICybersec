"""Controlled, cancellation-aware subprocess runner (Phase 3).

Wraps process control for scan-driven tool execution WITHOUT modifying
agent_core: the runner satisfies the same duck-typed contract as
agent_core's run_pinned_binary (SubprocessResult attrs: stdout/stderr/
returncode/timed_out/truncated/spill_path) and REUSES its output-cap
infrastructure. agent_core stays untouched.

Safety properties:
- NEVER shell=True; never accepts a command string; args stay a list.
- POSIX: start_new_session=True -> own process group; cancel/timeout
  kill the WHOLE group (os.killpg). Windows fallback: terminate ->
  grace wait -> kill() (NOT identical to POSIX process-group semantics).
- Cancel polled every ~100ms; timeout is a wall-clock deadline.
- Output capped via agent_core's truncate_output (50KB/2000 lines);
  full stdout spilled to backend-controlled paths (trusted UUIDs).
- Minimal environment (PATH/HOME + OS essentials) - no inherited
  application secrets reach scanner processes.
- Captures argv/exit_code/raw output per invocation into an optional
  RunRecorder for ToolRun audit enrichment (internal/audit data; never
  exposed through the API).
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from agent_core.tools.subprocess import SubprocessResult, truncate_output

POLL_INTERVAL_S = 0.1
GRACE_PERIOD_S = 2.0

# Minimal environment for scanner execution: PATH/HOME plus the OS
# essentials a binary needs to start. No application configuration,
# credentials, or secrets are inherited.
_SANITIZED_ENV_KEYS = ("PATH", "HOME", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP")


def sanitized_env() -> dict[str, str]:
    """Minimal environment for scanner subprocesses."""
    env: dict[str, str] = {}
    for key in _SANITIZED_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


@dataclass
class RunnerRecord:
    """One invocation's audit capture (argv/exit_code/raw output)."""

    argv: list[str] = field(default_factory=list)
    exit_code: int | None = None
    raw_output: str = ""
    stderr: str = ""
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ms: int | None = None
    outcome: str = "completed"  # completed | timeout | cancelled | error


class RunRecorder:
    """Per-scan audit capture: one RunnerRecord per tool invocation.

    Thread-safe: the runner closure is called from the scan's worker
    thread; records are read back when the run finishes.
    """

    def __init__(self) -> None:
        self._records: dict[str, list[RunnerRecord]] = {}
        self._lock = threading.Lock()

    def add(self, tool: str, record: RunnerRecord) -> None:
        with self._lock:
            self._records.setdefault(tool, []).append(record)

    def records_for(self, tool: str) -> list[RunnerRecord]:
        with self._lock:
            return list(self._records.get(tool, []))


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Terminate the process group (POSIX) or the process (Windows)."""
    try:
        if os.name == "posix":
            import signal

            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the process group (POSIX) or the process (Windows)."""
    try:
        if os.name == "posix":
            import signal

            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _spill(full_stdout: str, spill_dir: str | None) -> str | None:
    """Write full stdout to a backend-controlled path when truncation
    occurred. Paths come from trusted internal identifiers (UUIDs)."""
    if spill_dir is None or not full_stdout:
        return None
    try:
        d = os.path.join(spill_dir, "subprocess_stdout.txt")
        os.makedirs(os.path.dirname(d), exist_ok=True)
        with open(d, "w", encoding="utf-8", errors="replace") as f:
            f.write(full_stdout)
        return d
    except OSError:
        return None


def make_cancelling_runner(
    cancel_event: threading.Event,
    spill_dir: str | None = None,
    recorder: RunRecorder | None = None,
) -> Callable[..., SubprocessResult]:
    """Build a runner compatible with the real tools' RunnerFn contract:

        runner(executable, args, timeout_s=...) -> SubprocessResult
    """

    def runner(
        executable: str, args: list[str], timeout_s: float = 60, **_kwargs: Any
    ) -> SubprocessResult:
        started_at = datetime.now(timezone.utc)
        argv = [executable, *list(args)]
        record = RunnerRecord(argv=list(argv), started_at=started_at)

        popen_kwargs: dict[str, Any] = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            shell=False,
            env=sanitized_env(),
        )
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True  # own process group

        try:
            proc = subprocess.Popen(argv, **popen_kwargs)
        except FileNotFoundError:
            record.outcome = "error"
            record.ended_at = datetime.now(timezone.utc)
            record.stderr = f"executable not found: {executable!r}"
            _finish_record(record)
            if recorder is not None:
                recorder.add(executable, record)
            return SubprocessResult(
                stdout="",
                stderr=record.stderr,
                returncode=127,
            )
        except (PermissionError, OSError) as exc:
            record.outcome = "error"
            record.ended_at = datetime.now(timezone.utc)
            record.stderr = f"executable could not be started: {exc}"
            _finish_record(record)
            if recorder is not None:
                recorder.add(executable, record)
            return SubprocessResult(
                stdout="",
                stderr=record.stderr,
                returncode=126,
            )

        deadline = time.monotonic() + float(timeout_s)
        timed_out = False
        cancelled = False
        while True:
            if cancel_event.is_set():
                cancelled = True
                record.outcome = "cancelled"
                _terminate_tree(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                record.outcome = "timeout"
                _terminate_tree(proc)
                break
            if proc.poll() is not None:
                break
            time.sleep(POLL_INTERVAL_S)

        # Reap: read remaining output; escalate to kill if the grace
        # period expires (terminate -> grace -> kill -> reap).
        out: str = ""
        err: str = ""
        try:
            out, err = proc.communicate(timeout=GRACE_PERIOD_S)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            try:
                out, err = proc.communicate(timeout=1.0)
            except (subprocess.TimeoutExpired, ValueError):
                out, err = "", ""

        out_capped, t1 = truncate_output(out or "")
        err_capped, t2 = truncate_output(err or "")
        truncated = t1 or t2
        record.ended_at = datetime.now(timezone.utc)
        record.exit_code = proc.returncode
        record.raw_output = out_capped
        record.stderr = err_capped
        _finish_record(record)
        if recorder is not None:
            recorder.add(executable, record)

        if cancelled:
            return SubprocessResult(
                stdout=out_capped,
                stderr=err_capped + "\n[cancelled by request]",
                returncode=-1,
                timed_out=False,
                truncated=truncated,
            )
        if timed_out:
            return SubprocessResult(
                stdout=out_capped,
                stderr=err_capped,
                returncode=-1,
                timed_out=True,
                truncated=truncated,
                spill_path=_spill(out or "", spill_dir),
            )
        return SubprocessResult(
            stdout=out_capped,
            stderr=err_capped,
            returncode=proc.returncode if proc.returncode is not None else -1,
            timed_out=False,
            truncated=truncated,
            spill_path=_spill(out or "", spill_dir) if truncated else None,
        )

    return runner


def _finish_record(record: RunnerRecord) -> None:
    if record.started_at is not None and record.ended_at is not None:
        delta = (record.ended_at - record.started_at).total_seconds()
        record.duration_ms = max(0, int(delta * 1000))
