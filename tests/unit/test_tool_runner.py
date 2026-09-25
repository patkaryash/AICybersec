"""Unit tests: controlled cancelling runner (mocked Popen, no binaries).

Same pattern as test_subprocess.py: subprocess.Popen is monkeypatched
with fakes; no real binaries, no network. Asserts shell=False, argv
list, cancellation, timeout, output cap, spill paths, env sanitization.
"""
from __future__ import annotations

import threading

import pytest

from backend.services import tool_runner as tr


class _FakePopen:
    """Fake process: controllable lifetime and output."""

    def __init__(self, argv, *, output="out", polls_before_exit=0, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.pid = 424242
        self.output = output
        self._polls = 0
        self._polls_before_exit = polls_before_exit
        self._terminated = False
        self._killed = False
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        self._polls += 1
        if self._polls > self._polls_before_exit:
            self.returncode = 0
        return None

    def terminate(self):
        self._terminated = True
        self.returncode = -1

    def kill(self):
        self._killed = True
        self.returncode = -9

    def communicate(self, timeout=None):
        return (self.output, "some-stderr")


def _runner(monkeypatch, fake_cls=_FakePopen, **fake_kwargs):
    seen = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return fake_cls(argv, **fake_kwargs, **kwargs)

    monkeypatch.setattr(tr.subprocess, "Popen", fake_popen)
    return seen


def test_completion_and_security_contract(monkeypatch):
    seen = _runner(monkeypatch)
    runner = tr.make_cancelling_runner(threading.Event())
    res = runner("nmap", ["-oX", "-", "demo.local"], timeout_s=5)
    # shell=False, argv list, sanitized env
    assert seen["kwargs"].get("shell") is False
    assert isinstance(seen["argv"], list)
    assert seen["argv"] == ["nmap", "-oX", "-", "demo.local"]
    assert set(seen["kwargs"].get("env", {}).keys()) <= set(tr._SANITIZED_ENV_KEYS)
    assert res.returncode == 0 and not res.timed_out and res.stdout == "out"


def test_real_process_cancelled_is_actually_killed(tmp_path):
    """Verification evidence (Phase 3 review §16): cancellation must kill a
    LIVE operating-system process, not merely change database state.

    Real subprocess (the interpreter itself, cross-platform): the child
    proves it started (started.txt), then sleeps, then would write
    survived.txt. Cancel mid-run -> the child must die before finishing
    the sleep -> survived.txt must never appear.
    """
    import sys
    import time as _time

    started = tmp_path / "started.txt"
    survived = tmp_path / "survived.txt"
    child_code = (
        f"import time; open(r'{started}', 'w').write('ok'); "
        f"time.sleep(6); open(r'{survived}', 'w').write('ok')"
    )

    cancel = threading.Event()
    runner = tr.make_cancelling_runner(cancel)
    threading.Timer(0.4, cancel.set).start()

    t0 = _time.monotonic()
    res = runner(sys.executable, ["-c", child_code], timeout_s=60)
    elapsed = _time.monotonic() - t0

    assert "[cancelled by request]" in res.stderr
    assert elapsed < 5, "runner should return promptly after cancel"
    assert started.exists(), "the child process must have actually launched"
    # wait past the child's full sleep: if the kill failed, the child
    # would complete its 6s sleep and write the survivor marker.
    _time.sleep(max(0.0, 7.0 - elapsed))
    assert not survived.exists(), "the live process was NOT killed by cancellation"


def test_cancel_mid_run(monkeypatch):
    _runner(monkeypatch, polls_before_exit=10_000)  # never completes on its own
    cancel = threading.Event()
    runner = tr.make_cancelling_runner(cancel)
    threading.Timer(0.3, cancel.set).start()
    res = runner("nmap", ["-oX", "-", "t"], timeout_s=60)
    assert not res.timed_out
    assert "[cancelled by request]" in res.stderr


def test_timeout_kills_process(monkeypatch):
    fake_cls = _FakePopen
    seen = {}
    proc_holder = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        proc = fake_cls(argv, output="x", polls_before_exit=10_000, **kwargs)
        proc_holder["proc"] = proc
        return proc

    monkeypatch.setattr(tr.subprocess, "Popen", fake_popen)
    runner = tr.make_cancelling_runner(threading.Event())
    res = runner("nmap", ["t"], timeout_s=0.2)
    assert res.timed_out is True
    assert proc_holder["proc"]._terminated or proc_holder["proc"]._killed


def test_output_cap_enforced(monkeypatch):
    _runner(monkeypatch, output="x" * 100_000)
    runner = tr.make_cancelling_runner(threading.Event())
    res = runner("nmap", ["t"], timeout_s=5)
    assert res.truncated is True
    assert len(res.stdout.encode("utf-8")) <= tr.truncate_output.__globals__[
        "MAX_OUTPUT_BYTES"
    ] + 100  # cap + the truncation marker line


def test_spill_path_written_when_truncated(monkeypatch, tmp_path):
    _runner(monkeypatch, output="y" * 100_000)
    runner = tr.make_cancelling_runner(threading.Event(), spill_dir=str(tmp_path / "runs" / "scan-1"))
    res = runner("nmap", ["t"], timeout_s=5)
    assert res.truncated is True
    # backend-controlled path under the trusted scan dir
    assert res.spill_path is not None
    assert str(tmp_path / "runs" / "scan-1") in res.spill_path
    assert res.spill_path.endswith("subprocess_stdout.txt")


def test_no_spill_when_within_cap(monkeypatch, tmp_path):
    _runner(monkeypatch, output="small")
    runner = tr.make_cancelling_runner(threading.Event(), spill_dir=str(tmp_path / "runs" / "scan-1"))
    res = runner("nmap", ["t"], timeout_s=5)
    assert res.truncated is False
    assert res.spill_path is None


def test_missing_executable_rc_127(monkeypatch):
    def fake_popen(argv, **kwargs):
        raise FileNotFoundError("nope")

    monkeypatch.setattr(tr.subprocess, "Popen", fake_popen)
    runner = tr.make_cancelling_runner(threading.Event())
    res = runner("nmap", ["t"], timeout_s=5)
    assert res.returncode == 127
    assert "executable not found" in res.stderr


def test_recorder_captures_audit_data(monkeypatch):
    _runner(monkeypatch, output="audit-out")
    recorder = tr.RunRecorder()
    runner = tr.make_cancelling_runner(threading.Event(), recorder=recorder)
    runner("nmap", ["-oX", "-", "t"], timeout_s=5)
    records = recorder.records_for("nmap")
    assert len(records) == 1
    record = records[0]
    assert record.argv == ["nmap", "-oX", "-", "t"]
    assert record.exit_code == 0
    assert record.raw_output == "audit-out"
    assert record.outcome == "completed"
    assert record.duration_ms is not None


def test_recorder_outcome_cancelled(monkeypatch):
    _runner(monkeypatch, polls_before_exit=10_000)
    cancel = threading.Event()
    recorder = tr.RunRecorder()
    runner = tr.make_cancelling_runner(cancel, recorder=recorder)
    threading.Timer(0.2, cancel.set).start()
    runner("nmap", ["t"], timeout_s=60)
    assert recorder.records_for("nmap")[0].outcome == "cancelled"


def test_run_pinned_binary_never_changed(monkeypatch):
    """The agent_core runner is untouched; the backend runner reuses its
    infrastructure (SubprocessResult, truncate_output)."""
    from agent_core.tools import subprocess as sp

    assert tr.SubprocessResult is sp.SubprocessResult
    assert tr.truncate_output is sp.truncate_output


def test_sanitized_env_excludes_secrets(monkeypatch):
    monkeypatch.setenv("AICYBERSEC_JWT_SECRET", "super-secret-value")
    monkeypatch.setenv("AICYBERSEC_DATABASE_URL", "postgresql://user:pass@host/db")
    monkeypatch.setenv("PATH", "C:/bin")
    env = tr.sanitized_env()
    assert env["PATH"] == "C:/bin"
    assert "AICYBERSEC_JWT_SECRET" not in env
    assert "AICYBERSEC_DATABASE_URL" not in env
    assert "super-secret-value" not in str(env)
