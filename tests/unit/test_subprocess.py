"""Unit tests: controlled subprocess runner (mocked subprocess, no binaries)."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from agent_core.tools import subprocess as sp


def _completed(stdout="", stderr="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_success(monkeypatch):
    monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: _completed("out", ""))
    assert k_called(monkeypatch) is True
    monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: _completed("hello", ""))
    res = sp.run_pinned_binary("nmap", ["-oX", "-", "demo.local"], timeout_s=5)
    assert res.returncode == 0 and res.stdout == "hello" and not res.timed_out


def k_called(monkeypatch):
    """Assert shell=False and argv list (no shell string)."""
    seen = {}

    def fake(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _completed("x", "")

    monkeypatch.setattr(sp.subprocess, "run", fake)
    sp.run_pinned_binary("nmap", ["-oX", "-", "t"], timeout_s=5)
    assert seen["argv"] == ["nmap", "-oX", "-", "t"]
    assert seen["kwargs"].get("shell") is False
    assert isinstance(seen["argv"], list)
    return True


def test_nonzero_exit_is_data(monkeypatch):
    monkeypatch.setattr(
        sp.subprocess, "run", lambda *a, **k: _completed("", "boom", 2)
    )
    res = sp.run_pinned_binary("nmap", ["x"], timeout_s=5)
    assert res.returncode == 2 and res.stderr == "boom" and not res.timed_out


def test_timeout(monkeypatch):
    def fake(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=5, output="partial", stderr="e")

    monkeypatch.setattr(sp.subprocess, "run", fake)
    res = sp.run_pinned_binary("nmap", ["x"], timeout_s=5)
    assert res.timed_out is True and "partial" in res.stdout


def test_missing_executable(monkeypatch):
    def fake(*a, **k):
        raise FileNotFoundError("nope")

    monkeypatch.setattr(sp.subprocess, "run", fake)
    res = sp.run_pinned_binary("nmap", ["x"], timeout_s=5)
    assert res.returncode == 127 and "not found" in res.stderr


def test_truncation_and_spill(tmp_path, monkeypatch):
    big = "\n".join(f"line {i}" for i in range(2500))
    monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: _completed(big, ""))
    res = sp.run_pinned_binary("nmap", ["x"], timeout_s=5, spill_dir=tmp_path)
    assert res.truncated is True
    assert "truncated" in res.stdout
    assert res.spill_path is not None
    assert "line 0" in open(res.spill_path, encoding="utf-8").read()


def test_rejects_command_string():
    import pytest

    with pytest.raises(ValueError):
        sp.run_pinned_binary("nmap -oX - demo.local", [], timeout_s=5)
    with pytest.raises(ValueError):
        sp.run_pinned_binary("nmap", "not-a-list", timeout_s=5)  # type: ignore[arg-type]
