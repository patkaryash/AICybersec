"""Unit tests: SubfinderTool (mocked runner + fake resolver, no binary/network)."""
from __future__ import annotations

import json
import threading

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subfinder import (
    SubfinderParams,
    SubfinderTool,
    build_subfinder_argv,
    verify_hosts,
)
from agent_core.tools.subprocess import SubprocessResult


def _line(host: str, source: str = "crtsh", **extra) -> str:
    return json.dumps({"host": host, "input": "example.com", "source": source, **extra})


LINE_OK = "\n".join(
    [
        _line("api.example.com"),
        _line("dev.example.com", source="github"),
    ]
)


def _ctx(targets=("example.com",), **kw):
    return ToolContext(run_id="t", allowed_targets=list(targets), timeout_s=5, **kw)


def _resolver_of(mapping: dict):
    def resolve(hostname: str) -> list[str]:
        return list(mapping.get(hostname, []))

    return resolve


class TestParams:
    def test_valid_domain_normalized(self):
        assert SubfinderParams(domain="Example.COM.").domain == "example.com"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "http://example.com",
            "https://example.com/x",
            "user@example.com",
            "*.example.com",
            "*",
            "-bad.com",
            "--flag",
            "-d",
            "example.com,other.com",
            "exam ple.com",
            "a;b",
            "a|b",
            "a&b",
            "$(id)",
            "`id`",
            "a\nb",
            "10.0.0.5",
            "2001:db8::1",
            "a" * 254,
            "bad..dots",
        ],
    )
    def test_invalid_domains_rejected(self, bad: str):
        with pytest.raises(ValidationError):
            SubfinderParams(domain=bad)

    def test_extra_keys_forbidden(self):
        with pytest.raises(ValidationError):
            SubfinderParams(domain="example.com", sources=["crtsh"])  # type: ignore[call-arg]


class TestArgv:
    def test_exact_fixed_argv(self):
        argv = build_subfinder_argv(SubfinderParams(domain="example.com"))
        assert argv == [
            "subfinder",
            "-d",
            "example.com",
            "-silent",
            "-nc",
            "-json",
            "-timeout",
            "30",
            "-max-time",
            "5",
            "-duc",
        ]

    def test_no_dangerous_flags_exposable(self):
        argv = build_subfinder_argv(SubfinderParams(domain="example.com"))
        for forbidden in ("-o", "-oD", "-dL", "-pc", "-config", "-r", "-s", "-es",
                          "-all", "-recursive", "-cs", "-ip", "-oI", "-m", "-f",
                          "-rls", "-stats", "-silent protected", "|", ";", "$("):
            assert forbidden not in argv
        assert SubfinderTool.danger_level == "safe"

    def test_policy_target_hook(self):
        tool = SubfinderTool()
        assert tool.policy_target({"domain": "example.com"}) == "example.com"
        assert tool.policy_target({}) is None
        assert tool.policy_target({"domain": 123}) is None


class TestExecute:
    def test_success_with_verification(self):
        def runner(exe, args, timeout_s, spill_dir=None):
            assert exe == "subfinder"
            assert args[:2] == ["-d", "example.com"]
            assert "-json" in args and "-duc" in args
            return SubprocessResult(stdout=LINE_OK, stderr="", returncode=0)

        tool = SubfinderTool(
            runner=runner, resolver=_resolver_of({"api.example.com": ["93.184.216.34"]})
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx())
        assert res.status == "ok"
        assert res.findings == []
        assert res.data["domain"] == "example.com"
        by_host = {s["host"]: s for s in res.data["subdomains"]}
        assert by_host["api.example.com"]["verification_status"] == "resolved"
        assert by_host["api.example.com"]["dns_a"] == ["93.184.216.34"]
        assert by_host["dev.example.com"]["verification_status"] == "unverified"
        assert "dns_a" not in by_host["dev.example.com"]
        assert res.data["verified_count"] == 1
        assert res.data["unverified_count"] == 1
        assert res.data["skipped"] == 0 and res.data["filtered"] == 0
        assert "2 subdomain" in res.summary

    def test_subfinder_reported_ip_never_trusted(self):
        # The binary claims an IP; our resolver says nothing resolves.
        out = _line("api.example.com", ip="6.6.6.6")
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout=out, stderr="", returncode=0),
            resolver=_resolver_of({}),
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx())
        sub = res.data["subdomains"][0]
        assert sub["verification_status"] == "unverified"
        assert "dns_a" not in sub

    def test_promotion_filtering_in_tool(self):
        out = "\n".join(
            [
                _line("api.example.com"),
                _line("example.com"),  # root itself
                _line("API.EXAMPLE.COM."),  # dup after normalize
                _line("evil-example.com"),
                _line("example.com.evil.com"),
                _line("*.example.com"),
                _line("not a host!!"),
                "garbage line",
            ]
        )
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout=out, stderr="", returncode=0),
            resolver=_resolver_of({}),
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx())
        assert res.status == "ok"
        assert [s["host"] for s in res.data["subdomains"]] == ["api.example.com"]
        assert res.data["skipped"] == 1  # the garbage line
        assert res.data["filtered"] == 6

    def test_empty_output_is_clean_not_error(self):
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout="", stderr="", returncode=0),
            resolver=_resolver_of({}),
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx())
        assert res.status == "ok"
        assert res.data["subdomains"] == []
        assert "no subdomains discovered" in res.summary

    def test_all_garbage_output_is_empty_not_error(self):
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout="boom\njunk\n", stderr="", returncode=0),
            resolver=_resolver_of({}),
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx())
        assert res.status == "ok" and res.data["subdomains"] == []
        assert res.data["skipped"] == 2

    def test_tool_errors(self):
        err = SubfinderTool(runner=lambda *a, **k: SubprocessResult("", "boom", 1))
        r = err.execute(SubfinderParams(domain="example.com"), _ctx())
        assert r.status == "error" and r.findings == []
        missing = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult("", "executable not found", 127)
        )
        r2 = missing.execute(SubfinderParams(domain="example.com"), _ctx())
        assert r2.status == "error"
        to = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult("", "", -1, timed_out=True)
        )
        assert to.execute(SubfinderParams(domain="example.com"), _ctx()).status == "timeout"

    def test_in_tool_allowlist_recheck(self):
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout=LINE_OK, stderr="", returncode=0),
            resolver=_resolver_of({}),
        )
        r = tool.execute(SubfinderParams(domain="example.com"), _ctx(targets=("other.com",)))
        assert r.status == "error" and "not in the allowed targets list" in r.summary

    def test_cancelled_context_skips_verification(self):
        calls: list = []

        def resolver(hostname: str):
            calls.append(hostname)
            return ["1.2.3.4"]

        ev = threading.Event()
        ev.set()
        tool = SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout=LINE_OK, stderr="", returncode=0),
            resolver=resolver,
        )
        res = tool.execute(SubfinderParams(domain="example.com"), _ctx(cancel=ev))
        assert res.status == "ok"
        assert calls == []
        assert all(s["verification_status"] == "unverified" for s in res.data["subdomains"])


class TestVerifyHosts:
    def test_respects_cancel(self):
        ev = threading.Event()
        ev.set()
        assert verify_hosts(["a.example.com"], _resolver_of({"a.example.com": ["1.1.1.1"]}), cancel=ev) == {}

    def test_timeout_means_unverified(self):
        import time

        def slow(hostname: str):
            time.sleep(30)
            return ["1.1.1.1"]

        out = verify_hosts(["a.example.com"], slow, per_host_s=0.2, workers=1)
        assert out == {}

    def test_resolver_exception_means_unverified(self):
        def boom(hostname: str):
            raise RuntimeError("dns down")

        assert verify_hosts(["a.example.com"], boom) == {}

    def test_cap(self):
        hosts = [f"h{i}.example.com" for i in range(150)]
        out = verify_hosts(hosts, lambda h: ["1.1.1.1"], max_hosts=100, workers=4)
        assert len(out) == 100


class TestValidatorIntegration:
    def _validator(self, allowed=("example.com",)):
        reg = ToolRegistry()
        reg.register(SubfinderTool(runner=lambda *a, **k: SubprocessResult("", "", 0)))
        policy = Policy(allowed_targets=list(allowed), max_danger="active_scan", max_steps=6)
        return SafetyValidator(reg, policy), AgentState(run_id="t", goal="g", max_steps=6)

    def test_authorized_domain_accepted(self):
        v, state = self._validator()
        out = v.validate(ToolCall(tool="subfinder", params={"domain": "example.com"}), state)
        assert out.accepted

    def test_subdomain_as_domain_rejected(self):
        v, state = self._validator()
        out = v.validate(ToolCall(tool="subfinder", params={"domain": "api.example.com"}), state)
        assert not out.accepted and "not in the allowed targets list" in out.reason

    def test_out_of_scope_domain_rejected(self):
        v, state = self._validator()
        out = v.validate(ToolCall(tool="subfinder", params={"domain": "evil.com"}), state)
        assert not out.accepted

    def test_runner_not_called_on_rejection(self):
        calls: list = []
        reg = ToolRegistry()

        def spy(exe, args, timeout_s, spill_dir=None):
            calls.append(args)
            return SubprocessResult("", "", 0)

        reg.register(SubfinderTool(runner=spy))
        v = SafetyValidator(reg, Policy(allowed_targets=["example.com"]))
        state = AgentState(run_id="t", goal="g")
        out = v.validate(ToolCall(tool="subfinder", params={"domain": "evil.com"}), state)
        assert not out.accepted and calls == []
