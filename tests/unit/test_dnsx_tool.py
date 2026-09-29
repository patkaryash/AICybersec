"""Unit tests: DNSXTool (mocked runner, no binary/network)."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.base import ToolContext
from agent_core.tools.dnsx import DNSXParams, DNSXTool, build_dnsx_argv
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult


def _line(host: str, **fields) -> str:
    return json.dumps({"host": host, **fields})


LINE_A = _line("api.example.com", a=["93.184.216.34"])
LINE_AAAA = _line("api.example.com", aaaa=["2606:2800:220:1:248:1893:25c8:1946"])
LINE_CNAME = _line("cdn.example.com", cname=["cdn.provider.net"])


def _ctx(targets=("api.example.com",)):
    return ToolContext(run_id="t", allowed_targets=list(targets), timeout_s=5)


class TestArgv:
    def test_exact_fixed_argv(self):
        argv = build_dnsx_argv(DNSXParams(targets=["api.example.com"]))
        assert argv == [
            "dnsx",
            "-json",
            "-silent",
            "-nc",
            "-duc",
            "-timeout",
            "3s",
            "-retry",
            "1",
            "-threads",
            "25",
            "-a",
            "-aaaa",
            "-cname",
            "-omit-raw",
            "-l",
            "api.example.com",
        ]

    def test_comma_list_single_element(self):
        argv = build_dnsx_argv(
            DNSXParams(targets=["a.example.com", "b.example.com", "c.example.com"])
        )
        assert argv[-2:] == ["-l", "a.example.com,b.example.com,c.example.com"]

    def test_version_flags_present(self):
        argv = build_dnsx_argv(DNSXParams(targets=["a.example.com"]))
        for flag, value in (("-timeout", "3s"), ("-retry", "1"), ("-threads", "25")):
            assert flag in argv and value in argv
        for flag in ("-json", "-silent", "-nc", "-duc", "-a", "-aaaa", "-cname", "-omit-raw"):
            assert flag in argv
        assert DNSXTool.danger_level == "safe"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "-r", "-resolver", "-axfr", "-trace", "-recon", "-all", "-any",
            "-d", "-domain", "-w", "-wordlist", "-proxy", "-resp", "-resp-only",
            "-raw", "-debug", "-cdn", "-asn", "-wd", "-wildcard-domain",
            "-auto-wildcard", "-o", "-output", "-stats", "-stream", "-resume",
            "-hostsfile", "-e", "-exclude-type", "-rl", "-rate-limit",
            "-ot", "-output-template", "-v", "-verbose", "-rc", "-rcode",
            "|", ";", "$(",
        ],
    )
    def test_forbidden_flags_absent(self, forbidden: str):
        argv = build_dnsx_argv(DNSXParams(targets=["api.example.com"]))
        assert forbidden not in argv

    def test_policy_targets_hook(self):
        tool = DNSXTool()
        assert tool.policy_targets({"targets": ["a.example.com"]}) == ["a.example.com"]
        assert tool.policy_targets({}) == []
        assert tool.policy_targets({"targets": "nope"}) == [None]


class TestParams:
    def test_one_target(self):
        assert DNSXParams(targets=["api.example.com"]).targets == ["api.example.com"]

    def test_target_normalized(self):
        assert DNSXParams(targets=["API.Example.COM."]).targets == ["api.example.com"]

    def test_twenty_targets_ok(self):
        params = DNSXParams(targets=[f"h{i}.example.com" for i in range(20)])
        assert len(params.targets) == 20

    def test_more_than_twenty_rejected(self):
        with pytest.raises(ValidationError):
            DNSXParams(targets=[f"h{i}.example.com" for i in range(21)])

    @pytest.mark.parametrize(
        "bad",
        [
            "http://api.example.com",
            "https://api.example.com/x",
            "10.0.0.5",
            "2001:db8::1",
            "*.example.com",
            "*",
            "-target",
            "--flag",
            "api,example.com",
            "ta rget",
            "a;b",
            "a|b",
            "a&b",
            "$(id)",
            "`id`",
            "a\nb",
            "user@example.com",
            "api.example.com:8080",
            "api.example.com/path",
            "bad..dots",
            "",
            "   ",
            "a" * 254,
        ],
    )
    def test_invalid_targets_rejected(self, bad: str):
        with pytest.raises(ValidationError):
            DNSXParams(targets=[bad])

    def test_empty_list_rejected(self):
        with pytest.raises(ValidationError):
            DNSXParams(targets=[])

    def test_extra_keys_forbidden(self):
        with pytest.raises(ValidationError):
            DNSXParams(targets=["a.example.com"], resolvers=["8.8.8.8"])  # type: ignore[call-arg]


class TestExecute:
    def test_success_a_record(self):
        def runner(exe, args, timeout_s, spill_dir=None):
            assert exe == "dnsx"
            assert args[:3] == ["-json", "-silent", "-nc"]
            assert args[-2:] == ["-l", "api.example.com"]
            return SubprocessResult(stdout=LINE_A, stderr="", returncode=0)

        tool = DNSXTool(runner=runner)
        res = tool.execute(DNSXParams(targets=["api.example.com"]), _ctx())
        assert res.status == "ok"
        assert res.findings == []
        assert res.data["targets"] == ["api.example.com"]
        assert res.data["records"][0]["a"] == ["93.184.216.34"]
        assert "1 of 1" in res.summary

    def test_success_aaaa_and_cname(self):
        out = "\n".join([LINE_AAAA, LINE_CNAME])
        tool = DNSXTool(
            runner=lambda *a, **k: SubprocessResult(stdout=out, stderr="", returncode=0)
        )
        res = tool.execute(
            DNSXParams(targets=["api.example.com", "cdn.example.com"]),
            _ctx(targets=("api.example.com", "cdn.example.com")),
        )
        assert res.status == "ok"
        by_host = {r["host"]: r for r in res.data["records"]}
        assert by_host["api.example.com"]["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]
        # CNAME is recorded but never followed: no resolution attempted,
        # no extra record fabricated for the CNAME target.
        assert by_host["cdn.example.com"]["cname"] == ["cdn.provider.net"]
        assert "cdn.provider.net" not in by_host

    def test_dns_ips_remain_observation_data_only(self):
        tool = DNSXTool(
            runner=lambda *a, **k: SubprocessResult(stdout=LINE_A, stderr="", returncode=0)
        )
        res = tool.execute(DNSXParams(targets=["api.example.com"]), _ctx())
        assert res.data["records"][0]["a"] == ["93.184.216.34"]
        # No asset creation, no findings, no allowlist mutation from IPs.
        assert res.findings == []
        assert "93.184.216.34" not in res.data["targets"]

    def test_empty_output_is_clean_not_error(self):
        tool = DNSXTool(
            runner=lambda *a, **k: SubprocessResult(stdout="", stderr="", returncode=0)
        )
        res = tool.execute(DNSXParams(targets=["api.example.com"]), _ctx())
        assert res.status == "ok"
        assert res.data["records"] == []
        assert "no DNS records" in res.summary

    def test_all_garbage_output_is_empty_not_error(self):
        tool = DNSXTool(
            runner=lambda *a, **k: SubprocessResult(stdout="boom\njunk\n", stderr="", returncode=0)
        )
        res = tool.execute(DNSXParams(targets=["api.example.com"]), _ctx())
        assert res.status == "ok" and res.data["records"] == []
        assert res.data["skipped"] == 2

    def test_tool_errors(self):
        err = DNSXTool(runner=lambda *a, **k: SubprocessResult("", "boom", 1))
        r = err.execute(DNSXParams(targets=["api.example.com"]), _ctx())
        assert r.status == "error" and r.findings == []
        missing = DNSXTool(
            runner=lambda *a, **k: SubprocessResult("", "executable not found", 127)
        )
        assert missing.execute(DNSXParams(targets=["api.example.com"]), _ctx()).status == "error"
        to = DNSXTool(
            runner=lambda *a, **k: SubprocessResult("", "", -1, timed_out=True)
        )
        assert to.execute(DNSXParams(targets=["api.example.com"]), _ctx()).status == "timeout"

    def test_in_tool_allowlist_recheck(self):
        tool = DNSXTool(
            runner=lambda *a, **k: SubprocessResult(stdout=LINE_A, stderr="", returncode=0)
        )
        r = tool.execute(DNSXParams(targets=["api.example.com"]), _ctx(targets=("other.com",)))
        assert r.status == "error" and "not in the allowed targets list" in r.summary


class TestValidatorIntegration:
    def _validator(self, allowed=("api.example.com",)):
        reg = ToolRegistry()
        reg.register(DNSXTool(runner=lambda *a, **k: SubprocessResult("", "", 0)))
        policy = Policy(allowed_targets=list(allowed), max_danger="active_scan", max_steps=6)
        return SafetyValidator(reg, policy), AgentState(run_id="t", goal="g", max_steps=6)

    def test_authorized_targets_accepted(self):
        v, state = self._validator()
        out = v.validate(
            ToolCall(tool="dnsx", params={"targets": ["api.example.com"]}), state
        )
        assert out.accepted

    def test_out_of_scope_rejected(self):
        v, state = self._validator()
        out = v.validate(
            ToolCall(tool="dnsx", params={"targets": ["evil.com"]}), state
        )
        assert not out.accepted and "not in the allowed targets list" in out.reason

    def test_one_bad_target_fails_whole_call(self):
        v, state = self._validator()
        out = v.validate(
            ToolCall(tool="dnsx", params={"targets": ["api.example.com", "evil.com"]}), state
        )
        assert not out.accepted

    def test_runner_not_called_on_rejection(self):
        calls: list = []
        reg = ToolRegistry()

        def spy(exe, args, timeout_s, spill_dir=None):
            calls.append(args)
            return SubprocessResult("", "", 0)

        reg.register(DNSXTool(runner=spy))
        v = SafetyValidator(reg, Policy(allowed_targets=["api.example.com"]))
        state = AgentState(run_id="t", goal="g")
        out = v.validate(ToolCall(tool="dnsx", params={"targets": ["evil.com"]}), state)
        assert not out.accepted and calls == []
