"""CLI demo: run the complete foundation locally, no API key, no network.

    python -m agent_core --target demo.local --list-tools
    python -m agent_core --target demo.local
    python -m agent_core --goal "..." --target demo.local --max-steps 6

A real model backend is opt-in only (M3-C): --provider openai_compatible
with AICYBERSEC_MODEL_BASE_URL / AICYBERSEC_MODEL_NAME set. Mock/scripted
remains the default so the demo never needs credentials or network.
"""
from __future__ import annotations

import argparse
import sys

from agent_core.planner import ModelPlanner, ScriptedPlanner
from agent_core.providers.factory import build_provider
from agent_core.runtime import AgentRuntime, InMemorySink, PrinterSink
from agent_core.safety.policy import policy_from_env
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.nmap import NmapTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.registry import ToolRegistry


def build_default_registry() -> ToolRegistry:
    """The composition root for the CLI (backend builds its own in deps.py)."""
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(NmapTool())
    registry.register(HTTPXTool())
    registry.register(NucleiTool())
    return registry


def build_planner(registry: ToolRegistry, target: str, provider_name: str | None = None):
    """Select the planner from config (M3-C).

    Default is the deterministic ScriptedPlanner (mock path, offline).
    ``openai_compatible`` (env AICYBERSEC_MODEL_PROVIDER or --provider)
    builds a real provider + ModelPlanner; endpoint credentials come
    from the environment, never from code. SafetyValidator still owns
    every authorization decision downstream.
    """
    from agent_core.config import get_settings

    settings = get_settings()
    if provider_name is not None:
        settings = settings.model_copy(update={"model_provider": provider_name})
    name = str(settings.model_provider or "mock").strip().lower()
    if name == "openai_compatible":
        provider = build_provider(settings)
        print(f"  planner: ModelPlanner via {type(provider).__name__}")
        return ModelPlanner(provider, registry, allowed_targets=[target])
    return ScriptedPlanner(ScriptedPlanner.demo_script(target))


def run_demo(
    goal: str,
    target: str,
    runs_dir: str,
    max_steps: int,
    sinks: list | None = None,
    provider_name: str | None = None,
) -> dict:
    """Assemble the full pipeline and run it. Returns the final state dict."""
    registry = build_default_registry()
    policy = policy_from_env(
        allowed_targets=[target],
        max_steps=max_steps,
        max_danger="active_scan",
        mode="recon",
    )
    validator = SafetyValidator(registry, policy)
    store = JsonFileStore(runs_dir)
    planner = build_planner(registry, target, provider_name)
    sinks = sinks if sinks is not None else [PrinterSink(), InMemorySink()]

    runtime = AgentRuntime(
        planner=planner,
        registry=registry,
        validator=validator,
        store=store,
        events=sinks,
        policy=policy,
    )
    state = runtime.run(goal)
    return state.model_dump(mode="json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agent_core",
        description="AICybersec agent foundation demo (fully local, mock-first)",
    )
    parser.add_argument(
        "--goal",
        default="Perform a basic reconnaissance of the target and report findings.",
    )
    parser.add_argument("--target", default="demo.local", help="allowed target")
    parser.add_argument(
        "--runs-dir", default=None, help="where state/trajectory files go"
    )
    parser.add_argument("--max-steps", type=int, default=6)
    parser.add_argument(
        "--provider",
        default=None,
        choices=["mock", "openai_compatible"],
        help="planner backend (default: env AICYBERSEC_MODEL_PROVIDER or mock)",
    )
    parser.add_argument(
        "--list-tools", action="store_true", help="print registered tool specs and exit"
    )
    args = parser.parse_args(argv)

    from agent_core.config import get_settings

    runs_dir = args.runs_dir or get_settings().runs_dir

    if args.list_tools:
        registry = build_default_registry()
        import json

        print(json.dumps([s.model_dump() for s in registry.schemas()], indent=2))
        return 0

    print("AICybersec agent foundation - demo run")
    print(f"  goal: {args.goal}")
    print(f"  target (allowlist): {args.target}")
    print(f"  runs dir: {runs_dir}")
    print()

    try:
        final = run_demo(
            goal=args.goal,
            target=args.target,
            runs_dir=runs_dir,
            max_steps=args.max_steps,
            provider_name=args.provider,
        )
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    print()
    print(f"  run id : {final['run_id']}")
    print(f"  status : {final['status']}")
    print(f"  steps  : {final['step']}")
    print(f"  findings: {len(final['findings'])}")
    for f in final["findings"]:
        print(f"    - [{f['severity']}] {f['title']}")
    print()
    print(f"  state.json and trajectory.jsonl written under {runs_dir}/{final['run_id']}/")
    return 0 if final["status"] == "finished" else 1


if __name__ == "__main__":
    sys.exit(main())
