# AICybersec

AI-assisted penetration-testing platform (academic major project). This
repository currently contains the **agent foundation**: a modular,
mock-first agent core that runs entirely offline, plus a minimal FastAPI
backend exposing it over HTTP/SSE.

> **Status:** foundation + three real tools (nmap, httpx, nuclei) + model
> planner. No external LLM wired by default, no exploitation, no browser
> automation, no model training yet. Mock tools and MockModelProvider still
> work; real tools run as controlled subprocesses against allowlisted
> targets only.

## Architecture (text diagram)

```
Frontend (separate, not built yet)
        |  REST + SSE
        v
FastAPI backend  (backend/)          <- HTTP only, composition root
        |  in-process
        v
AgentRuntime (agent_core/runtime)    <- decide -> validate -> execute loop
   |          \__________________
   v                             v
Planner                    SafetyValidator
(scripted now,             (schema stage + policy stage)
 model-backed later)             |
   |                             v
   |  Decision (tool_call|finish, JSON)  ->  ToolRegistry (whitelist)
   |                                             |
   v                                             v
ModelProvider (protocol,                Tool.execute(validated params)
 mock now; your trained                          |
 model later plugs in here)                      v
                                           ToolResult -> Observation
                                                 |
                                                 v
                                    AgentState (persisted state.json)
                                    Trajectory (trajectory.jsonl)
                                    Events -> SSE -> Frontend
```

See `docs/architecture.md` for the detailed boundary rationale.

## Repository structure

```
agent_core/     Pure agent library. No FastAPI, no HTTP, no shell tool.
  schemas/      Shared contracts (Decision, ToolSpec, Finding, AgentState...)
  providers/    ModelProvider protocol + mock (future model plugs in here)
  planner/      Planner protocol + ScriptedPlanner (deterministic demo)
  tools/        Tool ABC, ToolContext, ToolRegistry, mock tools,
                subprocess.py (pinned-binary runner), nmap.py + nmap_parser.py
  safety/       Policy + two-stage SafetyValidator
  runtime/      AgentRuntime loop + event system
  state/        JsonFileStore (state.json + trajectory.jsonl)
backend/        FastAPI adapter: deps.py (composition root), routes/, SSE
frontend/       NOT built yet - README documents the API/event contract
tests/          unit / integration / contracts / api (all offline)
docs/           architecture.md
runs/           gitignored runtime output (state.json, trajectory.jsonl)
```

## Nmap (M1 - first real tool)

Authorized targets only. `nmap` is invoked as a controlled subprocess:

- No `shell=True`, no raw command strings; target is a separate argv element.
- Fixed argv per profile, XML stdout (`-oX -`) parsed with stdlib only.
- `NmapParams{target, ports="top-1000", profile="safe"|"version"|"os"|"vuln"}`
  (`ports` is `top-<n>` or `80,443`/`1-1024`; arbitrary flags rejected).
- Reconnaissance only: no vulnerability Findings are manufactured.
- Every call still passes `Decision -> SafetyValidator -> ToolRegistry`.

Check/install Nmap locally (optional - tests never require it):

```bash
nmap --version
# Windows: winget install Insecure.Nmap  |  Debian/Ubuntu: sudo apt install nmap
python -m agent_core --target 127.0.0.1 --list-tools  # shows "nmap"
```

## HTTPX (M2-A - second real tool)

Purpose: HTTP/service reconnaissance (status, title, server, tech, TLS).
Authorized targets only, through the same controlled subprocess layer:

- No `shell=True`, no raw command strings; each target is a separate
  `-u <target>` argv value.
- Fixed argv, JSONL stdout (`-json`) parsed per-line; only agent-relevant
  fields retained (raw httpx JSON never enters model context).
- `HTTPXParams{targets: list[str]}` (max 20, validated; arbitrary flags rejected).
- `danger_level=safe`. Reconnaissance only: `findings=[]`.
- EVERY target in `targets` must pass the allowlist before execution.

Check/install HTTPX locally (optional - tests never require it):

```bash
httpx -version
# Go: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
python -m agent_core --target demo.local --list-tools  # shows "httpx"
```

## Nuclei (M2-B - controlled vulnerability scanning)

Purpose: template-based vulnerability checks against authorized targets.
Same controlled subprocess layer, no arbitrary commands:

- No `shell=True`, no raw command strings; each target is a separate
  `-target <target>` argv value.
- Fixed profile, JSONL stdout (`-jsonl`) parsed per-line into `Finding`
  objects (`tool="nuclei"`); raw nuclei JSON never enters model context.
- `NucleiParams{targets: list[str]}` (max 20, validated; arbitrary flags rejected).
- `danger_level=active_scan`. EVERY target must pass the allowlist before
  execution; empty output is a valid clean result (`findings=[]`).
- Arbitrary command execution is not supported by design.

Check/install Nuclei locally (optional - tests never require it):

```bash
nuclei -version
# Go: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Templates (out of band): nuclei -update-templates
python -m agent_core --target demo.local --list-tools  # shows "nuclei"
```

## ModelPlanner (M3-A - model decision layer)

The model proposes; safety disposes. `ModelPlanner` implements the existing
`Planner` interface, so `AgentRuntime` is unchanged:

```
structured state (goal, recent observations, findings, tool specs, scope)
  → ModelProvider.generate() → raw JSON text (never trusted)
  → parse_decision() → typed ToolCall | Finish (fail-closed)
  → SafetyValidator → ToolRegistry → Tool
```

- The request is bounded (recent observations, capped data/strings) and
  carries no raw scanner dumps, binaries, or shell syntax.
- Malformed JSON, schema violations, and provider failures raise
  `ModelPlannerError`; the runtime fails the run without executing anything.
- Tests use `MockModelProvider` (queued deterministic responses). A minimal
  stdlib-only `OpenAICompatibleProvider` exists for later wiring; no API key
  or network is required for CI.

## M3-C - controlled real model integration

M3-A's planner can now talk to a real OpenAI-compatible endpoint
(Ollama, LM Studio, vLLM, or any `/chat/completions` server) through the
unchanged `ModelProvider` interface. The model still only proposes;
`SafetyValidator` still authorizes every call.

```bash
# Local server example (Ollama); keys stay in the environment, never in code.
export AICYBERSEC_MODEL_PROVIDER=openai_compatible
export AICYBERSEC_MODEL_BASE_URL=http://localhost:11434/v1
export AICYBERSEC_MODEL_NAME=qwen2.5:14b
export AICYBERSEC_MODEL_API_KEY=   # empty for local servers
python -m agent_core --target demo.local --provider openai_compatible
```

- Selection is config-driven (`agent_core/providers/factory.py:build_provider`);
  default remains mock/scripted, so tests and demos never need credentials.
- Completions are capped (`AICYBERSEC_MODEL_MAX_RESPONSE_CHARS`, default 8000);
  requests carry the same bounded, normalized context as M3-A.
- `tests/integration/test_live_model.py` is the opt-in live smoke test
  (`AICYBERSEC_LIVE_MODEL_TEST=1`); it is skipped in CI.

## M3-B - deterministic end-to-end evaluation

`tests/integration/test_autonomous_loop.py` proves the architecture runs a
multi-step planner-driven workflow with `MockModelProvider` only:

```
ModelPlanner → SafetyValidator → nmap → Observation
→ ModelPlanner → SafetyValidator → httpx → Observation
→ ModelPlanner → SafetyValidator → nuclei → Observation
→ ModelPlanner → Finish
```

No real LLM, no network, no binaries: model responses are queued FIFO and
tool runners are mocked. Safety stays outside the model (an evil-target
proposal is rejected, never executed), and the existing `max_steps` guard
stops a planner that never finishes. This is an architecture evaluation,
not an autonomous production deployment.

## Setup

```bash
python -m venv .venv
source .venv/Scripts/activate      # Windows (bash)  |  Linux: .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.11+. No API keys, no environment variables required.

## Run the demo (no LLM, no network)

```bash
python -m agent_core --target demo.local
python -m agent_core --target demo.local --list-tools   # print ToolSpecs
python -m agent_core --goal "custom goal" --target demo.local --max-steps 6
```

You will see: goal -> tool call -> validation -> mock tool -> findings ->
second tool -> finish, plus `runs/<run_id>/state.json` and
`runs/<run_id>/trajectory.jsonl`.

## Run tests

```bash
python -m pytest
```

All tests are offline: no API keys, no network, no real security tools.

## Start the backend

```bash
uvicorn backend.main:app --reload
# then:
#   curl -X POST localhost:8000/runs -H "Content-Type: application/json" \
#        -d '{"goal": "recon", "targets": ["demo.local"]}'
#   curl localhost:8000/runs/<run_id>
#   curl -N localhost:8000/runs/<run_id>/events
# interactive docs: http://localhost:8000/docs
```

The API works without an LLM: the backend wires the scripted planner and
mock tools (see `backend/deps.py`).

## Development workflow

- See `CONTRIBUTING.md` for branch/PR rules and ownership boundaries.
- Shared contracts live in `agent_core/schemas/` - all three components
  depend on them; change carefully and with tests.
- Adding a new tool = one new file implementing `Tool` + one registration
  line in the composition root + a contract test. No core changes.

## Security / authorization note

This platform is being built **for authorized security testing in
controlled lab environments only**. The architecture enforces this stance
by design:

- The agent has **no shell tool** and no arbitrary command execution.
- Tools are reachable **only** through the registered `Tool` whitelist.
- Every model decision is validated (schema + policy) before execution;
  rejections never execute.
- Target **allowlists** are enforced by policy and injected into the tool
  context; tools cannot widen them.
- Runs are limited by `max_steps`, a danger-level cap, and cancellation.

Users are responsible for operating the platform only against systems
they are explicitly authorized to test.
