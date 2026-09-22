# AICybersec

AI-assisted penetration-testing platform (academic major project). This
repository currently contains the **agent foundation**: a modular,
mock-first agent core that runs entirely offline, plus a minimal FastAPI
backend exposing it over HTTP/SSE.

> **Status:** foundation only. No real security tools (nmap/httpx/nuclei/
> ZAP), no external LLM, no exploitation, no browser automation, no
> model training yet. Everything runs on mocks and scripted decisions.

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
  tools/        Tool ABC, ToolContext, ToolRegistry, mock tools
  safety/       Policy + two-stage SafetyValidator
  runtime/      AgentRuntime loop + event system
  state/        JsonFileStore (state.json + trajectory.jsonl)
backend/        FastAPI adapter: deps.py (composition root), routes/, SSE
frontend/       NOT built yet - README documents the API/event contract
tests/          unit / integration / contracts / api (all offline)
docs/           architecture.md
runs/           gitignored runtime output (state.json, trajectory.jsonl)
```

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
