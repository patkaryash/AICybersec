# Architecture

This document explains the boundaries of the AICybersec agent foundation,
why they exist, and how data flows through the system.

## 1. The boundary chain

```
Frontend (not built yet)
    |  REST + SSE
    v
FastAPI backend .......................... backend/
    |  in-process import (no microservice)
    v
AgentRuntime ............................. agent_core/runtime/agent.py
    |
    v
Planner .................................. agent_core/planner/
    |  decide(state) -> Decision
    v
Decision (tool_call | finish, JSON) ...... agent_core/schemas/actions.py
    |
    v
Safety Validator ......................... agent_core/safety/validator.py
    |  stage 1: schema        (does the call parse against the tool's
    |                          Pydantic input model? is the tool known?)
    |  stage 2: policy        (target allowlist, danger cap, max steps,
    |                          extension point for rate limits)
    v
ToolRegistry (whitelist) ................. agent_core/tools/registry.py
    |
    v
Tool.execute(validated_params, ctx) ...... agent_core/tools/base.py
    |
    v
ToolResult ............................... agent_core/schemas/results.py
    |
    v
Observation (normalized, fed back) ....... agent_core/schemas/results.py
    |
    v
AgentState (persisted: state.json) ....... agent_core/schemas/state.py
    |
    v
Events -> SSE ............................ agent_core/runtime/events.py
```

## 2. Why `agent_core` does not depend on FastAPI

`agent_core` is a **pure library**. The dependency arrow points exactly
one way: `backend -> agent_core`, never the reverse.

Consequences of this discipline:

1. **Testability.** The whole agent loop runs in plain Python with
   in-memory sinks and temp directories. No HTTP server is needed to test
   planning, validation, tool execution or persistence.
2. **Replaceability of transport.** If the backend ever changes (CLI,
   gRPC, queue worker), `agent_core` does not change. The CLI demo
   (`python -m agent_core`) already proves this: it is a second "host"
   for the same core.
3. **Replaceability of the model.** `ModelProvider` returns raw text and
   knows nothing about HTTP, tools, or decisions. A future
   OpenAI-compatible client or the team's own trained model implements
   `generate(request) -> ModelResponse` and is selected in the
   composition root (`backend/deps.py` or the CLI). The runtime never
   learns which model is behind the interface.
4. **Safety reviewability.** Every path from "model says something" to
   "something executes" lives in one place (`safety/`), without HTTP
   concerns mixed in. A reviewer can audit the entire execution surface
   by reading three small files.

## 3. Safety model

- **Closed decision space.** A `Decision` is a discriminated union of
  exactly `ToolCall` and `Finish`, with `extra="forbid"`. There is
  nothing else the model can emit and nothing else the runtime executes.
- **No shell tool.** Real security tools (nmap, httpx, nuclei, ZAP) will
  implement the `Tool` interface using **fixed argv construction from
  validated Pydantic parameters**. Arbitrary model-generated strings
  never reach a shell.
- **Whitelist registry.** `ToolRegistry.get()` raises on unknown tools;
  the validator checks membership before execution.
- **Two-stage validation.** Schema errors and policy violations both
  reject before execution; a rejection becomes an `Observation` so the
  planner can react.
- **Host-normalized allowlist.** URL-shaped params are reduced to
  hostnames before allowlist comparison (`Policy.normalize_target`), so
  `http://demo.local:8080/x` is governed by the `demo.local` entry.
- **Injected context.** `ToolContext.allowed_targets` comes from policy;
  tools cannot widen their own permissions.
- **Reasoning is inert.** `ToolCall.reasoning` is recorded for
  trajectory/debugging but is never part of the executable view
  (`decision_validated` in trajectory entries omits it).

## 4. State, trajectory and events

- `AgentState` is the single source of truth for a run. It is plain
  Pydantic and fully JSON-serializable, persisted after every step to
  `runs/<run_id>/state.json`.
- `runs/<run_id>/trajectory.jsonl` gets one JSON line per step:
  `decision_raw` (as proposed, incl. reasoning), `decision_validated`
  (executable content only), rejection info, and the normalized
  observation. This format is designed to become training/evaluation
  data later. Values under secret-looking keys are scrubbed to
  `[REDACTED]` before hitting disk.
- Events are plain dicts with a frozen vocabulary (`run.started`,
  `step.started`, `decision.proposed`, `decision.rejected`,
  `tool.started`, `tool.finished`, `finding.recorded`, `run.finished`,
  `run.failed`). Sinks receive them; the backend bridges them to SSE.

## 5. Extension contracts (how things plug in later)

| Extension | What you implement | Where it's wired | Core changes |
|---|---|---|---|
| New security tool | subclass `Tool`, Pydantic input model, fixed-argv execution | registration line in composition root + contract test | none |
| Nmap (M1, done) | `tools/nmap.py:NmapTool` + `tools/nmap_parser.py:parse_nmap_xml` + `tools/subprocess.py:run_pinned_binary` | `agent_core/__main__.py:build_default_registry` + `backend/deps.py:build_registry` | none (validator already extracts `target`) |
| HTTPX (M2-A, done) | `tools/httpx.py:HTTPXTool` + `tools/httpx_parser.py:parse_httpx_jsonl` (reuse `run_pinned_binary`) | same two composition roots | tiny: validator `_extract_targets()` + `policy_targets()` hook so EVERY `targets[]` entry is allowlisted |
| Nuclei (M2-B, done) | `tools/nuclei.py:NucleiTool` + `tools/nuclei_parser.py:parse_nuclei_jsonl` (reuse `run_pinned_binary`, same `policy_targets()` hook) | same two composition roots | none (M2-A hook reused; `danger_level=active_scan`) |
| ModelPlanner (M3-A, done) | `planner/model.py:ModelPlanner` + `build_model_request()` over `providers/base.py:ModelProvider` (mock queued, stdlib OpenAI-compatible) | injected as `Planner` (tests/demos; composition root unchanged) | none (strict `parse_decision()`; validator/runtime untouched) |
| Real model | class with `generate(ModelRequest) -> ModelResponse` | composition root + config | none |
| Model-backed planner | `Planner.decide(state)` wrapping a provider | composition root | none |
| Rate limiting | `safety.policy.check_extra` | inside policy module | none |
| New sink (SSE broker, DB) | callable with `handle(event)` | composition root | none |

## 6. Deliberate non-goals (current foundation)

Autonomous exploitation, multi-agent orchestration, model training,
browser automation, RAG, databases, Redis, Kubernetes, production
deployment, and unrestricted command execution are all out of scope by
decision of the team. The interfaces above are the seams where those
capabilities would eventually attach - but nothing here pre-builds them.
