# AICybersec

AI-assisted penetration-testing platform (academic major project), built
for **authorized testing in controlled lab environments only**. The
repository now contains a working end-to-end system:

- **agent_core** — pure agent library: planner → decision → two-stage
  safety validation → controlled subprocess tools (nmap, httpx, nuclei).
- **FastAPI backend** — JWT auth, projects with target scope, background
  scan execution (ScanManager), findings/assets/events persistence in
  PostgreSQL, everything under `/api/v1`.
- **React + Vite frontend** — login/register, projects, scan execution
  with a live agent-event feed, findings dashboard.

> **Status (Phase 3 complete):** a scan started from the browser runs a
> real, safety-gated pipeline — nmap → httpx → nuclei — against an
> allowlisted local lab target (OWASP Juice Shop) and persists findings,
> assets and agent events to PostgreSQL. No external LLM is required;
> exploitation, browser automation and model training are future phases.

## Architecture (text diagram)

```
React frontend (frontend/, Vite dev server :5173)
        |  REST, JWT Bearer, all under /api/v1
        v
FastAPI backend (backend/)            <- HTTP only, composition root
   |  auth / projects / scans / findings / assets / events / dashboard
   v
ScanManager (backend/services/)       <- one background task per scan,
   |  status: queued -> initializing -> running -> terminal;
   |  cancellation support; max one active scan per project
   v
AgentRuntime (agent_core/runtime)     <- decide -> validate -> execute loop
   |          \__________________
   v                             v
Planner                    SafetyValidator
(pipeline planner; the     (schema stage + policy stage: target
 model planner exists but   allowlist, danger cap, max steps)
 external LLMs stay off by default)
   |                             |
   |  Decision (tool_call|finish) ->  ToolRegistry (whitelist)
   v                                   |
ModelProvider (mock by default)        v
                                 Tool.execute(validated params)
                                 nmap | httpx | nuclei   (fixed argv,
                                 pinned binaries, XML/JSONL stdout)
                                       |
                                       v
                            ToolResult -> Observation
                                       |
            +--------------------------+--------------------------+
            v                          v                          v
   ScanRecord (PostgreSQL)    Findings + Assets +        AgentEvents +
                              ToolRuns (PostgreSQL)      ToolRuns events
                              (served via REST)          (persisted, served
                                                          via REST polling)
```

See `docs/architecture.md` for the detailed boundary and safety-model
rationale.

## Repository structure

```
agent_core/     Pure agent library. No FastAPI, no HTTP, no shell tool.
  schemas/      Shared contracts (Decision, ToolSpec, Finding, AgentState...)
  providers/    ModelProvider protocol + mock (future model plugs in here)
  planner/      Planner protocol + ScriptedPlanner / ModelPlanner
  tools/        Tool ABC, ToolContext, ToolRegistry, mock tools,
                subprocess.py (pinned-binary runner),
                nmap.py, httpx.py, nuclei.py + parsers
  safety/       Policy + two-stage SafetyValidator
  runtime/      AgentRuntime loop + event system
  state/        JsonFileStore (state.json + trajectory.jsonl)
backend/        FastAPI adapter: api/ (routes), services/ (ScanManager,
                pipeline planner, persistence), core/ (config, errors),
                schemas/, db/ (SQLAlchemy models + Alembic migrations)
frontend/       React + Vite app (login, projects, scans, findings, events)
docker/         docker-compose.yml (postgres + backend + Juice Shop lab target)
tests/          unit / integration / contracts / api (offline except DB tests)
docs/           architecture.md
runs/           gitignored runtime output (state.json, trajectory.jsonl)
```

## Quick start (Docker, recommended)

Prerequisite: Docker Desktop (or any Docker Engine with Compose v2).

```bash
# from the repository root
docker compose -f docker/docker-compose.yml up -d                 # postgres + backend
docker compose -f docker/docker-compose.yml --profile lab up -d   # + Juice Shop lab target
```

| Service | URL | Notes |
|---|---|---|
| Backend API | http://localhost:8000 | runs Alembic migrations, then uvicorn |
| API docs (Swagger) | http://localhost:8000/api/v1/docs | ReDoc: `/api/v1/redoc` |
| PostgreSQL | localhost:5432 | user/db/password `aicybersec` (dev default) |
| Juice Shop (lab) | http://localhost:3000 | only with `--profile lab`; give it memory headroom (see the note in `docker/docker-compose.yml`) |

The backend seeds a default admin at startup (dev defaults live in
`docker/docker-compose.yml` / `.env.example`):
`admin@aicybersec.dev` / `admin-dev-password-change-me`. Change these in
any shared environment.

## Frontend (dev server)

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

CORS for `localhost:5173` is pre-configured in the compose file. The UI
talks to the backend at `http://localhost:8000`; the frozen v1 API
contract is documented in `frontend/README.md`.

## Local (non-Docker) backend

```bash
python -m venv .venv
source .venv/Scripts/activate        # Windows (bash)  |  Linux: .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env                 # adjust values; NEVER commit .env
alembic upgrade head
uvicorn backend.main:app --reload    # http://localhost:8000
```

Configuration is environment-driven (`AICYBERSEC_` prefix, loaded from
`.env`). See `.env.example` for the full list: database URL, JWT
secret/expiry, admin seed credentials, CORS origins, concurrency and
timeout limits, `AICYBERSEC_SCAN_AUTO_START` (set `0` to keep scans
queued instead of auto-starting them), runs directory, AI provider
settings.

## Authentication (JWT Bearer)

Every endpoint except `/api/v1/health*`, `register` and `login` requires
`Authorization: Bearer <token>`.

```bash
python - <<'PY'
import json, urllib.request

def request(path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("http://localhost:8000" + path,
                                 data=data, headers=headers,
                                 method="POST" if body is not None else "GET")
    return json.load(urllib.request.urlopen(req))

request("/api/v1/auth/register",
        {"email": "student@example.com", "password": "password123"})
tok = request("/api/v1/auth/login",
              {"email": "student@example.com",
               "password": "password123"})["data"]["access_token"]
print(request("/api/v1/auth/me", token=tok))
PY
```

- `POST /api/v1/auth/register` → **201** (duplicate email → 409; role is
  always `user`, clients cannot create admins)
- `POST /api/v1/auth/login` → `{access_token, token_type, expires_in}`
  (wrong credentials → generic 401)
- `GET /api/v1/auth/me` → current user

Every response uses the envelope
`{success, data, error, meta.request_id}`; error codes map to HTTP
401 (credentials) / 404 (not found **or** not owned) / 409 (conflict) /
422 (validation).

## Projects and target scope

Scans never accept free-form targets — they scan the **scope** of a
project you own. Create a project first (via the UI or the API):

```json
POST /api/v1/projects
{
  "name": "Juice Shop lab",
  "description": "Authorized local lab target",
  "scope": [
    {"type": "host", "value": "juice-shop"},
    {"type": "host", "value": "172.18.0.3"},
    {"type": "url",  "value": "http://juice-shop:3000"}
  ]
}
```

- `scope.type` is `host | cidr | url`; at least one entry is required;
  values are validated and canonicalized (otherwise 422
  `INVALID_TARGET`).
- The scope is snapshotted into the scan at creation time
  (`target_snapshot`) and enforced by the SafetyValidator on **every**
  tool call — tools cannot widen it.
- List/read/update/archive: `GET|PATCH|DELETE /api/v1/projects[...]`
  (delete is an archive, never a physical delete). You only ever see
  your own projects.

Lab note: inside the compose network the `juice-shop` hostname resolves
to the container IP. Scans may derive URL targets such as
`http://juice-shop:3000`; the validator compares the **derived** host,
so include the container IP as a `host` scope entry too (as above) —
otherwise the derived target is rejected fail-closed.

## Running a scan

```json
POST /api/v1/scans          -> 202 Accepted, returns immediately
{ "project_id": "<uuid>", "profile": "full", "mode": "pipeline" }
```

- `profile` is `recon | web | full`; `mode` is `pipeline | agent`.
- Status vocabulary: `queued → initializing → running → (cancelling) →
  completed | failed | cancelled`.
- The scan executes in the background (ScanManager). Poll
  `GET /api/v1/scans/{id}` and the read endpoints:
  - `GET /api/v1/scans/{id}/findings?severity&status`
  - `GET /api/v1/scans/{id}/assets?asset_type`
  - `GET /api/v1/scans/{id}/agent-events?after_id&limit` (cursor
    pagination: pass the last `seq`; `after_id=0` replays history)
  - `GET /api/v1/scans/{id}/tool-runs`
- `POST /api/v1/scans/{id}/cancel` → **202** (works while
  `queued`/`initializing`/`running`; later → 409)
- One active scan per project; a second → 409 `SCAN_ALREADY_RUNNING`.
- `GET /api/v1/dashboard` → aggregated counts + recent scans.

Phase 3 pipeline profiles:

| Profile | Steps |
|---|---|
| `recon` | nmap → httpx |
| `web` | httpx → nuclei |
| `full` | nmap → httpx → nuclei |

Each step is a `Decision → SafetyValidator → ToolRegistry → Tool`
round-trip. nmap/httpx are reconnaissance (`danger_level=safe`); nuclei
is template-based vulnerability scanning (`danger_level=active_scan`,
`cve,misconfig,exposure,default-login` tags, medium+ severity).
Tools run as pinned binaries with fixed argv (no shell, no arbitrary
flags); raw tool output never enters model context or event payloads.

## Demo script (~5 minutes, fully offline)

1. Start the stack (Quick start) and open http://localhost:5173.
2. Register a user — or log in as the seeded admin.
3. Create the "Juice Shop lab" project with the 3-entry scope above.
4. Start a `recon` scan (~15–20 s): assets appear as nmap → httpx
   complete, and the live agent-event feed streams decisions and tool
   results.
5. Start a `full` scan; while httpx runs, hit **Cancel** — status moves
   `cancelling → cancelled` within seconds.
6. Open a completed Nuclei scan from Scan History: findings by severity,
   per-finding evidence, tool-run list.
7. Safety beat: a rejected decision in the agent events
   (`decision.rejected`) shows the model proposing and the validator
   refusing — the model proposes, safety disposes.

Everything stays on the lab network: the only allowed target is the
Juice Shop container.

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

## Run tests

```bash
python -m pytest
```

- Unit/contract tests are fully offline: no API keys, no network, no real
  security tools.
- API/integration tests need a PostgreSQL (the compose `postgres` service
  is enough): with it up the full suite passes (~340 tests, 1
  environment-gated skip); without it, those tests skip automatically.

## Development workflow

- See `CONTRIBUTING.md` for branch/PR rules and ownership boundaries.
- Shared contracts live in `agent_core/schemas/` - all three components
  depend on them; change carefully and with tests.
- The frozen v1 frontend/API contract is documented in `frontend/README.md`.
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
