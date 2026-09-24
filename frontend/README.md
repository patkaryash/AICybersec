# AICybersec frontend — frozen v1 API contract

The backend (FastAPI, `/api/v1`) is the contract you (the frontend
developer) build against independently. This document reflects the
**Phase 2 frozen contract**: authentication, projects, scans, findings,
assets, agent events, tool runs, dashboard.

Start the backend:

```bash
uvicorn backend.main:app --reload      # http://localhost:8000
# docs: /api/v1/docs  |  redoc: /api/v1/redoc  |  openapi: /api/v1/openapi.json
```

## 0. Response envelope (every response)

```json
{ "success": true, "data": {}, "error": null, "meta": { "request_id": "uuid" } }
```

Errors:

```json
{ "success": false, "data": null,
  "error": { "code": "SCAN_NOT_FOUND", "message": "Scan does not exist." },
  "meta": { "request_id": "uuid" } }
```

Paginated responses put items under `data.items` and add
`meta.page` / `meta.page_size` / `meta.total` (`page_size` max 100).
Timestamps are UTC ISO-8601 (`2026-09-23T15:40:00Z`).

Error codes: `PROJECT_NOT_FOUND`, `SCAN_NOT_FOUND`, `FINDING_NOT_FOUND`,
`INVALID_TARGET`, `INVALID_SCAN_PROFILE`, `SCAN_ALREADY_RUNNING`,
`SCAN_NOT_CANCELLABLE`, `INVALID_CREDENTIALS`, `EMAIL_ALREADY_REGISTERED`,
`VALIDATION_ERROR`, `DATABASE_ERROR`, `INTERNAL_ERROR`.
HTTP: 401 credentials, 404 not-found/ownership, 409 conflicts,
422 validation. Unauthorized resources consistently return **404**
(no resource enumeration).

## 1. Authentication (Bearer JWT)

`Authorization: Bearer <token>` on every request except `/api/v1/health*`,
`register`, `login`.

- `POST /api/v1/auth/register` → **201**
  `{"email", "password" (min 8), "display_name"?}` → `data: {id, email, display_name, role, is_active, created_at, updated_at}`
  Duplicate email → 409. Role is always `user`; clients cannot create admins.
- `POST /api/v1/auth/login` → **200**
  `{"email", "password"}` → `data: {access_token, token_type: "bearer", expires_in}`
  Unknown user / wrong password / deactivated user → the same generic 401.
- `GET /api/v1/auth/me` → **200** current user (no password hash).

Store the token (e.g. localStorage) and attach the header to every call.

## 2. Projects

| Method | Path | Success | Errors |
|---|---|---|---|
| POST | `/api/v1/projects` | 201 | 422 `INVALID_TARGET` (bad scope) |
| GET | `/api/v1/projects?page&page_size` | 200 paginated | — |
| GET | `/api/v1/projects/{project_id}` | 200 | 404 |
| PATCH | `/api/v1/projects/{project_id}` | 200 | 404, 422 |
| DELETE | `/api/v1/projects/{project_id}` | **204** (archive) | 404 |

Create request:

```json
{
  "name": "Juice Shop lab",
  "description": "Authorized lab testing",
  "scope": [
    {"type": "host", "value": "juice-shop", "note": null},
    {"type": "cidr", "value": "127.0.0.0/31", "note": null},
    {"type": "url", "value": "http://juice-shop:3000", "note": null}
  ]
}
```

- `scope.type` is `host | cidr | url`; scope must contain **at least one**
  entry. Values are validated and canonicalized (hostnames lowercased,
  IPs/CIDRs canonical; unsupported schemes, embedded credentials, invalid
  ports/hosts/CIDRs → 422).
- List returns **only your own projects** (admins see all), newest first.
- DELETE archives (`status: "archived"`) — never a physical delete.

## 3. Scans

| Method | Path | Success | Errors |
|---|---|---|---|
| POST | `/api/v1/scans` | **202** | 404 (unknown/unowned project), 422 `INVALID_SCAN_PROFILE`, 409 `SCAN_ALREADY_RUNNING` |
| GET | `/api/v1/scans?project_id&status&page&page_size` | 200 paginated | 404 (unowned `project_id`) |
| GET | `/api/v1/scans/{scan_id}` | 200 | 404 |
| POST | `/api/v1/scans/{scan_id}/cancel` | **202** | 404, 409 `SCAN_NOT_CANCELLABLE` |

Create request:

```json
{ "project_id": "uuid", "profile": "full", "mode": "pipeline", "goal": "...", "tool_timeout_s": 300, "max_steps": 12 }
```

- `profile` is `recon | web | full`; `mode` is `pipeline | agent`.
- `tool_timeout_s` is 30..1800 (default 300).
- **Phase 2 semantics:** creation authenticates you, authorizes the
  project, snapshots the project scope into `target_snapshot` and
  persists the scan with `status: "queued"`. **No execution is
  scheduled yet** — Phase 3 adds background execution; until then scans
  stay `queued` (you may cancel them).
- Scan status vocabulary (seven states): `queued`, `initializing`,
  `running`, `cancelling`, `completed`, `failed`, `cancelled`.
  Cancel works on `queued`/`initializing`; other states → 409.
- A project can have at most **one active scan** (`queued`/`initializing`/
  `running`/`cancelling`) — a second one returns 409.
- `ScanOut` includes `total_steps` (static per profile: recon=2, web=2,
  full=3), `current_step` (0 until Phase 3 execution), and
  `findings_count {critical, high, medium, low, info, total}`.

## 4. Findings / Assets / Agent events / Tool runs (read APIs)

| Path | Notes |
|---|---|
| `GET /api/v1/scans/{scan_id}/findings?severity&status&page&page_size` | paginated; filters `severity` (info/low/medium/high/critical), `status` (open/accepted_risk/resolved/false_positive) |
| `GET /api/v1/findings/{finding_id}` | single finding |
| `GET /api/v1/scans/{scan_id}/assets?asset_type&page&page_size` | paginated; filter `asset_type` (host/service/url) |
| `GET /api/v1/assets/{asset_id}` | single asset |
| `GET /api/v1/scans/{scan_id}/agent-events?after_id&limit` | **cursor** pagination: pass the last `seq` you have seen; `after_id=0` replays the full history; `limit` 1..100 (default 50) |
| `GET /api/v1/scans/{scan_id}/tool-runs?page&page_size` | paginated, oldest first |

Until Phase 3 executes tools, scans created now have **empty** lists for
all four resources — that is expected, not a bug.

**Finding separation:** scanner fields (`scanner_severity`,
`scanner_evidence`, `scanner_references`, `source_tool`) are tool
evidence and are never overwritten; AI fields (`ai_severity`,
`ai_analysis`, `ai_confidence`, `ai_recommendation`, `ai_analyzed_at`)
are AI interpretation, stored separately, populated from Phase 8
onwards. `tool_run` responses deliberately exclude `argv`, `raw_output`
and `stderr` (internal/audit data).

**Agent events:** `data` payloads are sanitized by the backend — no
secrets, credentials, environment variables, raw subprocess output, or
hidden model reasoning.

## 5. Dashboard

`GET /api/v1/dashboard?recent_limit=6` (Bearer) → **200**:

```json
{
  "total_projects": 1, "total_scans": 3, "running_scans": 0,
  "scans_by_status": {"queued": 0, "initializing": 0, "running": 0,
                       "cancelling": 0, "completed": 3, "failed": 0, "cancelled": 0},
  "total_findings": 12,
  "findings_by_severity": {"critical": 1, "high": 2, "medium": 4, "low": 3, "info": 2},
  "total_assets": 8,
  "recent_scans": [ { "id": "...", "status": "completed", "findings_count": {...}, "...": "..." } ]
}
```

`recent_scans` are the newest scans visible to you, newest first
(`recent_limit` 1..50, default 6), each a full `ScanOut`.

## 6. Ownership behavior

Ownership flows `user → project → scan → findings/assets/agent-events/
tool_runs`. You can only access your own projects and their descendants
(admins see all). Guessing another user's IDs returns **404** — the same
response as a nonexistent resource. Never rely on client-side filtering
for security; the backend enforces everything.

## 7. Current frontend mismatches (the `frontend-siddharth` branch)

The existing frontend is a mock-driven UI shell (localStorage services,
no HTTP calls) designed for drop-in replacement with real REST calls.
Required adaptations when integrating:

| Frontend today | Backend v1 | Required action |
|---|---|---|
| profiles `recon` / `web_assessment` / `full_assessment` | `recon` / `web` / `full` | Update `SCAN_PROFILES` keys in `types/scan.ts` |
| `ScanStatus` `running/finished/failed/cancelled` | seven-state model (§3) | Update the union; map `finished` → `completed` |
| localStorage `scanService` / `findingsService` | REST + envelope (§0–§4) | Replace services with fetch + Bearer header |
| no authentication | JWT Bearer (§1) | Add login/register UI + token storage + 401 handling |
| no projects concept | projects with scope (§2) | Add project creation/selection to `NewPentestPage`; scans require a `project_id` |
| no pagination | pagination on all list endpoints (§4) | Add page/page_size params + `meta.total` handling |
| `Finding.aiAnalysis` structured object | `ai_analysis` TEXT + separate AI fields (Phase 8) | Adapt at Phase 8 integration; until then render AI fields as null |
| dot-notation events (`run.started`) | snake_case events (`scan_started`, `tool_started`, ...) on the Phase 6 WS/SSE contract | Update `AgentEventType` when the live contract lands (§8) |
| `notes` / `isSimulated` / `elapsedSeconds` on Scan | not in `ScanOut` | Drop or derive locally (mock-only fields) |

## 8. Future WebSocket/SSE contract (Phase 6 — not implemented yet)

Live updates will arrive over `WS /api/v1/scans/{scan_id}/events`
(replay-on-connect from persisted events, `after_id` cursor,
terminal-event-last) with SSE compatibility at
`GET /api/v1/scans/{scan_id}/events/stream`. Event envelope:

```json
{ "event": "tool_started", "scan_id": "...", "seq": 42,
  "timestamp": "2026-09-23T15:40:00Z", "data": { "tool": "nmap" } }
```

Event types (planned): `scan_started`, `scan_status_changed`,
`agent_started`, `agent_decision`, `agent_observation`, `tool_started`,
`tool_progress` (transient), `tool_completed`, `tool_failed`,
`finding_created`, `finding_updated`, `scan_completed`, `scan_failed`,
`scan_cancelled`. Until Phase 6, poll the REST endpoints.
