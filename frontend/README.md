# AICybersec frontend

The frontend application is **not built yet**. This file is the contract
you (the frontend developer) can build against independently: run the
backend locally and consume the endpoints below. Everything works
offline with the mock/scripted planner - no LLM needed.

Start the backend:

```bash
uvicorn backend.main:app --reload     # http://localhost:8000, docs at /docs
```

## 1. Endpoints

### `POST /runs` - start a run

Request:

```json
{
  "goal": "Perform a basic reconnaissance of the target and report findings.",
  "targets": ["demo.local"],
  "mode": "recon"
}
```

- `targets` must not be empty (422 otherwise). The first target drives
  the current scripted planner.
- `mode` is a free string for now (e.g. `recon`).

Response `200`:

```json
{ "run_id": "run-3bbfac53778a" }
```

### `GET /runs/{run_id}` - poll state

Response `200`:

```json
{
  "state": {
    "run_id": "run-3bbfac53778a",
    "goal": "Perform a basic reconnaissance of the target and report findings.",
    "status": "finished",
    "step": 3,
    "max_steps": 12,
    "observations": [
      {
        "step": 1,
        "source": "tool",
        "tool": "mock_port_scan",
        "ok": true,
        "summary": "Scanned 3 ports on demo.local: 3 open (80, 443, 8080).",
        "data": { "target": "demo.local", "open_ports": [{"port": 80, "service": "http"}], "synthetic": true },
        "findings": [],
        "reason": null
      }
    ],
    "findings": [
      {
        "id": "mock_port_scan:http-service-on-port-80",
        "title": "HTTP service on port 80",
        "severity": "info",
        "target": "demo.local",
        "asset": "http://demo.local:80",
        "description": "Mock scan identified a http service listening on port 80. This is a synthetic result.",
        "evidence": { "port": 80, "service": "http" },
        "tool": "mock_port_scan",
        "confidence": "high",
        "status": "open",
        "references": []
      }
    ],
    "steps": [],
    "started_at": "2026-09-22T10:00:00.000000+00:00",
    "completed_at": "2026-09-22T10:00:00.100000+00:00",
    "error": null
  }
}
```

`status` is one of `running | finished | failed | cancelled`.
`404` if the run id is unknown (runs live in the backend process memory
for now; restart clears them).

### `GET /runs/{run_id}/events` - Server-Sent Events stream

- `Content-Type: text/event-stream`
- The stream first flushes every event recorded so far (backlog), then
  streams live events and **ends when the run reaches a terminal state**
  (`run.finished` or `run.failed` is the last event).
- Connect any time; you will always get the full history from step 1.

Wire format (standard SSE):

```
event: tool.finished
data: {"type": "tool.finished", "run_id": "run-3bbfac53778a", "step": 1, "timestamp": "2026-09-22T10:00:00.050000+00:00", "data": {"tool": "mock_port_scan", "status": "ok", "summary": "Scanned 3 ports on demo.local: 3 open (80, 443, 8080)."}}
```

Browser usage: `new EventSource("/runs/" + runId + "/events")` and
`addEventListener` per event type (note: `EventSource` reconnects
automatically; the backlog-on-connect behavior makes that safe).

### `GET /health`

`{"status": "ok"}` - use for readiness checks.

## 2. Event types

The event vocabulary is frozen - it is the contract. The final event of
a stream is exactly one of `run.finished` / `run.failed`.

| Event | Payload `data` fields | Meaning |
|---|---|---|
| `run.started` | `goal`, `mode` | Run accepted, loop starting |
| `step.started` | *(none)* | Loop iteration `step` begins |
| `decision.proposed` | `decision` (`{kind, tool?, params?, reasoning?, summary?}`) | Planner produced a decision (shown before validation) |
| `decision.rejected` | `reason` | Decision failed validation and was NOT executed |
| `tool.started` | `tool` | Approved tool call begins execution |
| `tool.finished` | `tool`, `status` (`ok\|error\|timeout`), `summary` | Tool returned a result |
| `finding.recorded` | `finding` (Finding object) | A security finding was recorded |
| `run.finished` | `status` (`finished\|cancelled`), `findings_count`, `steps`, `summary?` | Terminal success |
| `run.failed` | `status` (`failed`), `findings_count`, `steps`, `error` | Terminal failure (e.g. max steps reached) |

Every event also carries the envelope: `type`, `run_id`, `step`,
`timestamp` (UTC ISO-8601), `data`.

## 3. Suggested UI flow

1. Form (goal, targets) -> `POST /runs` -> keep `run_id`.
2. Open `EventSource` on `/runs/{id}/events`; render a live timeline
   from events (decisions, rejections, tool results, findings).
3. On `run.finished`, render `finding.recorded` items as a findings
   table (severity, title, tool, evidence), or fetch `GET /runs/{id}`
   for the full state snapshot.

## 4. Notes

- All current results are **synthetic** (mock tools). Severity/evidence
  values are for demo purposes.
- CORS is not configured yet; add it in `backend/main.py` when the
  frontend runs on a different origin during development.
