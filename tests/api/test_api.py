"""API tests: FastAPI endpoints including SSE - all offline, no LLM."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from backend.main import create_app


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_post_runs_returns_run_id(client):
    res = client.post(
        "/runs",
        json={"goal": "recon", "targets": ["demo.local"], "mode": "recon"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["run_id"].startswith("run-")


def test_post_runs_requires_targets(client):
    res = client.post("/runs", json={"goal": "recon", "targets": []})
    assert res.status_code == 422


def test_get_unknown_run_404(client):
    res = client.get("/runs/run-doesnotexist")
    assert res.status_code == 404


def test_get_run_state_and_findings(client):
    run_id = client.post(
        "/runs", json={"goal": "recon", "targets": ["demo.local"]}
    ).json()["run_id"]

    res = client.get(f"/runs/{run_id}")
    assert res.status_code == 200
    state = res.json()["state"]
    assert state["run_id"] == run_id
    assert state["goal"] == "recon"
    # the scripted demo completes quickly; give it a moment if needed
    for _ in range(50):
        if state["status"] in ("finished", "failed"):
            break
        import time

        time.sleep(0.05)
        state = client.get(f"/runs/{run_id}").json()["state"]
    assert state["status"] == "finished"
    assert len(state["findings"]) == 3


def test_sse_stream_delivers_events(client):
    run_id = client.post(
        "/runs", json={"goal": "recon", "targets": ["demo.local"]}
    ).json()["run_id"]

    with client.stream("GET", f"/runs/{run_id}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        seen_types = []
        for line in response.iter_lines():
            if line.startswith("event: "):
                seen_types.append(line[len("event: "):])
            if seen_types and seen_types[-1] in ("run.finished", "run.failed"):
                break

    assert seen_types[0] == "run.started"
    assert "decision.proposed" in seen_types
    assert "tool.finished" in seen_types
    assert seen_types[-1] in ("run.finished", "run.failed")


def test_sse_payload_is_valid_json(client):
    run_id = client.post(
        "/runs", json={"goal": "g", "targets": ["demo.local"]}
    ).json()["run_id"]
    with client.stream("GET", f"/runs/{run_id}/events") as response:
        for line in response.iter_lines():
            if line.startswith("data: "):
                event = json.loads(line[len("data: "):])
                assert {"type", "run_id", "step", "timestamp", "data"} <= set(event)
            if line.startswith("event: run."):
                if line in ("event: run.finished", "event: run.failed"):
                    break
