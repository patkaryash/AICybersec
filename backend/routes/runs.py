"""Run management API.

Contract documented for the frontend developer in frontend/README.md.
Keep payloads in sync with that file.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.deps import get_run_manager

router = APIRouter(prefix="/runs", tags=["runs"])


class CreateRunRequest(BaseModel):
    goal: str = Field(min_length=1)
    targets: list[str] = Field(default_factory=list)
    mode: str = "recon"


@router.post("")
def create_run(body: CreateRunRequest) -> dict:
    if not body.targets:
        raise HTTPException(status_code=422, detail="targets must not be empty")
    run_id = get_run_manager().create_run(body.goal, body.targets, body.mode)
    return {"run_id": run_id}


@router.get("/{run_id}")
def get_run(run_id: str) -> dict:
    managed = get_run_manager().get(run_id)
    if managed is None:
        raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")
    return {"state": managed.state.model_dump(mode="json")}


@router.get("/{run_id}/events")
async def stream_events(run_id: str) -> StreamingResponse:
    managed = get_run_manager().get(run_id)
    if managed is None:
        raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")

    async def gen():
        cursor = 0
        # Emit the current backlog, then poll for new events until the run
        # reaches a terminal state.  Simple and sufficient for the mock
        # runtime; a queue-based broker can replace this without changing
        # the event contract.
        while True:
            events = managed.sink.events
            while cursor < len(events):
                event = events[cursor]
                cursor += 1
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
            if managed.state.status in ("finished", "failed", "cancelled"):
                break
            await asyncio.sleep(0.05)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
