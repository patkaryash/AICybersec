"""Event system: typed dict events + EventSink protocol.

The event vocabulary below is the frontend/backend contract (see
frontend/README.md).  Keep event names stable.

Final event per run is exactly one of:
    run.finished  (status finished | cancelled)
    run.failed    (status failed)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

EVENT_TYPES = (
    "run.started",
    "step.started",
    "decision.proposed",
    "decision.rejected",
    "tool.started",
    "tool.finished",
    "finding.recorded",
    "run.finished",
    "run.failed",
)


def make_event(event_type: str, run_id: str, step: int = 0, **data: Any) -> dict:
    """Build one event dict. Timestamps are UTC ISO-8601."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type!r}")
    return {
        "type": event_type,
        "run_id": run_id,
        "step": step,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


@runtime_checkable
class EventSink(Protocol):
    """Anything with ``handle(event: dict)``. Backend bridges this to SSE."""

    def handle(self, event: dict) -> None: ...


class PrinterSink:
    """Readable console output for the CLI demo."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout

    def handle(self, event: dict) -> None:
        etype = event["type"]
        data = event.get("data", {})
        if etype == "run.started":
            line = f"==> RUN STARTED  goal: {data.get('goal')!r}"
        elif etype == "step.started":
            line = f"-- step {event['step']} -------------------------"
        elif etype == "decision.proposed":
            d = data.get("decision", {})
            kind = d.get("kind")
            if kind == "tool_call":
                line = f"    decision: CALL {d.get('tool')} params={d.get('params')}"
                if d.get("reasoning"):
                    line += f"\n    reasoning (debug only): {d.get('reasoning')}"
            else:
                line = f"    decision: FINISH {d.get('summary')!r}"
        elif etype == "decision.rejected":
            line = f"    REJECTED: {data.get('reason')}"
        elif etype == "tool.started":
            line = f"    executing tool: {data.get('tool')}"
        elif etype == "tool.finished":
            line = f"    tool finished [{data.get('status')}]: {data.get('summary')}"
        elif etype == "finding.recorded":
            f = data.get("finding", {})
            line = f"    FINDING [{f.get('severity')}] {f.get('title')} ({f.get('id')})"
        elif etype == "run.finished":
            line = (
                f"==> RUN FINISHED [{data.get('status')}]  "
                f"findings: {data.get('findings_count')}  summary: {data.get('summary')!r}"
            )
        elif etype == "run.failed":
            line = f"==> RUN FAILED: {data.get('error')}"
        else:
            line = f"    {etype}: {data}"
        print(line, file=self.stream)


class InMemorySink:
    """Collects events in a list - used by tests and the API layer."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def handle(self, event: dict) -> None:
        self.events.append(event)

    def of_type(self, event_type: str) -> list[dict]:
        return [e for e in self.events if e["type"] == event_type]
