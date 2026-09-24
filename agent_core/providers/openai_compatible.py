"""OpenAI-compatible provider - minimal implementation (M3-A).

Speaks ``POST {base_url}/chat/completions`` with stdlib only (no new
dependencies). It returns RAW text; parsing into Decisions happens in
the planner layer, never here. The provider never executes tools,
touches ToolRegistry, mutates AgentState, or spawns subprocesses.

Not used by tests (MockModelProvider is mandatory for CI - no API keys,
no network). Selection happens in the composition root via config.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from agent_core.providers.base import Message, ModelRequest, ModelResponse


class OpenAICompatibleProvider:
    """Minimal OpenAI-compatible chat client."""

    def __init__(
        self, base_url: str, api_key: str, model: str, timeout_s: float = 60
    ) -> None:
        if not base_url or not base_url.strip():
            raise ValueError("base_url must be non-empty")
        if not model or not model.strip():
            raise ValueError("model must be non-empty")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_s = timeout_s

    def _payload(self, request: ModelRequest) -> dict:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": m.role, "content": m.content} for m in request.messages
            ],
        }
        if request.response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        return payload

    def generate(self, request: ModelRequest) -> ModelResponse:
        data = json.dumps(self._payload(request)).encode("utf-8")
        http_req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"model endpoint returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"cannot reach model endpoint: {exc.reason}") from exc
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("model response missing choices[0].message.content") from exc
        return ModelResponse(raw_text=content or "")
