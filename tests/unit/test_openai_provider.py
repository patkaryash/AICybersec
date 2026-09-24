"""Unit tests: OpenAICompatibleProvider transport (M3-C).

The HTTP layer is stubbed by monkeypatching urlopen - these tests prove
the real provider class builds correct requests, extracts completions,
bounds output, and maps failures. No network, no credentials.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from agent_core.providers.base import Message, ModelRequest
from agent_core.providers.openai_compatible import OpenAICompatibleProvider


def _request():
    return ModelRequest(
        messages=[
            Message(role="system", content="sys"),
            Message(role="user", content='{"goal": "x"}'),
        ],
        tool_schemas=[{"name": "mock_port_scan"}],
        response_format="json",
    )


class _FakeHTTPResponse:
    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _completion(content):
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def test_payload_shape_and_headers(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        seen["body"] = json.loads(req.data.decode())
        seen["timeout"] = timeout
        return _FakeHTTPResponse(_completion('{"kind": "finish", "summary": "done"}'))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:11434/v1", api_key="k", model="m", timeout_s=7
    )
    resp = provider.generate(_request())
    assert resp.raw_text == '{"kind": "finish", "summary": "done"}'
    assert seen["url"] == "http://localhost:11434/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer k"
    assert seen["body"]["model"] == "m"
    assert seen["body"]["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": '{"goal": "x"}'},
    ]
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert seen["timeout"] == 7


def test_no_json_response_format_when_not_requested(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["body"] = json.loads(req.data.decode())
        return _FakeHTTPResponse(_completion("hi"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    req = _request()
    req.response_format = "text"
    OpenAICompatibleProvider("http://h", "", "m").generate(req)
    assert "response_format" not in seen["body"]


def test_http_error_maps_to_runtime_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        OpenAICompatibleProvider("http://h", "", "m").generate(_request())


def test_unreachable_maps_to_connection_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ConnectionError, match="cannot reach"):
        OpenAICompatibleProvider("http://h", "", "m").generate(_request())


def test_timeout_maps_to_timeout_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(TimeoutError, match="timed out"):
        OpenAICompatibleProvider("http://h", "", "m").generate(_request())


def test_malformed_body_rejected(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeHTTPResponse(json.dumps({"no": "choices"}).encode()),
    )
    with pytest.raises(RuntimeError, match="choices"):
        OpenAICompatibleProvider("http://h", "", "m").generate(_request())


def test_response_is_bounded(monkeypatch):
    big = '{"kind": "finish", "summary": "' + "x" * 5000 + '"}'
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeHTTPResponse(_completion(big)),
    )
    provider = OpenAICompatibleProvider("http://h", "", "m", max_response_chars=100)
    assert len(provider.generate(_request()).raw_text) == 100


def test_constructor_validation():
    with pytest.raises(ValueError, match="base_url"):
        OpenAICompatibleProvider("", "", "m")
    with pytest.raises(ValueError, match="model must be non-empty"):
        OpenAICompatibleProvider("http://h", "", "  ")
    with pytest.raises(ValueError, match="max_response_chars"):
        OpenAICompatibleProvider("http://h", "", "m", max_response_chars=0)
