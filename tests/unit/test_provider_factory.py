"""Unit tests: provider factory selection (M3-C, offline, no credentials)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_core.providers.base import ModelProvider
from agent_core.providers.factory import build_provider
from agent_core.providers.mock import MockModelProvider
from agent_core.providers.openai_compatible import OpenAICompatibleProvider


def _settings(**overrides):
    base = {
        "model_provider": "mock",
        "model_base_url": "",
        "model_api_key": "",
        "model_name": "",
        "model_timeout_s": 60,
        "model_max_response_chars": 8000,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_default_is_mock():
    provider = build_provider(_settings())
    assert isinstance(provider, MockModelProvider)
    assert isinstance(provider, ModelProvider)


def test_name_matching_is_case_insensitive():
    assert isinstance(build_provider(_settings(model_provider="Mock")), MockModelProvider)


def test_unknown_provider_rejected():
    with pytest.raises(ValueError, match="unknown model provider"):
        build_provider(_settings(model_provider="langchain"))


def test_openai_compatible_requires_base_url():
    with pytest.raises(ValueError, match="MODEL_BASE_URL"):
        build_provider(_settings(model_provider="openai_compatible"))


def test_openai_compatible_construction():
    provider = build_provider(
        _settings(
            model_provider="openai_compatible",
            model_base_url="http://localhost:11434/v1/",
            model_api_key="",
            model_name="qwen",
        )
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert isinstance(provider, ModelProvider)
    assert provider.base_url == "http://localhost:11434/v1"  # trailing slash stripped
    assert provider.model == "qwen"
