"""Unit tests: response envelope builders (the single response shape)."""
from __future__ import annotations

from backend.core.envelope import (
    MAX_PAGE_SIZE,
    Envelope,
    error_envelope,
    normalize_pagination,
    ok,
    paginated,
)


def test_ok_envelope_shape():
    env = ok({"a": 1}, request_id="req-1")
    assert env.success is True
    assert env.data == {"a": 1}
    assert env.error is None
    assert env.meta.request_id == "req-1"
    assert env.meta.page is None


def test_paginated_envelope_shape():
    env = paginated(["a", "b"], page=2, page_size=20, total=42, request_id="req-2")
    assert env.success is True
    assert env.data.items == ["a", "b"]
    assert env.meta.page == 2
    assert env.meta.page_size == 20
    assert env.meta.total == 42


def test_pagination_clamping():
    assert normalize_pagination(0, 0) == (1, 1)
    assert normalize_pagination(-5, 500) == (1, MAX_PAGE_SIZE)
    assert normalize_pagination(3, 100) == (3, 100)
    assert MAX_PAGE_SIZE == 100


def test_error_envelope_shape():
    env = error_envelope("SCAN_NOT_FOUND", "Scan does not exist.", "req-3")
    assert env.success is False
    assert env.data is None
    assert env.error.code == "SCAN_NOT_FOUND"
    assert env.error.message == "Scan does not exist."
    assert env.meta.request_id == "req-3"


def test_envelope_serializes_round_trip():
    env = ok({"a": 1}, "req-4")
    data = env.model_dump(mode="json")
    assert Envelope.model_validate(data).data == {"a": 1}
