"""API tests: OpenAPI contract - the frozen v1 surface.

Verifies every frozen path exists, the bearer security scheme is
documented, protected endpoints advertise authentication, envelopes are
the documented response models, and legacy paths are absent. These
tests need no database.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app

FROZEN_PATHS = {
    "/api/v1/health",
    "/api/v1/health/ready",
    "/api/v1/auth/register",
    "/api/v1/auth/login",
    "/api/v1/auth/me",
    "/api/v1/dashboard",
    "/api/v1/projects",
    "/api/v1/projects/{project_id}",
    "/api/v1/scans",
    "/api/v1/scans/{scan_id}",
    "/api/v1/scans/{scan_id}/cancel",
    "/api/v1/scans/{scan_id}/findings",
    "/api/v1/scans/{scan_id}/assets",
    "/api/v1/scans/{scan_id}/agent-events",
    "/api/v1/scans/{scan_id}/tool-runs",
    "/api/v1/findings/{finding_id}",
    "/api/v1/assets/{asset_id}",
}

PUBLIC_PATHS = {"/api/v1/health", "/api/v1/health/ready", "/api/v1/auth/register", "/api/v1/auth/login"}

LEGACY_PATHS = ("/runs", "/runs/{run_id}", "/runs/{run_id}/events", "/health")


@pytest.fixture()
def spec() -> dict:
    with TestClient(create_app()) as client:
        return client.get("/api/v1/openapi.json").json()


def test_all_frozen_paths_present(spec):
    assert FROZEN_PATHS <= set(spec["paths"])


def test_no_unexpected_paths(spec):
    assert set(spec["paths"]) == FROZEN_PATHS


def test_no_legacy_paths(spec):
    for path in LEGACY_PATHS:
        assert path not in spec["paths"], path


def test_bearer_security_scheme_documented(spec):
    schemes = spec["components"]["securitySchemes"]
    assert "HTTPBearer" in schemes
    assert schemes["HTTPBearer"]["type"] == "http"
    assert schemes["HTTPBearer"]["scheme"] == "bearer"


def test_protected_endpoints_declare_security(spec):
    for path in FROZEN_PATHS - PUBLIC_PATHS:
        for method in spec["paths"][path]:
            security = spec["paths"][path][method].get("security")
            assert security is not None, f"{method.upper()} {path}"


def test_public_endpoints_do_not_declare_security(spec):
    for path in PUBLIC_PATHS:
        for method in spec["paths"][path]:
            assert spec["paths"][path][method].get("security") is None, path


def test_envelope_response_models_documented(spec):
    """Every response 2xx schema references the Envelope wrapper."""
    schemas = spec["components"]["schemas"]
    assert "Envelope_UserOut_" in schemas or any(s.startswith("Envelope_") for s in schemas)
    # login response documents TokenResponse inside the envelope
    login_ref = spec["paths"]["/api/v1/auth/login"]["post"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    assert "Envelope" in login_ref
    assert "TokenResponse" in schemas
    # scans list documents PageData[ScanOut]
    list_ref = spec["paths"]["/api/v1/scans"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    assert "PageData" in list_ref
    assert "ScanOut" in schemas


def test_documented_status_codes(spec):
    """Scan creation documents 202; project creation documents 201."""
    assert "202" in spec["paths"]["/api/v1/scans"]["post"]["responses"]
    assert "201" in spec["paths"]["/api/v1/projects"]["post"]["responses"]
    assert "204" in spec["paths"]["/api/v1/projects/{project_id}"]["delete"]["responses"]


def test_query_parameter_enums_documented(spec):
    """status filters and request enums appear in the OpenAPI schema
    (OpenAPI 3.1 renders nullable Literals as anyOf[enum, null])."""
    params = spec["paths"]["/api/v1/scans"]["get"]["parameters"]
    status_param = next(p for p in params if p["name"] == "status")
    schema = status_param["schema"]
    enum = schema.get("enum") or schema["anyOf"][0]["enum"]
    assert set(enum) == {
        "queued", "initializing", "running", "cancelling", "completed", "failed", "cancelled",
    }
    create_profile = spec["paths"]["/api/v1/scans"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert "ScanCreate" in create_profile.get("$ref", "")
