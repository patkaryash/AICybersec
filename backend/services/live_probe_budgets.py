"""Server-pinned execution budgets for the live-probe profile (F3).

Design contract for Phase 5 Stage 2 - NO execution code lives here or
anywhere yet (ScanManager still hard-refuses ``live_probe``). Before
Stage 2 ships a dedicated live path, these values MUST be treated as
fixed platform policy, and they are deliberately NOT environment- or
client-configurable:

- Clients must not be able to loosen the request budget, the deadlines,
  the concurrency, or the response-size cap. ``AICYBERSEC_*`` env vars
  exist for the ambient platform; the live profile overrides all of
  them deterministically at scan creation.
- Nothing in this module reads the environment.

What is pinned per live_probe scan TODAY (Stage 1, at creation time via
``live_authorization_service.create_live_scan`` - validation only, the
scan still never executes):

- ``mode``            -> ``LIVE_PROBE_PINNED_MODE`` ("pipeline": no
  model-driven planning, no AgentRuntime actions).
- ``max_steps``       -> ``LIVE_PROBE_PINNED_MAX_STEPS``
- ``tool_timeout_s``  -> ``LIVE_PROBE_PINNED_TOOL_TIMEOUT_S``

The bound client fields live on ``ScanCreate`` (``mode``, ``max_steps``,
``tool_timeout_s``); ``create_live_scan`` discards all three. A
regression test asserts the override behavior
(tests/api/test_live_scan_authorizations.py::TestLiveScanBudgetPinning).

Stage 2 request budget proposal (constants; enforced by the dedicated
live transport, never by the client, never by the model):

- LIVE_PROBE_SCAN_REQUEST_BUDGET: hard cap on total HTTP requests per
  scan; the transport closes the scan when it is exhausted.
- LIVE_PROBE_REQUESTS_PER_SECOND: rate cap (deterministic spacing).
- LIVE_PROBE_REQUEST_TIMEOUT_S: per-request connect+read deadline
  (tighter than the scan's coarse ``tool_timeout_s`` + margin).
- LIVE_PROBE_SCAN_WALL_CLOCK_S: total wall-clock cap; on expiry the
  scan is cancelled cooperatively at the next request boundary, never
  mid-request beyond the request deadline.
- LIVE_PROBE_RESPONSE_MAX_BYTES: per-response cap; larger bodies are
  truncated/rejected, not streamed unboundedly.
- LIVE_PROBE_MAX_CONCURRENT_CONNECTIONS: pinned connection pool size to
  the single authorized origin.

Where these must be recorded tamper-evidently in Stage 2 (DECIDED):

- NOT inside the authorization snapshot. ``verify_live_scan_authorization``
  proves the snapshot equals a FRESH RENDER of the parent authorization
  record (digest equality). Budgets are execution policy, not
  authorization facts the parent record carries; folding them into the
  snapshot would either break the fresh-render comparison or require
  storing execution budgets inside the authorization record itself
  (coupling an admin authorization artifact to transport internals).
- Instead: a per-scan immutable ``execution_profile`` JSONB column
  (Stage 2 migration) rendered once at scan creation from THESE
  constants, plus an external digest column beside it - the exact same
  double-anchor pattern already proven for ``authorization_snapshot`` /
  ``authorization_snapshot_digest``. The live transport refuses to run
  unless the execution profile verifies against its digest AND the
  authorization snapshot verifies, and any policy-version drift
  invalidates both.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr

# --- Stage 1 request policy (single source for snapshots AND the S2-2
# execution profile; live_authorization_service re-exports these) -------
LIVE_PROBE_PATHS = ["/"]
LIVE_PROBE_METHODS = ["GET"]
LIVE_PROBE_FOLLOW_REDIRECTS = False

# --- Pinned NOW (Stage 1, validation-time only) -------------------------
# No model-driven planning in live mode: the profile is a fixed pipeline
# with zero agent turns.
LIVE_PROBE_PINNED_MODE = "pipeline"
LIVE_PROBE_PINNED_MAX_STEPS = 1
# Coarse scan-level deadline carried on the Scan row (Stage 2 request
# deadlines below are the tight per-request control).
LIVE_PROBE_PINNED_TOOL_TIMEOUT_S = 60

# --- Pinned for Stage 2 (enforced by the dedicated live transport) -------
LIVE_PROBE_SCAN_REQUEST_BUDGET = 200
LIVE_PROBE_REQUESTS_PER_SECOND = 1
LIVE_PROBE_REQUEST_TIMEOUT_S = 30
LIVE_PROBE_SCAN_WALL_CLOCK_S = 600
# 256 KiB: enough for "/" HTML of small sites; bounded memory profile.
LIVE_PROBE_RESPONSE_MAX_BYTES = 262_144
LIVE_PROBE_MAX_CONCURRENT_CONNECTIONS = 2

# --- S2-2 execution-profile contract (constants are the ONLY authority) --
# These values are rendered into the per-scan immutable execution profile
# at scan creation and are re-verified field-by-field against the LIVE
# constants before every future use. No env var, no client field, and no
# model output can ever set or relax any of them. Schema/policy only:
# nothing here performs DNS, HTTP, sockets, or any network I/O.
LIVE_PROBE_DNS_TIMEOUT_S = 5
# Hardcoded executor identity + step allowlist (§4.3 rule 5).
LIVE_PROBE_EXECUTOR = "live_transport_v1"
LIVE_PROBE_EXECUTOR_STEPS = ["live_root_get"]
# v1 request policy: one request shape, GET / on 80/443, no redirects,
# no env proxies, identity encoding (no decompression, §6.5).
LIVE_PROBE_PORTS = [80, 443]
LIVE_PROBE_HONOR_ENV_PROXIES = False
LIVE_PROBE_ACCEPT_ENCODING = "identity"
# v1 DNS policy (§4.2/§6.3): BOTH families are ALWAYS queried; A-only
# profiles are invalid. Fresh resolution every request boundary.
LIVE_PROBE_DNS_RECORD_GROUPS = ["A", "AAAA"]
LIVE_PROBE_DNS_ANSWER_SET_POLICY = "all_answers_global"
LIVE_PROBE_DNS_CNAME_FOLLOWING = True
LIVE_PROBE_DNS_CACHE = "none"


class _StrictProfileModel(BaseModel):
    """Base for every execution-profile sub-model: unknown fields are
    REJECTED (never ignored - ignoring unknowns is how forgery hides)
    and every scalar is strict-typed so wrong types fail parsing."""

    model_config = ConfigDict(extra="forbid")


class ExecutionProfileBudgets(_StrictProfileModel):
    max_requests_per_scan: StrictInt
    requests_per_second: StrictInt
    per_request_timeout_s: StrictInt
    wall_clock_s: StrictInt
    response_max_bytes: StrictInt
    max_concurrent_connections: StrictInt
    dns_timeout_s: StrictInt


class ExecutionProfileRequestPolicy(_StrictProfileModel):
    methods: list[StrictStr]
    paths: list[StrictStr]
    ports: list[StrictInt]
    follow_redirects: StrictBool
    honor_env_proxies: StrictBool
    accept_encoding: StrictStr


class ExecutionProfileDnsPolicy(_StrictProfileModel):
    record_groups: list[StrictStr]
    answer_set_policy: StrictStr
    cname_following: StrictBool
    cache: StrictStr


class LiveProbeExecutionProfile(_StrictProfileModel):
    """Canonical §4.2 execution-profile payload (single source).

    The authority for every VALUE is the pinned constant set above plus
    the caller-supplied binding uuids and the CURRENT policy-version
    SETTING; the payload carries the values, never the authority.
    ``profile_id`` binds the profile to the scan lifetime; ``scan_id``
    must equal the actual ``scans.id`` row, ``authorization_id`` must
    agree with both the scan FK and the Stage-1-verified snapshot, and
    ``project_id`` must equal ``scans.project_id`` at verification.
    """

    profile_id: UUID
    scan_id: UUID
    authorization_id: UUID
    project_id: UUID
    policy_version: StrictStr
    mode: StrictStr
    steps: list[StrictStr]
    executor: StrictStr
    budgets: ExecutionProfileBudgets
    request_policy: ExecutionProfileRequestPolicy
    dns_policy: ExecutionProfileDnsPolicy


def render_execution_profile(
    *,
    profile_id: UUID,
    scan_id: UUID,
    authorization_id: UUID,
    project_id: UUID,
    policy_version: str,
) -> dict[str, Any]:
    """Render the canonical execution-profile payload from constants
    ONLY (S2-2 issuance shape; called exactly once per live scan, at
    creation, immediately after the authorization snapshot). Every
    policy field comes from this module's pinned constants; the caller
    may supply only the four binding uuids and the current policy
    version SETTING - no client field, no env var, no model output.
    Returns a JSON-safe dict; the digest is computed by the caller with
    the same canonical-JSON algorithm used for snapshots."""
    profile = LiveProbeExecutionProfile(
        profile_id=profile_id,
        scan_id=scan_id,
        authorization_id=authorization_id,
        project_id=project_id,
        policy_version=policy_version,
        mode=LIVE_PROBE_PINNED_MODE,
        steps=list(LIVE_PROBE_EXECUTOR_STEPS),
        executor=LIVE_PROBE_EXECUTOR,
        budgets=ExecutionProfileBudgets(
            max_requests_per_scan=LIVE_PROBE_SCAN_REQUEST_BUDGET,
            requests_per_second=LIVE_PROBE_REQUESTS_PER_SECOND,
            per_request_timeout_s=LIVE_PROBE_REQUEST_TIMEOUT_S,
            wall_clock_s=LIVE_PROBE_SCAN_WALL_CLOCK_S,
            response_max_bytes=LIVE_PROBE_RESPONSE_MAX_BYTES,
            max_concurrent_connections=LIVE_PROBE_MAX_CONCURRENT_CONNECTIONS,
            dns_timeout_s=LIVE_PROBE_DNS_TIMEOUT_S,
        ),
        request_policy=ExecutionProfileRequestPolicy(
            methods=list(LIVE_PROBE_METHODS),
            paths=list(LIVE_PROBE_PATHS),
            ports=list(LIVE_PROBE_PORTS),
            follow_redirects=LIVE_PROBE_FOLLOW_REDIRECTS,
            honor_env_proxies=LIVE_PROBE_HONOR_ENV_PROXIES,
            accept_encoding=LIVE_PROBE_ACCEPT_ENCODING,
        ),
        dns_policy=ExecutionProfileDnsPolicy(
            record_groups=list(LIVE_PROBE_DNS_RECORD_GROUPS),
            answer_set_policy=LIVE_PROBE_DNS_ANSWER_SET_POLICY,
            cname_following=LIVE_PROBE_DNS_CNAME_FOLLOWING,
            cache=LIVE_PROBE_DNS_CACHE,
        ),
    )
    return profile.model_dump(mode="json")
