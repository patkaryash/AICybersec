# Phase 5 Stage 2 — Live Probe Transport Design (Step 1: design only)

**Status: DESIGN — nothing in this document is implemented.** No source code,
migrations, tests, configuration, dependencies, or flags were modified to
produce this document. All network-execution behavior described here is
future work behind the existing (still disabled) `AICYBERSEC_LIVE_PROBE_ENABLED`
flag and a future dedicated prober.

**Revision 2** — incorporates the security owner's approval-with-corrections
review: execution-profile binding contract (§4.3), stricter DNS wire-client
specification (§6.3, § 6.4), hard deadline/cancellation requirements (§6.1),
v1 concurrency/counting contract (§7.0), tightened response-size policy
(§6.5), egress boundary as a hard go/no-go gate (§9.4), twelve additional
acceptance tests (§10), evidence-spike stage (§11), and the recorded
approval status (§13). All corrections are design text only.

Label conventions used throughout:

- **[Verified existing behavior]** — confirmed against the current repository.
- **[Proposed design]** — a decision for implementation in Stage 2; not built.
- **[Requires validation]** — evidence must be produced (dependency capability
  proof, benchmark, or deployment check) before the design is finalized.
- **[Known limitation]** — an accepted, documented weakness (never silently
  ignored).

---

## 1. Executive summary

[Proposed design]

Stage 2 adds live website assessment behind an opt-in authorization plane
(shipped in Stage 1) plus a **dedicated, tightly constrained HTTP transport**
that is a separate execution path from the general scanner pipeline. The
transport enforces, at every layer, exactly one request shape: `GET /` on an
exact, admin-authorized HTTP/HTTPS origin (ports 80/443 only), without
redirects, without discovery, without model-driven planning, and only against
a destination IP that was **validated by policy in the same resolution event
that produced the actual TCP connection** (connection pinning). Six strict
budgets (200 requests/scan, 1 req/s, 30 s/request, 600 s wall clock, 256 KiB
responses, 2 connections) are enforced in trusted backend code, are not
client- or model-controlled, and are recorded in an immutable per-scan
`execution_profile` with its own digest anchor. Authorization is re-verified
per request boundary; revocation or expiry mid-scan fails the scan closed.

The application layer cannot defend a compromised backend host: a
kernel/container egress boundary is mandatory as the outer enforcement layer
before anything is enabled.

## 2. Current Stage 1 baseline and explicit limitations

**[Verified existing behavior]**

- Authorization plane: `LiveAuthorization` records (admin-activated,
  immutable, one-way suspend/revoke, max 90-day window, policy version,
  required evidence pointer), immutable per-scan `authorization_snapshot`
  JSONB + external `authorization_snapshot_digest` column, full verification
  in `verify_live_scan_authorization`
  (`backend/services/live_authorization_service.py:647`), F5 cross-check of
  `scan.live_authorization_id` against the snapshot id, FK semantics set to
  `RESTRICT` by additive migration `0004_live_auth_fk_semantics.py`.
- Role-aware API responses (`LiveAuthorizationOut` for admins,
  `LiveAuthorizationOwnerOut` for owners in
  `backend/schemas/live_authorization.py:46/:66`).
- Execution gate: `ScanManager._execute` refuses `live_probe` scans
  (scan_manager.py:239-241) **before** the `initializing` transition, before
  tool registry construction, planner invocation, discovery pre-stage, tool
  runs, assets, and any socket activity
  (`scan_manager.py:393-428 `_refuse_live_probe``).
- Startup recovery re-submits queued live scans; they re-enter the same
  refusal (scan_manager.py:140-190).
- Server-pinned execution values at scan creation from
  `backend/services/live_probe_budgets.py` (`mode`, `max_steps`,
  `tool_timeout_s` discarded if client-supplied).
- Feature flag `AICYBERSEC_LIVE_PROBE_ENABLED` defaults to `False`
  (`backend/core/config.py:54`); no `.env` exists; `.env.example` documents
  `=0`.
- Phase 4C discovery (`discovery_service.py`, `httpx_eligibility.py`,
  `pipeline_planner.py`) is unchanged and is NOT part of the live path.
- ProjectDiscovery HTTPX is a controlled **subprocess runner**
  (`agent_core/tools/httpx.py:22, run_pinned_binary`), not a Python HTTP
  client — per the standing constraint it is NOT a live-mode shortcut.

**[Known limitation]**

- The authorization snapshot/digest mechanism detects accidental or
  API-layer tampering and partial (digest-forgetting) edits; a **coordinated
  database rewrite** of the parent record, snapshot, and both digest anchors
  is undetectable in-system. Accepted in Stage 1; the same limitation applies
  to the `execution_profile` below. Mitigations are deployment controls
  (database access restricted to the application user; external audit
  anchoring as a future option) — NOT code.

**[Verified existing behavior / known gaps carried from the Stage 1 review]**

- Migration `0004` relies on constraint names auto-generated by migration
  `0003` (`live_authorizations_project_id_fkey`,
  `live_authorizations_approved_by_fkey`); correct for the
  migration-managed path, treated as a documented assumption that migration
  round-trip tests must keep covering.
- `create_live_scan` maps any `IntegrityError` to
  `SCAN_ALREADY_RUNNING` (backend/services/live_authorization_service.py:763);
  an FK `RESTRICT` conflict would be mislabeled 409. Fails closed; cleanup
  item for Stage 2.
- Owner-facing scan responses intentionally retain the authorization
  snapshot/digest/authorization-id: the payload contains authorization
  mechanics (origins, methods, paths, window) and never evidence or approver
  data. Admin-only evidence/approver fields remain protected in
  authorization endpoints.

## 3. Threat model and trust boundaries

[Proposed design]

```
Trust boundaries (S2 target state):

  Browser/user ──(untrusted API input)──> FastAPI backend ──(trusted code)──>
      Authorization plane (SS1) ──> execution-profile verification ──>
      dedicated live transport ──(policy-validated egress ONLY)──> target origin
      |                                                                        |
      |-- outer boundary: container/kernel egress filter (netns/firewall) -----+
```

Actors and abuse cases:

1. **Malicious/compromised project owner (tenant).** Goal: get the platform
   to scan unowned or internal hosts. Defeated by: admin-only authorization
   activation, exact-no-wildcard origins (Stage 1), no discovery expansion,
   destination validation + pinning (this design), per-scan budgets.
2. **Model output / planner.** Live mode never consults planner choices for
   behavior (pinned `mode=pipeline`; prober follows only the execution
   profile). Observations (DNS answers, HTTP responses) never expand
   authorization or cooperate with the profile ratings.
3. **Attacker-controlled DNS for an authorized origin (the target's own
   infrastructure attacker).** Goal: rebinding → SSRF to internal metadata /
   private network, or HTTPS-TLS confusion. Defeated by: complete answer-set
   validation (all answers must be global), single-resolution pinning
   (the socket connects ONLY to an address produced by the same validated
   resolution), per-request re-resolution (no stale pins), CNAME-cluster
   rejection of private members, IPv6 scope-id/mapped-address hardening.
4. **Compromised backend process/host.** Application-level controls are
   void. Only the kernel/container egress boundary limits blast radius
   (§9). **Known limitation:** if the boundary host is compromised too,
   NOTHING in this design protects internal networks; this is the explicit
   risk-owner acceptance of enabling live assessment, documented here —
   not hidden.
5. **Intentional abuse of evidence or audit fields by owners.** Defeated in
   Stage 1 (role-gated responses); must remain intact through any Stage 2
   schema additions.

Out of scope: Frontend behavior (backend security gates must pass first),
model/provider integration, multi-container production deployment.

## 4. Execution-profile schema and digest contract

[Proposed design]

### 4.1 Storage choice

Two new nullable `scans` columns (mirroring Stage 1):

- `execution_profile` (JSONB) — rendered once at scan creation
- `execution_profile_digest` (VARCHAR(64)) — external anchor column

Justification: the double-anchor pattern (payload + external digest column)
is **[Verified existing behavior]** for `authorization_snapshot` and is the
only pattern already proven by tests (snapshot tamper tests in
`tests/integration/test_live_probe_gate.py`). A separate table would add
joins/FK semantics without integrity benefit; digests cannot protect against
same-row coordinated rewrites either way (§ 2 Known limitation).

### 4.2 Fields (canonical payload)

```jsonc
{
  "profile_id":        "<uuid4 generated at creation>",  // binds profile to scan lifetime
  "scan_id":           "<scan uuid>",                    // must equal scans.id at verification
  "authorization_id":  "<live_authorization uuid>",      // must equal scan.live_authorization_id
                                                         // AND the snapshot authorization_id
  "project_id":        "<project uuid>",                 // must equal scan.project_id
  "policy_version":    "live-probe/v2",                  // must equal settings.live_probe_policy_version
  "mode":              "pipeline",
  "steps":             ["live_root_get"],
  "executor":          "live_transport_v1",
  "budgets": {
    "max_requests_per_scan": 200,
    "requests_per_second": 1,
    "per_request_timeout_s": 30,
    "wall_clock_s": 600,
    "response_max_bytes": 262144,
    "max_concurrent_connections": 2,
    "dns_timeout_s": 5            // new constant, see §5 note
  },
  "request_policy": {
    "methods": ["GET"],
    "paths": ["/"],
    "ports": [80, 443],
    "follow_redirects": false,
    "honor_env_proxies": false,
    "accept_encoding": "identity"     // avoid decompression amplification in v1
  },
  "dns_policy": {
    "record_groups": ["A", "AAAA"],  // both families ALWAYS queried (§6.3); A-only profiles are invalid
    "answer_set_policy": "all_answers_global",  // reject if ANY answer is non-global
    "cname_following": true,                    // resolved to final A records, then validated
    "cache": "none"                             // resolve fresh at every request boundary
  }
}
```

Type definitions (Pydantic DTO + constants) live in
`live_probe_budgets` single source; the payload carries the values, not the
authorities — the governing source is the `live-probe` policy version.

### 4.3 Verification contract (rev 2: explicit binding rules)

Digest = SHA-256 over canonical JSON (sorted keys, `(",", ":")`, no ascii
escape) of the payload minus the `digest` key — identical algorithm,
[Verified existing behavior] (backend/services/live_authorization_service
`_digest`). **A digest only proves consistency with the stored digest. It is
NOT a signature and NOT an external trust anchor**; every semantic binding
below is verified separately, every time, against live values.

Issuance is creation-time only: rendered and digest-stamped inside
`create_live_scan` RIGHT after the authorization snapshot, from constants
only. **No field is client-controlled** (mirrors Stage 1 pinning at
live_authorization_service.py:756-758, [Verified existing behavior]).

Verification MUST fail closed unless ALL of the following hold:

1. **Scan binding:** `profile.scan_id == scan.id` (the database scan row's
   actual ID — not a value copied from anywhere in the payload chain).
2. **Authorization binding:** `profile.authorization_id ==
   scan.live_authorization_id` AND `profile.authorization_id ==
   authorization_snapshot["authorization_id"]`. All three must agree; the
   same triple-mismatch class the Stage 1 F5 check covers for snapshots
   ([Verified existing behavior]
   live_authorization_service.py:680) is covered identically for profiles.
3. **Project binding:** `profile.project_id == scan.project_id` and, via the
   existing parent-render path, the parent authorization's `project_id is
   the same` (tenant isolation holds through profile + snapshot + parent).
4. **Policy conformance:** `profile.policy_version ==
   settings.live_probe_policy_version` AND EVERY budget value in the
   profile equals the server-side policy constants exactly (field-by-field,
   not "digest only"). This includes the DNS policy:
   `profile.dns_policy.record_groups` must exactly equal the server constant
   `["A", "AAAA"]` — a profile claiming A-only resolution is invalid. A
   profile with older or different limits is invalid even if internally
   self-consistent.
5. **Hardcoded shape:** `profile.executor` and `profile.steps` must exactly
   match a hardcoded allowlist (`{"live_transport_v1"}` ×
   `["live_root_get"]`) — no unknown executor, no extra/renamed steps.
6. **Strict schema:** the payload must parse against the exact profile
   schema: missing security-relevant fields, malformed types, unknown
   fields, and extra steps/budgets all fail closed (no forward-compat
   tolerance for security-relevant fields; unknown fields are REJECTED, not
   ignored — ignoring unknowns is how forgery hides).

Ordering: profile verification runs AFTER §5 gate 4 (parent authorization
re-verified) and must itself re-derive the `authorization_id` from the
STAGE-1-verified snapshot, never from the profile's own claims, so a
re-forged profile+digest pair still fails against snapshot/scan values.

Policy-version change: a bump of `live_probe_policy_version` invalidates
**both** authorization snapshots and execution profiles on their next
verification (same drift-fail-closed behavior as Stage 1 snapshots;
[Verified existing behavior] check pattern reused).
- DB constraints (additive migration `0005_live_probe_execution_profile`):
  two nullable columns on `scans`; extend the existing CHECK
  `ck_scans_live_probe_snapshot` to ALSO require non-null
  `execution_profile`/`execution_profile_digest` for `live_probe` rows
  (single constraint swap, upgrade-only on the lab DB, disposable downgrade
  tests as practiced in `tests/integration/test_migrations.py`).
- In-flight state: Stage-1-queued live scans created BEFORE the additive
  migration lack a profile → verification fails closed ("execution profile
  missing"), matching Stage-1 refusal semantics (those rows never
  executed and must be re-issued).

### 4.4 Interactions with retries / cancellation / recovery

- **Retries:** none at transport level (§8); a profile is never mutated.
  Scan retry = re-verification of the ORIGINAL profile, so a retry cannot
  bypass approval or budgets.
- **Cancellation:** the budget accounting object (§7) is owned by the
  in-thread prober only (single worker thread per scan, [Verified scanning
  architecture: per-scan worker]); cancel signalling uses the existing
  cooperative mechanism (scan_manager cancellation event cancel path reused
  in Stage 1). Scan (profile) is not consulted and is never written back.
- **Queued scans / startup recovery:** unchanged Stage-1 semantics
  (queued → re-submit → full preflight; initializing/running → failed on
  restart). Recovery never resumes mid-flight execution; budget objects are
  constructed fresh from the immutable profile, never persisted counters
  (wall-clock restarts are safe by design: recovery fails INTERRUPTED
  scans [Verified existing behavior]).

Explicit statement: the profile digest protects against accidental edits,
stale-column writes, and application-layer tampering. **It does NOT protect
against a coordinated database rewrite** (same [Known limitation] as §2).

## 5. Preflight verification sequence

Fail-closed order before the FIRST network request:

| # | Gate | Status |
|---|---|---|
| 1 | Feature flag `AICYBERSEC_LIVE_PROBE_ENABLED` == True and prober execution mode resumed/enabled in settings | Stage 2 design (**[Verified existing behavior]**: flag currently False; `_require_flag` exists at creation time only) |
| 2 | Scan is `profile == live_probe`, status eligible (terminal/running refused; queued/initializing proceed under the existing state machine transitions), and directly submitted the first packet gate | Partially [Verified existing behavior] (existing refusal/check); Stage 2 REUSES this order |
| 3 | Authorization snapshot integrity: embedded digest + external anchor column + `scan.live_authorization_id` == snapshot `authorization_id` | [Verified existing behavior] (live_authorization_service.py:647-690) |
| 4 | Parent authorization: exists, `status == active`, `now ∈ [valid_from, valid_until)`, `policy_version` current, belongs to `scan.project_id`, tenant reachable only via this project | [Verified existing behavior] |
| 5 | Execution-profile verification (all §4.3 checks) | **[Proposed design — Stage 2]** |
| 6 | Effective origin selection: exactly ONE origin per request boundary from snapshot `origins` minus `exclusions` (approval scope, never discovery output) | Stage 1 scope-validity [Verified existing behavior]; per-request selection [Proposed design] |
| 7 | DNS resolution at THIS request boundary: fresh A **AND** AAAA answer sets — both families ALWAYS queried ("AAAA when needed for v6" is forbidden wording, §6.3); every answer must be global-unicast (§6 rules); reject on empty/NXDOMAIN/timeout/malformed/scope-bearing/mixed answers | **[Proposed design]** |
| 8 | Connect to EXACTLY one address from the validated answer set of the SAME resolution (no second lookup, no pool re-resolution, no happy-eyeballs fallback to unvalidated IPs) | **[Proposed design]** |
| 9 | TLS: hostname-based SNI = authorized hostname (never the IP); certificate chain verification against that hostname; certificate hostname validation unaffected by pinning | **[Proposed design]** |
| 10 | Continuous rechecks during execution: cancellation event, authorization revocation/status (pre-request authorization re-check at every request boundary: DB read of parent status/window — cheap, no I/O inside), budget counters (at attempt start AND at write back), wall-clock deadline, etc. | **[Proposed design]** |

Once-only vs repeated: gates 3-9 are verified ONCE per request boundary
(cheap; no network inside), gate 7-8 together per REQUEST (the same
resolution event), gate 2's stage transitions per scan lifecycle, gate 10
repeats continuously. There is no point where a gate result obtained in a
previous request is reused to authorize a new request.

## 6. Destination-pinning transport design

[Proposed design — candidate selection requires validation; no library has
been chosen and no transport has been written]

### 6.1 Hard requirements (any candidate must satisfy — otherwise declared unsuitable)

1. Single-pass resolution→connect: the code path that computes the socket
   destination must consume a validated `ipaddress` value produced by the
   SAME resolution the policy validated. No implicit second DNS lookup, no
   happy-eyeballs iteration over a fresh lookup, no pool-maintained DNS
   cache.
2. TLS SNI + certificate hostname verification derive from the AUTHORIZED
   HOSTNAME, while the TCP peer is the PINNED IP.
3. No proxies: neither vm arg proxies nor implicit environment variables
   (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `REQUESTS_*`,
   lowercase variants) may influence the connection.
4. Per-phase deadlines: DNS, TCP connect, TLS handshake, headers, body —
   all bounded by the same wall-clock deadline (30 s per request).
5. Bounded reads: response body buffered up to 256 KiB hard cap, then
   truncated/abandoned (no streaming into unbounded memory).
6. No redirects at the HTTP layer (client never follows 3xx), no automatic
   retries, no transparent re-auth.
7. Deterministic: same profile + same answer-set → same request envelope;
   no nondeterministic connection reuse across origins/authorizations.
8. Full control of connection pooling: pool maintained per (scan, origin,
   authorization_id); every connection closes at scan end or when revoked;
   nothing is reusable across scans.
9. **Hard, interruptible deadlines:** a single monotonic deadline
   (`time.monotonic`-based) covers DNS + connect + TLS + headers + body per
   request; EVERY blocking operation must use a socket timeout recalculated
   as `remaining = request_deadline - now()` immediately before the call —
   a cancellation check BETWEEN blocking calls alone is insufficient. If a
   candidate cannot bound or interrupt a blocked DNS query or socket read,
   it is UNSUITABLE.
10. **Safe I/O interruption on cancellation:** a cancellation event must
    actively close/interrupt in-flight sockets (watchdog or bounded-poll
    design — exact mechanism is an evidence-spike deliverable), not merely
    be consulted between operations. Safe close = close the socket file
    object once, from exactly one party; the blocked call then fails with
    an error mapped to `cancelled` (never silently retried).

If a candidate cannot guarantee (1), it is UNSUITABLE — no unsafe fallback
(plain preflight DNS validation outside the connection code path is
explicitly insufficient: TOCTOU between validate and connect).

### 6.2 Candidates and required evidence

[Deps verified: main dependencies contain no HTTP client; `httpx>=0.27` is a
DEV extra; runtime is Python 3.11; the existing "httpx" tool is a
ProjectDiscovery subprocess (`agent_core/tools/httpx.py`), unrelated.]

- **Candidate A (leading): stdlib `http.client.HTTPSConnection` subclass.** Own
  subclass connects to the pinned `(ip, port)` via raw `socket.create_connection([(ip, ...)])`-style override while `wrap_socket` keeps
  `server_hostname=<authorized hostname>`; redirects/pooling/retries are the
  app's code (we need NONE — one shape). Zero new dependencies. **[Requires
  validation]:** exact stdlib behavior proof on 3.11 (server_hostname with
  pinned IP; `HTTPConnection` never honors env proxies — verify;
  `Host:` header correctness; deadline plumbing into `HTTPResponse` reads).
- **Candidate B: vendor `httpx` (+httpcore) and custom transport
  subclassing `httpx.HTTPTransport` via a custom `httpcore` pool.** Blocked
  on documented/ip-core proof that a custom pool hook can guarantee (1)
  without monkey-patching resolution internals. **[Requires validation].**
- **Candidate C: `aiohttp` + custom `Resolver`.** Known structured hook
  (`TCPConnector(resolver=...)`), proven design pattern for (1); TLS
  `server_hostname` pass-through must be proven; adds async runtime mismatch
  (app is sync/thread-based). **[Requires validation].**
- **Candidate D: ProjectDiscovery httpx subprocess / NetworkX / Nuclei /
  Subfinder / HTTPX / DNSX tools.** UNSUITABLE for live mode by design
  (no pinning guarantee, autonomous capabilities violate the memory
  architecture: [Verified existing behavior] they are subprocess-based and
  policy-independent).

### 6.3 Resolver design (rev 2: strict wire-protocol specification)

[Proposed design]

**Resolver selection.** Direct DNS wire-protocol client over UDP (stdlib
`socket`, single trusted resolver address from settings — **never**
`getaddrinfo()` or any OS resolver, which would reintroduce OS caching and
uncontrolled channel behavior). There is **no fallback resolver of any
kind**: any DNS failure — timeout, partial data, malformed packet, TC
truncation without a successful bounded TCP retry — fails the boundary
**closed**. A test proves that NO resolver-fallback attempt ever occurs
(§10 T31).

**Trusted resolver configuration.** Exactly one configured lab resolver
(address validated as a global IP address by the same §6.3 address policy),
sent the queries directly. DNS egress is additionally restricted by the
outer boundary (§9): only the designated resolver may be reached on port
53 from the live-probe runtime. **[Requires validation]**: the lab network
must demonstrably block DNS to any other destination (§10 T40).

**Protocol handling rules (all fail closed):**

- **Transaction ID:** each query uses a fresh random 16-bit ID; responses
  whose ID does not match the outstanding query are DISCARDED (counted as
  no-answer attempts) — no blind acceptance of unsolicited datagrams.
- **Question matching:** the response question section must EXACTLY match
  the queried hostname and type; anything else → reject the packet.
- **RCODEs:** NOERROR → proceed to evaluation; NXDOMAIN, SERVFAIL, REFUSED
  or any other code → boundary fails closed (no retry, no second resolver).
- **Truncation (TC flag):** a TC response is NOT accepted over UDP. The
  client retries the SAME query over TCP to the same trusted resolver with
  the same remaining deadline budget; a second TC/timeout → reject boundary
  (nothing ever falls back to the OS resolver).
- **Malformed packets:** any parse failure (length mismatches, name
  pointer loops, bogus offsets) → reject the response entirely and fail
  the boundary; malformed answers are never partially used.
- **Answer-set construction:** ONLY answer-section records that belong to
  the question name or the resolved CNAME chain are used. Additional
  (glue/authority) records are **NOT authoritative for this resolution**:
  they are ignored, and their presence never expands validation
  ("rejection-of-the-actually-used-records" rule — unused junk neither
  saves a resolution nor poisons it; any answer-section record that cannot
  be tied to the resolved chain makes the result AMBIGUOUS → reject).
- **CNAME chains:** followed within the answer section only, with **loop
  detection** (visited-name set; revisit → reject) and a **maximum depth
  of 8 hops** (excess → reject). Each chain member's ownership is matched
  to the original question name; orphan chains → reject.
- **Dual stacks:** A **and** AAAA are ALWAYS queried for the authorized
  hostname — both address families are validated whenever a dual-stack
  hostname returns records. "AAAA when needed" is FORBIDDEN wording: the
  v1 transport connects over one family only (IPv4 preference for an IPv4
  lab), but BOTH families' records must pass the address policy or the
  whole boundary result is rejected (an unvalidated AAAA record is an
  unvalidated egress path in future transports).
- **Address policy (every returned address used for resolution AND every
  address in the validated answer sets used in this boundary):** validation
  rules of §6.3's address list below apply; ANY violation → reject the
  COMPLETE result set (never partial connect).
- **Timeouts:** DNS query deadline is the remaining request deadline
  capped at `dns_timeout_s` (5 s, [Requires validation]) — a timeout or
  partial response NEVER triggers fallback (explicit T31).

Address policy — REJECT ANY answer that is or maps to:

- unspecified `::`/`0.0.0.0`; loopback `127/8`, `::1`
- private ranges `10/8`, `172.16/12`, `192.168/16`, `fc00::/7`
- link-local `169.254/16` (incl. metadata `169.254.169.254`), `fe80::/10`
- IPv4-mapped IPv6 `::ffff:0:0/96` (any mapped member in a v6 answer → reject)
- multicast/reserved/benchmark/documentation: `224/4`, `ff00::/8`,
  `240/4`, `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `198.18/15`,
  `2001:db8::/32`
- deprecated/other: `::/128`, site-local `fec0::/10`, ambiguous or
  scope-bearing addresses (`ipaddress.IPv6Address` with a non-empty
  `scope_id` → reject)
- shared address space `100.64/10` (CGNAT ranges are private in effect)

Global-unicast allow test (`ipaddress.ip_address(x).is_global`) is a
NECESSARY condition, never a sufficient one — the explicit denies above
also apply (defense against `is_global` drift across Python patch
releases; [Requires validation] against the pinned runtime version).

Mixed safe/unsafe answer sets → REJECT the whole boundary (fail-closed,
no partial connect). Repeated resolution is REQUIRED at every request
boundary; no pin cache or OS cache is consulted across boundaries, which
bounds the rebinding window to one request's DNS+connect lifetime
(§10 T13). Numeric/binary hostname spellings are irrelevant here: the
authorized HOST is Stage-1-validated (no IP-literal hosts; [Verified
existing behavior]) — this section validates ADDRESSES returned by DNS.

**Pin handoff proof obligation:** the transport must demonstrate —
structurally and by test (§10 T14/T13/T24) — that the TCP connection code
receives the validated `ipaddress` object itself (not a hostname to
resolve again, not a cached tuple from outside the validated resolution).
The connect code path has NO DNS name parameter.

- **[Known limitation]:** server-side DNSSEC validation is out of scope for
  v1 (no upstream validation library in deps); DNS-level tamper resistance
  relies on answer-set validation + documented trust in the single trusted
  resolver. Resolver trust is a deployment parameter, not a code
  assumption.

### 6.4 Connection behavior

[Proposed design]

- Pool: at most `max_concurrent_connections` (2) sockets per (scan,
  authorization_id, origin), each KEEPS dying keep-alive against the same
  validated (origin → pinned IP) but only within the same request chain:
  **one resolution event per request boundary drives its own connect;**
  pooled reuse is permitted ONLY if the socket's remote peer was validated
  by the SAME PREVIOUS resolution that produced it AT THE CURRENT BOUNDARY:
  v1 design: **no pooled reuse across boundaries** (each request boundary
  re-resolves → fresh connect; pinning-weight simplicity over performance).
  This is v1-safe and converts pooling to a "connection is per-boundary
  object". Keep-alive pooling can be revisited after acceptance only.
- Socket connection validation additionally on THIS peer: after connect,
  before ANY HTTP byte: `socket.getpeername()` re-check == validated IP
  (belt and bracers T-O-I binding in-case of an exotic OS scheduler).
- `Host` header == authorized hostname (never IP); SNI == hostname; cert
  chain hostname == authorized hostname. Trailing normalization is irrelevant
  (Stage 1 origins end at `:`-default banner phase; hostname canonical form
  is the DNS form used for resolution and TLS).

### 6.5 Response content handling (rev 2: tightened size contract)

[Proposed design]

- The request carries `Accept-Encoding: identity`. If the server responds
  with ANY other `Content-Encoding` (gzip, deflate, br, zstd, ...), v1
  does NOT decompress: the response is treated as a malformed/unacceptable
  boundary outcome, the body read is aborted at the raw-byte cap, and the
  observation records `content_encoding_rejected`. **No decompression path
  exists in v1** — decompression amplification is structurally impossible,
  not merely mitigated. If decompression is added later, it MUST enforce
  independent caps on compressed input bytes AND decompressed output bytes
  (breaks the "3 GB from 3 KB" class), and it MUST be a profile-level
  policy change (bumping the policy version), never a code-config toggle.
- A **hard cap of 256 KiB raw bytes is enforced on bytes read from the
  socket**, regardless of framing: readers count every byte consumed from
  the wire. `Content-Length` is NEVER trusted as the sole control —
  a lying (oversized) header, a chunked stream without end, or a
  contentless body with infinite padding all end at the SAME
  hard read cap (§10 T34/T36).
- No response body is ever buffered beyond the cap: the read loop stops at
  the ceiling and the remainder of the connection is discarded. Headers
  themselves are line-bounded and length-capped as part of the same read
  discipline (an endless header decade terminates at the deadline).
- Redirect responses (3xx) are treated as ORDINARY observations: recorded,
  NEVER followed (no `Location` handling code, no fallback follow), the
  boundary terminates after one request for that boundary. Anything
  discovered in redirect targets is an observation — not authorization
  (matches Stage-1 invariants: [Verified existing behavior] that discovery
  results never expand scope).
- No proxy layer exists in the transport; if any future proxy setting is
  introduced, it MUST also be pinned in `execution_profile.request_policy`
  (per-scan) and re-validated; today `honor_env_proxies: false` is a design
  assertion, pending an acceptance test (§10 row "proxy env poisoning make
  no difference").

## 7. Budget-enforcement matrix

[Proposed design — NONE of these are implemented; constants alone are no
enforcement, verified in stage-1 review]

### 7.0 v1 concurrency and request-accounting contract (rev 2)

Plainly stated, to eliminate ambiguity between "2 connections" and
"single worker thread":

- **Initial concurrency: ONE active request per scan at any moment.**
  No overlapping DNS/connect/TLS/body operations across boundaries.
- **Maximum permitted connections: TWO — a HARD SAFETY CEILING, not a
  target or a pipeline dimension.** The second connection is admitted only
  for exceptional transport states (e.g. an abandoned socket awaiting close
  while a next-boundary socket opens after a boundary failure); steady-state
  v1 uses exactly one.
- **Connection reuse: DISABLED across request boundaries in v1.** Each
  boundary opens a fresh connection from the same validated resolution;
  pooling across boundaries is structurally absent (see §6.4 — a
  "pooled-connection" object cannot exist in v1 to be reused).
- **Request accounting performed atomically: reserve-and-increment the
  request budget BEFORE the DNS/network attempt begins** (single worker
  thread ⇒ simple atomic sequence; the increment must nonetheless live in
  one critical section so a future multi-worker design cannot double-spend).
- **Retries: NO automatic retries anywhere** — not at DNS level, not per
  connection, not per response. Overlayed transport-level retry candidates
  (TCP for TC responses) are protocol-completion rules from §6.3, not
  retry attempts, and never re-issue a completed request.

**Rate-limit scope decision:** 1 request per second applies **per SCAN,
regardless of how many origins the authorization approves** — origin-level
pacing is NOT granted in v1. A multi-origin authorization still yields one
paced sequential stream: the scan is the pacing domain.

| Budget | Enforcement layer | Scope | Race handling | Counting | Exhaustion |
|---|---|---|---|---|---|
| 200 requests/scan | Prober code (trusted, NoEnv, in `live_transport_v1`) | per scan | single worker thread per scan ⇒ no race; ScanManager guarantees ≤1 non-terminal scan/project ([Verified existing behavior] partial-unique index); increment is one atomic reserve-then-increment section per boundary | incremented and RESERVED **before** the network attempt (DNS query counts as attempt start; connect/TLS/body failures count; successful redirect RESPONSES count as spent requests) | stop issuing requests; finalize scan `completed` with `budget_stop= "request_budget"` recorded in execution summary |
| 1 req/s | Prober scheduling code | **per scan — regardless of the number of approved origins** (sequential requests, fixed spacing) | single thread ⇒ no race | n/a (spacing between request boundaries, no queue) | never blocks forever: deadline checks keep spacing < wall-clock |
| 30 s/request timeout | Transport-level deadline with a top-level `deadline = request_start + 30s` threading EVERY phase; connect-suspension check inside blocking calls; socket timeouts recalculated against remaining time per §6.1(9) | per request | n/a (single-thread within the request) | deadline starts at attempt start (budget already counted) | request aborted; scan may continue to next boundary until outer budgets allow; deadline aborts count as request failure |
| 600 s wall-clock | Prober loop `deadline = scan_start + 600s`, also mirrored in transport deadlines calculation | per scan | single worker | started at first request boundary | current request aborted cooperatively; finalize `completed` with `budget_stop="wall_clock"` (audit-visible) |
| 256 KiB response | Transport body reader: hard raw-byte cap per §6.5 (no decompression path exists in v1; if ever added, independent compressed-input AND decompressed-output caps are mandatory) | per response | n/a | request already counted | response recorded truncated/encoding-rejected; scan continues |
| 2 connections | Transport pool cap (hard bound in code, not config) | **hard safety ceiling per scan/origin — not a target** (§7.0) | single thread ⇒ no race | connections opened per request boundary (v1 = 1) | never exceed cap: fresh-connection-per-boundary keeps steady state at 1 |

None overridable by API/model: profile carries these values from server
constants only; no env var or API field exists for them
(**[Verified existing behavior]** for `ScanCreate` shape + Stage-2 profile
issuance design in §4.3).

## 8. Lifecycle and failure semantics

[Proposed design — terminal states follow existing ScanManager conventions
**[Verified existing behavior]**: `queued, initializing, running,
cancelling, completed, failed, cancelled` (models.py:136-137); no new
states]

| Situation | Outcome |
|---|---|
| Authorization revoked/suspended before first boundary | preflight aborts: `failed`, error `Live authorization rejected: ... revocation/suspension...`; zero sockets [Verified caller path] |
| Revoked / expired at any LATER request boundary | abort in-flight request cooperatively (shutdown socket), `failed`, error records boundary # that observed the change; per-request DB re-check (no in-process approval caching authoritative state) |
| User cancel at DNS/connect/TLS/headers/body | existing cooperative cancel ([Verified scanning suspension behavior: stage-1 manager], now bound to the new transport): cancel event flips at next poll point inside each phase; socket force-closed; finalize `cancelled` |
| Budget exhausted (requests/rate/wall-clock/size) | finalize `completed`, `budget_stop` recorded (results are observations, not failures) |
| DNS rebinding / disallowed answer set / timeout / NXDOMAIN at a boundary | boundary fails CLOSED; scan finalized `failed`, error `dns_validation_failed: ...` (fail-fast; per-authorization failure policy: re-issue authorizationлерг needed to investigate) |
| Redirect response | recorded as observation; scan continues to next allowed boundary until budget stops; per-boundary not followed |
| Network timeout / TLS failure / malformed response | count as a request attempt spent (accounted before attempt), record boundary outcome, continue until budgets; malformed HTTP may mark boundary failed without scan failure |
| Worker crash / backend restart while running | existing recovery: initializing/running → `failed` (`_RESTART_ERROR`) [Verified existing behavior]; live never resumes mid-flight; queued → re-submit → FULL preflight incl. profile (§4.4) |
| Partial completion | per-boundary observations persisted as scan events/assets EXACTLY like Phase-4C result persistence does [Verified existing behavior pattern re-use]; there are no "partial" non-terminal states: any boundary outcome above yields ONE of completed/failed/cancelled |

No retry ever bypasses: budgets are never reset except by re-creating a
scan/authorization lifecycle; authorization re-verification precedes every
boundary; destination validation is per-boundary (a previously validated IP
is NEVER reused for a later connect).

## 9. Egress-boundary design (kernel / container layer)

[Proposed design; repo contents make no proven firewall/libcapture/network
policy exist — **[Known limitation]**: nothing in this repo currently
deploys an egress boundary; `docker/docker-compose.extra-targets.yml` and
`docker/local-lab/` are untracked local artifacts whose contents are NOT
documents; their contents are not claimed here]

1. **Layer 1 — application (this design):** authorization snapshot + result
   profile verification + answer-set policy + single-resolution pinning +
   budgets. NOT defensible as the sole boundary and NOT effective
   against a compromised backend.
2. **Layer 2 — network boundary (mandatory before enabling anything):**
   - Dedicated network namespace/container for the live-probe process
     (or backend process) with NO default route to the internet; outbound
     allowlist: DNS to the configured lab resolver only; TCP 80/443 only to
     lab-target addresses under nftables/ipset (challenge: dynamic IPs of
     the lab target are the only legit destination class; apply at the
     kernel via ipset group populated ONLY by a trusted sidecar reading the
     validated pinned IP from the prober's audit log — or simplify lab-use:
     fixed lab-set of target IPs).
   - Metadata endpoint hardened at L2: link-local `169.254/16` (incl.
     `.254.169.254`) DROPped container-side (kernel tails; impossible on
     some cloud environments to ALTER; assert per deployment).
   - NO cloud-shared/multi-tenant network adjacency for v1; live mode runs
     ONLY in the explicitly configured lab environment.
3. **Layer 3 — deployment assumptions (operational):**
   - Backend DB account is least-privilege (application user only; no DDL,
     no cross-DB) — DB write compromise containment [deployment parameter,
     **[Requires validation]** per environment].
   - Process runs unprivileged (no CAP_NET_ADMIN); container rootfs
     read-only; host hardening out of scope — documented.
   - Secrets (any lab authorization) never on the node filesystem beyond
     runtime need.

**Security consequence if backend host is compromised:** application
controls (pinning/budgets/authorization checks) are all executed in-process
and are fully void. The only residual mitigation is Layer 2's egress filter
restricting the compromised process to designated lab targets; if Layer 2
is ALSO bypassed/compromised, nothing in this document limits exfiltration
or SSRF. This is the reason live mode remains flag-gated OFF everywhere
except the explicitly authorized lab environment (**[Verified existing
behavior]** today; [Proposed deployment policy]).

### 9.4 Egress boundary as a HARD go/no-go condition (rev 2)

**[Proposed design — gate, not implementation claim]** Before ANY live
request is attempted, an isolated Linux lab environment must DEMONSTRATE
(reproduce on demand, not just document):

1. The live-probe process can reach **only** explicitly approved lab
   destinations and its configured trusted resolver — nothing else.
2. Loopback, private-range, link-local, metadata, and every other
   prohibited destination class from §6.3 is **blocked by the network
   boundary itself** (kernel/nftables/netns/container routing), verified
   from inside the boundary's network namespace.
3. The backend cannot bypass the boundary through an alternate route,
   second interface, managed proxy, or DNS redirection — attempts are
   actively made and shown to fail.
4. Enforcement is demonstrably applied by the host/network layer — e.g.
   rules visible in the namespace's kernel state — NOT by the
   application's validator.

**If this cannot be demonstrated, live execution stays disabled.** A policy
document, an application-level unit test, or a code review is NOT a
substitute for the Layer-2 demonstration (this maps to §10 T25/T37/T40 and
the S2-4 stage gate).

## 10. Acceptance-test matrix

[Proposed design — test plan only; none exist except where marked
**[Verified existing behavior]**: authorization/snapshot/tamper,
suspended/revoked/expired cases, FK semantics, execution refusal are
already covered in `tests/security/test_phase5_live_authorizations.py`,
`tests/api/test_live_scan_authorizations.py`,
`tests/integration/test_live_probe_gate.py`,
`tests/integration/test_phase5_fk_semantics.py` — they must keep passing]

Test classes: **U** = unit (no I/O), **FT** = deterministic fake-resolver +
fake-transport (in-process), **PG** = PostgreSQL integration
(disposable/controlled rows, no network), **NS** = isolated
network-namespace/container-side validation (Linux; no real external
targets — the lab target container is the ONLY authorized destination).
No test accesses any real-world target; no real authorization evidence in
fixtures (placeholders only).

| ID | Class | Purpose | Setup | Expected | Layer |
|---|---|---|---|---|---|
| T01 | U | profile tamper: payload edited, digest stale | build valid profile, mutate field | verification fails closed | profile verify |
| T02 | U | profile ID mismatch: scan_id!=scan.id | swap scan_id | fail closed | profile verify |
| T03 | U | MISSING profile/digest (pre-migration rows) | old schema row | fail closed (no execution) | profile verify |
| T04 | U | authorization + profile double-tamper (digest re-forged entirely) | recompute BOTH digests | fail: profile-binding fail (still fail-closed) [Known mitigation class] | profile verify |
| T05 | PG | tamper-at-DB: SQL UPDATE with stale digest | direct SQL mutate | preflight refusal | DB CHECK + profile verify |
| T06 | PG | profile present, auth ID mismatch (A-scan/B-profile) | craft mismatch | fail closed | §4.3 §5(3) |
| T07 | U/PG | expired / suspended / revoked authorization | staged rows | no network; terminal failed | snapshot verify |
| T08 | FT | revocation mid-scan (between boundaries) | fake transport; revoke after first boundary | abort + fail; no further requests | per-boundary recheck |
| T09 | FT | user cancel mid-DNS/TLS/headers/body | hooks per phase | cooperative abort; `cancelled` | transport |
| T10 | FT | public-only answers | resolver returns only global IPs | request proceeds | §6.3 |
| T11 | FT | answers containing ANY of loopback / 10/8 / 172.16/12 / 192.168/16 / 169.254.169.254 / 100.64/10 / `::ffff:127.0.0.1` / `fe80::1%eth0` / `fec0::1` / `2001:db8::1` / `0.0.0.0` / `224.0.0.1` / TEST-NETs | mixed + single-only variants (each row) | boundary fails closed; zero sockets | §6.3 |
| T12 | FT | CNAME chain to private final A | chain config | reject whole boundary | §6.3 |
| T13 | FT | rebinding: resolver called twice returns mismatched answers | resolver returns A1 then A2; transport connects only via resolver output | connect attempted ONLY to A1 of same resolution; A2 connect never happens (assert on fake socket log) | single-pass pin |
| T14 | NS | exact-IP pinning proof | lab target has two IPs; validated P1; OS route would pick P2 by happy-eyeballs | socket peer == P1 exactly (getpeername assert) | §6.4 |
| T15 | NS | TLS host verification + SNI | mitm-cert'd lab replica | handshake SNI == hostname (wire capture); hostname mismatch certs rejected; IP-as-SNI never sent | §6.4 |
| T16 | FT/NS | redirect rejection | fake/lab 3xx to hostile URL | recorded; NOT followed; no second request | §6.5 |
| T17 | U | non-GET, non-root-path, alternate port | policy unit | refused by construction (profile/policy constants) | §4.2 |
| T18 | FT | proxy env poisoning | `HTTP(S)_PROXY`/`ALL_PROXY`/lowercase set to lab collector | no collector contact; direct-to-pin only | §6.1(3) |
| T19 | FT | request-count + rate races under repeated boundaries | N boundaries rapid-fire | count monotonic; rate spacing holds; budget stop accurate | §7 |
| T20 | FT | response-size cap (gzip-ignored server) | fake body > 256 KiB (under gzip identity & with server ignoring encoding) | truncated at cap; memory bounded (peak RSS assert / buffer assert) | §7 |
| T21 | FT | per-request deadline at each phase | fake transport hangs per phase | 30 s deadline aborts; per-phase observed | §7 |
| T22 | FT | wall-clock exhaustion mid-scan | long sequence | cooperative stop; `completed` + `budget_stop` | §7 |
| T23 | PG | no tool registry/planner/discovery/registry: live path never constructs them | inspect `ToolRun`/`Asset`/events after partial/final scan | forbidden rows absent ([Verified existing behavior] shape) | §5 |
| T24 | FT | preflight gate failure ⇒ NO network attempt anywhere | one gate broken per row (flag/snapshot/profile/DNS) | fake transport reports zero connections | §5 |
| T25 | NS | egress boundary effective | attempt connect to non-lab IP from inside boundary container | blocked by kernel (assert exit/timeout); not by app semantics | §9 |
| T26 | PG | tenant/project isolation | cross-tenant authorization/scan/profile references | all fail closed (extends [Verified existing behavior] anti-enumeration) | §5(4) |
| T27 | FT | DNS TC (truncated) responses handled by bounded TCP retry; second TC/timeout → reject | fake resolver emits TC, then refuses TCP | boundary fails closed; no UDP replay storm; no OS fallback | §6.3 |
| T28 | FT | malformed DNS packets (bad offsets, pointer loops, wrong question) | crafted corrupt responses | rejected; boundary fails closed; nothing partially used | §6.3 |
| T29 | FT | CNAME loop + excessive depth (9 hops) | crafted cycle chain | loop/excess depth → boundary rejected | §6.3 |
| T30 | FT | unmatched response ID / wrong question name / hostile RCODEs | replayed wrong-ID + NXDOMAIN/SERVFAIL/REFUSED responses | packets discarded, boundary fails closed | §6.3 |
| T31 | FT | NO resolver fallback, ever | resolver dead/timeout; OS env LRESOLV paths primed | zero `getaddrinfo` calls (call-tracing assert); boundary fails closed | §6.3 |
| T32 | FT | DNS cancellation + deadline expiry mid-query | hang resolver; cancel at t=X; deadline test | in-flight DNS aborted at bound; accounted as spent attempt | §6.1(9-10) |
| T33 | FT/NS | connect / TLS handshake / header / body timeout separately | phase-specific hangs per test row | each phase bounded by remaining deadline; abort observed per phase | §6.1(9)/§7 |
| T34 | FT | request-budget race at the FINAL available request | two boundary attempts at exactly 199/200, rapid-fire | exactly one spends the last available request (reserve-before-attempt holds); second boundary sees stop | §7.0 |
| T35 | FT/NS | server lies about Content-Length | claim small, stream huge (or inverse) | enforced by raw-byte cap, NOT the header; truncation at 256 KiB | §6.5 |
| T36 | FT | unexpected compressed responses / decompression amplification | gzip responding despite identity + 3-deep bomb payload v2 | v1: encoding rejected, raw-byte cap enforced; no decompression attempted | §6.5 |
| T37 | NS | revocation while a request is blocked inside I/O | fake/lab blocked response; revoke callback mid-read | in-flight socket closed by watchdog/cancel path; scan `failed`, zero further requests | §6.1(10)/§8 |
| T38 | FT/PG | altered profile with RECOMPUTED digest but mismatched authorization/project/scan binding | DB-crafted coherent-forge | verification fails on BINDING rules (§4.3 rules 1-3), digest alone insufficient | §4.3 |
| T39 | FT | explicit no-HTTP-after-any-failed-preflight check | break each §5 gate in turn before attempt 1 | fake transport + socket-tracing prove ZERO HTTP connections in every case | §5 |
| T40 | NS | network-level bypass attempts against lab egress rules | direct connect/spoof/DNS-over-alternate-port attempts from inside the namespace | all fail at kernel layer; prover evidence captured | §9.4 |

Fake vs real division (rev 2 statement): FT rows run entirely against
in-process fake resolvers/transports and prove TRUSTED-CODE LOGIC—they
never prove OS/socket/TLS/kernel behavior. NS rows use actual sockets,
real TLS, and an isolated Linux network namespace and are the ONLY rows
that may claim connection-level or kernel-level proof (T14, T15, T25,
T37, T40). Both classes are required before enablement; FT success
NEVER substitutes for NS success.

Go/no-go: ALL applicable tests T01–T40 must be green — with fake-transport
evidence where the row specifies FT, and network-namespace evidence where
the row specifies NS (FT success never substitutes for NS). That full
matrix is the enabling condition; no partial enabling. Enabling is
additionally gated on: §9 Layer-2 deployment check per lab, feature flag
explicitly set ONLY in lab config, decision sign-off.

## 11. Implementation stages and go/no-go criteria (rev 2 sequence)

[Proposed design — sequence per the security owner's review]

| Stage | Deliverable | Go/no-go |
|---|---|---|
| S2-1 (this doc) | design + threat model + test plan | **approved** subject to corrections (§13); corrections applied in rev 2 |
| S2-2 | execution-profile contract ONLY: schema + explicit §4.3 binding rules, issuance at `create_live_scan`, verification extension, additive migration `0005`, U+PG tests (T01-T06, T38@PG), plus the localized `create_live_scan` IntegrityError-mapping cleanup (§12.6) | migration round-trip clean; U/PG green; live execution STILL refused; zero sockets |
| **S2-2.5 — Transport evidence spike** | proof, using LOCAL test servers only (loopback-only bind inside an isolated netns, no lab-external egress): the chosen HTTP client can (a) pin the socket to a validated IP while preserving TLS SNI + hostname verification, (b) enforce a monotonic deadline across DNS/connect/TLS/header/body with socket timeouts computed against remaining time, (c) safely interrupt blocked I/O on a cancel event (§6.1 items 9-10) | every hard requirement of §6.1 evidenced; if any requirement cannot be met, that candidate is declared UNSUITABLE and re-selection happens FIRST — no unsafe fallback is ever written; transport implementation does not start until this stage passes |
| S2-3 | transport core per the evidence-backed design: resolver (§6.3 wire client + address policy), pinned connection, request policy, budgets behind the dedicated executor — exercised ONLY via fake transports; actual live execution still refused | T27-T36, T39 (FT versions) green; still zero real egress |
| S2-4 | isolated network-namespace/container harness + egress boundary | T14, T15, T25, T37, T40 green; §9.4's four demonstrations reproduced on demand — this is a HARD gate; failure keeps execution disabled |
| S2-5 | enablement review (lab only): complete acceptance matrix green, implementation-diff security review, deployment-boundary verification, rollback runbook | explicit owner approval; flag flipped ONLY in the isolated lab config; repo defaults stay `False` |

Each stage ends with a review gate; no stage skips the refusal/flag
invariants; Phase 4C untouched throughout.

## 12. Open questions and unresolved decisions

1. **[Requires validation]** Transport candidate selection (§6.2): stdlib
   `http.client` subclass vs vendor `httpx`/aiohttp. Candidate A is the
   leading proposal (zero deps, pinning trivially controllable); the
   validation spike must prove SNI/server_hostname behavior on 3.11 and
   no-env-proxy behavior before any code is written.
2. **[Requires validation]** Direct DNS wire client vs OS resolver
   (`getaddrinfo`): the direct-wire design gives complete answer sets and no
   OS caching (required by §6.3); must confirm upstream port 53 egress is
   acceptable in the lab network. dnspython remains a candidate (new
   dependency) only if the raw-wire client proves brittle.
3. **[Requires validation]** `dns_timeout_s=5` tuning (§4.2) and
   inter-request pacing at higher loads (>1 origin per scan IS possible in
   the profile; v1 keeps per-scan pacing).
4. **[Known limitation]** DB-approved audit anchoring (external anchor to
   detect coordinated rewrites) — deferred until Stage 3+; acceptance of
   the DB-tier compromise risk is required to enable live mode at all.
5. **[Requires validation]** Egress Layer-2 implementation details per lab
   (§9): ipset/netns vs container-network policy; the repo does not contain
   any of it today (`docker/local-lab/` is untracked and was not inspected
   as content — the document intentionally does NOT claim anything about
   its contents).
6. **[Proposed]** carried-forward cleanup: 0004 constraint-name assumption
   documentation; `create_live_scan` IntegrityError mapping narrowing; both
   are Stage 2 alongside the profile contract (S2-2), not blockers.

## 13. Approval status (recorded from the security owner's rev-2 review)

- **Design architecture: APPROVED, subject to the corrections above** — all
  corrections (A-F, test additions T27-T40, revised sequence, egress hard
  gate) are incorporated in this revision.
- **S2-2 (execution-profile contract): MAY PROCEED** once the profile-binding
  requirements (§4.3) are incorporated into the implementation task.
- **Live transport implementation: NOT yet approved** — the transport
  evidence spike (S2-2.5) must be completed first, with the hard
  requirements of §6.1 items 9-10 and the pinning proof per §6.3.
- **Actual network requests: NOT approved.** Nothing in S2-2 through S2-4
  may make a real external request; fake transports and isolated local
  netns lab servers only.
- **Feature flag: must remain disabled** (`AICYBERSEC_LIVE_PROBE_ENABLED`
  default `False`; [Verified existing behavior]).
- **Phase 4C: must remain untouched.**

---

*End of design document. Nothing here changes runtime behavior; live
execution remains refused and the flag remains disabled.*
