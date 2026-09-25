"""Hostname -> resolved-IP scope authorization bridge (Phase 3).

The target_snapshot is the ONLY authorization source. A discovered IP
(Nmap observation, redirect target, anything else) is NEVER authorized
by itself. An IP IS authorized only when it is deterministically
established as a forward-DNS resolution of an already-authorized
hostname:

    authorized hostname -> forward DNS (injectable) -> resolved IP

Security properties:
- Provenance is deterministic DNS resolution performed by US - never a
  scanner observation. If Nmap reports 172.18.0.3 but DNS resolves the
  authorized hostname to 172.18.0.4, then 172.18.0.3 is REJECTED.
- The resolution is derived at scan start and never persisted as a
  permanent allowlist; the snapshot remains authoritative.
- Redirect targets and unrelated IPs fail closed (they satisfy no
  authorized relationship).
- The resolver is injectable so unit tests are deterministic and never
  require real DNS.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable

from agent_core.safety.policy import Policy

# resolver: hostname -> list of resolved IP strings (injectable for tests)
Resolver = Callable[[str], list[str]]


def default_resolver(hostname: str) -> list[str]:
    """Forward DNS resolution via the stdlib (injectable for tests)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return []
    out: list[str] = []
    for info in infos:
        raw = str(info[4][0])
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_scope(
    snapshot: list[dict] | None,
    *,
    resolver: Resolver | None = None,
) -> list[str]:
    """Build the scan's authorized target list (host-normalized).

    - host/url entries: their host form (existing behavior)
    - cidr entries: skipped (networks cannot be expanded safely in
      Phase 3 v1; documented limitation)
    - PLUS: forward-DNS resolutions of authorized HOSTNAMES - the only
      way an IP becomes authorized (deterministic provenance)
    An empty snapshot authorizes nothing (fail-closed).
    """
    resolve = resolver or default_resolver
    allowed: list[str] = []
    hostnames: list[str] = []
    for entry in snapshot or []:
        if not isinstance(entry, dict) or entry.get("type") not in ("host", "url"):
            continue
        host = Policy.normalize_target(entry.get("value"))
        if not host or host in allowed:
            continue
        allowed.append(host)
        hostnames.append(host)
    for hostname in hostnames:
        if _is_ip(hostname):
            continue  # literal authorized IP: already allowed, no DNS
        for ip in resolve(hostname):
            if ip not in allowed:
                allowed.append(ip)
    return allowed
