"""Mock security tools: deterministic, synthetic, zero network access.

They exist so the full loop (planner -> validator -> tool -> observation ->
state) runs without nmap/httpx/nuclei/ZAP.  Later real tools implement the
same Tool interface with fixed argv construction from validated params.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agent_core.schemas.results import Finding, ToolResult
from agent_core.tools.base import Tool, ToolContext


def _finding_id(tool: str, title: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")
    return f"{tool}:{slug}"


class MockPortScanParams(BaseModel):
    """Validated parameters for MockPortScan (mirrors a future nmap wrapper)."""

    target: str = Field(min_length=1)
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8080])


class MockPortScan(Tool):
    name = "mock_port_scan"
    description = (
        "Mock TCP port scan. Returns deterministic open/closed port data "
        "for the target. Synthetic only - performs no network activity."
    )
    input_model = MockPortScanParams
    danger_level = "active_scan"

    # Deterministic pseudo-port-map so tests and demos never flake.
    _OPEN_PORTS = {80: "http", 443: "https", 8080: "http-proxy"}

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        p: MockPortScanParams = params  # type: ignore[assignment]
        target = p.target
        open_ports = [port for port in p.ports if port in self._OPEN_PORTS]

        findings: list[Finding] = []
        for port in open_ports:
            service = self._OPEN_PORTS[port]
            if service in ("http", "https"):
                findings.append(
                    Finding(
                        id=_finding_id(self.name, f"HTTP service on port {port}"),
                        title=f"HTTP service on port {port}",
                        severity="info",
                        target=target,
                        asset=f"{service}://{target}:{port}",
                        description=(
                            f"Mock scan identified a {service} service listening "
                            f"on port {port}. This is a synthetic result."
                        ),
                        evidence={"port": port, "service": service},
                        tool=self.name,
                        confidence="high",
                        status="open",
                        references=[],
                    )
                )

        return ToolResult(
            status="ok",
            summary=(
                f"Scanned {len(p.ports)} ports on {target}: "
                f"{len(open_ports)} open ({', '.join(map(str, open_ports)) or 'none'})."
            ),
            data={
                "target": target,
                "open_ports": [{"port": port, "service": self._OPEN_PORTS[port]} for port in open_ports],
                "synthetic": True,
            },
            findings=findings,
        )


class MockWebProbeParams(BaseModel):
    """Validated parameters for MockWebProbe (mirrors a future httpx/ZAP wrapper)."""

    url: str = Field(min_length=1)
    check_headers: bool = True


class MockWebProbe(Tool):
    name = "mock_web_probe"
    description = (
        "Mock web probe. Returns deterministic HTTP header/tls observations "
        "and a synthetic missing-security-header finding. No requests are made."
    )
    input_model = MockWebProbeParams
    danger_level = "safe"

    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        p: MockWebProbeParams = params  # type: ignore[assignment]
        url = p.url

        finding = Finding(
            id=_finding_id(self.name, "Missing security header (mock)"),
            title="Missing security header (mock)",
            severity="medium",
            target=url,
            asset=url,
            description=(
                "Mock web probe reports a missing Content-Security-Policy "
                "header. This is a synthetic result for demonstration."
            ),
            evidence={"url": url, "missing_header": "Content-Security-Policy"},
            tool=self.name,
            confidence="high",
            status="open",
            references=["https://owasp.org/www-project-secure-headers/"],
        )

        data: dict[str, Any] = {
            "url": url,
            "status_code": 200,
            "headers": {
                "Server": "mock-httpd/1.0",
                "Content-Type": "text/html",
                "X-Mock": "true",
            },
            "tls": {"version": "TLSv1.3", "valid": True},
            "synthetic": True,
        }
        return ToolResult(
            status="ok",
            summary=f"Probed {url}: 200 OK, 1 synthetic finding (missing CSP header).",
            data=data,
            findings=[finding],
        )
