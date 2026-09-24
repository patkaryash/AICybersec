"""Nmap XML parser: stdlib-only parsing of ``nmap -oX -`` output.

Only structured XML is parsed - never human-readable (-oN) or grepable
(-oG) output. Returns a plain JSON-serializable dict suitable for
ToolResult.data (never raw XML, so model context stays bounded).
"""
from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse Nmap XML stdout into ``{"hosts": [...]}``.

    Host shape:
        {"ip": str|None, "hostname": str|None, "status": str,
         "ports": [{"port": int, "protocol": str, "state": str,
                    "reason": str|None,
                    "service": {"name": str|None, "product": str|None,
                                "version": str|None, "extrainfo": str|None,
                                "method": str|None, "confidence": int|None,
                                "cpe": [...]}}],
         "os": {"name": str|None, "accuracy": int|None} | None}

    Raises:
        ValueError: on empty input or malformed XML.
    """
    if not xml_text or not xml_text.strip():
        raise ValueError("empty nmap XML output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"malformed nmap XML: {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for h in root.findall("host"):
        status_el = h.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"

        ip: str | None = None
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if ip is None:
            first = h.find("address")
            ip = first.get("addr") if first is not None else None

        hostname: str | None = None
        hostnames_el = h.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        ports: list[dict[str, Any]] = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                try:
                    portid = int(p.get("portid", "-1"))
                except (TypeError, ValueError):
                    continue
                protocol = p.get("protocol", "tcp")
                state_el = p.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                reason = state_el.get("reason") if state_el is not None else None

                svc_el = p.find("service")
                if svc_el is not None:
                    conf: int | None = None
                    raw_conf = svc_el.get("conf")
                    if raw_conf is not None:
                        try:
                            conf = int(raw_conf)
                        except ValueError:
                            conf = None
                    cpe = [c.text for c in svc_el.findall("cpe") if c.text]
                    service = {
                        "name": svc_el.get("name"),
                        "product": svc_el.get("product"),
                        "version": svc_el.get("version"),
                        "extrainfo": svc_el.get("extrainfo"),
                        "method": svc_el.get("method"),
                        "confidence": conf,
                        "cpe": cpe,
                    }
                else:
                    service = {
                        "name": None,
                        "product": None,
                        "version": None,
                        "extrainfo": None,
                        "method": None,
                        "confidence": None,
                        "cpe": [],
                    }
                ports.append(
                    {
                        "port": portid,
                        "protocol": protocol,
                        "state": state,
                        "reason": reason,
                        "service": service,
                    }
                )

        os_info: dict[str, Any] | None = None
        os_el = h.find("os")
        if os_el is not None:
            best = os_el.find("osmatch")
            if best is not None:
                acc: int | None = None
                try:
                    acc = int(best.get("accuracy", ""))
                except (TypeError, ValueError):
                    acc = None
                os_info = {"name": best.get("name"), "accuracy": acc}

        hosts.append(
            {"ip": ip, "hostname": hostname, "status": status, "ports": ports, "os": os_info}
        )

    return {"hosts": hosts}
