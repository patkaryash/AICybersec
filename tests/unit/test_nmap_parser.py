"""Unit tests: Nmap XML parser (static fixtures, no network/nmap)."""
from __future__ import annotations

import pytest

from agent_core.tools.nmap_parser import parse_nmap_xml

SINGLE_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="lab.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.2" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.2</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24" extrainfo="Ubuntu" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/>
<service name="https" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.X" accuracy="95"/></os>
</host>
</nmaprun>"""

MULTI_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" method="table" conf="3"/></port></ports></host>
<host><status state="down" reason="no-response"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
</host>
</nmaprun>"""


def test_single_host_with_services_and_os():
    data = parse_nmap_xml(SINGLE_HOST)
    assert len(data["hosts"]) == 1
    h = data["hosts"][0]
    assert h["ip"] == "10.0.0.5"
    assert h["hostname"] == "lab.local"
    assert h["status"] == "up"
    assert len(h["ports"]) == 3
    ssh = h["ports"][0]
    assert ssh["port"] == 22 and ssh["state"] == "open" and ssh["reason"] == "syn-ack"
    assert ssh["service"]["name"] == "ssh"
    assert ssh["service"]["product"] == "OpenSSH"
    assert ssh["service"]["confidence"] == 10
    assert ssh["service"]["cpe"] == ["cpe:/a:openbsd:openssh:9.2"]
    assert h["os"] == {"name": "Linux 5.X", "accuracy": 95}


def test_multiple_hosts_up_and_down():
    data = parse_nmap_xml(MULTI_HOST)
    assert len(data["hosts"]) == 2
    assert data["hosts"][0]["status"] == "up"
    assert data["hosts"][1]["status"] == "down"
    assert data["hosts"][1]["ip"] == "10.0.0.6"
    assert data["hosts"][1]["ports"] == []


def test_missing_optional_fields():
    xml = """<?xml version="1.0"?><nmaprun><host><status state="up"/>"""
    xml += """<address addr="10.0.0.7" addrtype="ipv4"/>"""
    xml += """<ports><port protocol="tcp" portid="80"><state state="open"/>"""
    xml += """</port></ports></host></nmaprun>"""
    data = parse_nmap_xml(xml)
    h = data["hosts"][0]
    assert h["hostname"] is None
    assert h["os"] is None
    assert h["ports"][0]["reason"] is None
    assert h["ports"][0]["service"]["name"] is None


def test_malformed_and_empty_raise():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all <")
    with pytest.raises(ValueError):
        parse_nmap_xml("")
    with pytest.raises(ValueError):
        parse_nmap_xml("   ")
