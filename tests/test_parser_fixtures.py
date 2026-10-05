"""KA-003 - parser regression fixtures: real-shaped recorded outputs
parsed, with EVERY extracted field pinned per fixture, both generations
where parsers exist, the implemented-vs-never-populated fields pinned as
documented gaps, and the current-behavior quirks pinned loudly (the CME
Pwn3d host capture, the unknown-severity uncounted row). No network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent
from agentic_ai.agents.cyber.kali_v2 import OutputParsers

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "parsers"
NMAP_XML_PATH = FIXTURES / "nmap_xml.sample.xml"
SQLMAP_PATH = FIXTURES / "sqlmap.sample.txt"
NUCLEI_PATH = FIXTURES / "nuclei.sample.jsonl"
CME_PATH = FIXTURES / "crackmapexec.sample.txt"


def _agent(tmp_path):
    return KaliAgent(agent_id="ka003-parsers",
                     workspace=str(tmp_path / "ws"),
                     log_dir=str(tmp_path / "logs"))


# ------------------------------------------------------------- nmap v1
def test_v1_nmap_string_parse_all_fields(tmp_path):
    result = _agent(tmp_path)._parse_nmap_xml(NMAP_XML_PATH.read_text())
    assert result is not None
    assert set(result) == {"hosts", "scan_time"}
    h1, h2 = result["hosts"]
    assert h1["address"] == "192.0.2.10"
    assert h1["hostname"] == "lab-host1.lab.example"
    assert h1["os"] is None
    assert [p["port"] for p in h1["ports"]] == [80, 445, 3389]  # ints, open-only
    assert h1["ports"][0]["protocol"] == "tcp"
    assert h1["ports"][0]["service"] == "http"
    assert h2["address"] == "198.51.100.20"
    assert h2["os"] == "Linux 5.4"
    assert [p["port"] for p in h2["ports"]] == [22]  # 443 closed EXCLUDED


# ------------------------------------------------------------- nmap v2
def test_v2_nmap_file_parse_all_fields(tmp_path):
    copy = tmp_path / "sample.xml"
    copy.write_text(NMAP_XML_PATH.read_text())
    result = OutputParsers.parse_nmap_xml(str(copy))
    assert set(result) == {
        "hosts", "total_hosts", "open_ports", "services",
        "os_detected", "vulnerabilities",
    }
    assert result["total_hosts"] == 2
    h1, h2 = result["hosts"]
    # FIXED at KA-INT-2: the attribute reads landed (ip/mac/status and
    # the port state/service/product/version); an ABSENT element still
    # reads None. All of these were "" under the old text-read parser.
    assert h1["ip"] == "192.0.2.10"
    assert h1["mac"] is None            # element absent -> None
    assert h2["ip"] == "198.51.100.20"
    assert h2["mac"] == "52:54:00:aa:00:42"
    assert h1["status"] == "up"
    assert h1["hostnames"] == ["lab-host1.lab.example"]
    p80 = h1["ports"][0]
    assert p80["port"] == "80" and p80["protocol"] == "tcp"
    assert p80["state"] == "open" and p80["service"] == "http"
    assert p80["product"] == "nginx" and p80["version"] == "1.18.0"
    assert [p["port"] for p in h2["ports"]] == ["22", "443"]  # CLOSED kept
    # open_ports populates for real-shaped xml since the fix:
    assert result["open_ports"] == [
        {"host": "192.0.2.10", "port": "80", "service": "http"},
        {"host": "192.0.2.10", "port": "445", "service": "microsoft-ds"},
        {"host": "192.0.2.10", "port": "3389", "service": "ms-wbt-server"},
        {"host": "198.51.100.20", "port": "22", "service": "ssh"}]
    assert result["os_detected"] == {"name": "Linux 5.4", "accuracy": "98"}
    assert result["vulnerabilities"] == [
        {"id": "smb-vuln-ms17-010", "output": "VULNERABLE: smb-v1 enabled"}]
    assert result["services"] == []  # documented gap: never populated


def test_v1_vs_v2_nmap_divergence_pinned(tmp_path):
    # the SAME xml through BOTH parsers: v1 keeps open-only int ports,
    # v2 keeps every port as strings - the documented generations' split
    text = NMAP_XML_PATH.read_text()
    h1, h2 = _agent(tmp_path)._parse_nmap_xml(text)["hosts"]
    assert [p["port"] for p in h2["ports"]] == [22]  # v1: closed EXCLUDED
    copy = tmp_path / "sample.xml"
    copy.write_text(text)
    h2v2 = OutputParsers.parse_nmap_xml(str(copy))["hosts"][1]
    assert [p["port"] for p in h2v2["ports"]] == ["22", "443"]  # v2: KEPT


# ------------------------------------------------------------- sqlmap v2
def test_v2_sqlmap_parse():
    result = OutputParsers.parse_sqlmap_output(SQLMAP_PATH.read_text())
    assert result["vulnerable"] is True
    assert result["injection_type"] == "boolean-based blind"
    assert result["database"] == "webshop"
    # documented gaps: these three never populate in v2
    assert result["tables"] == [] and result["columns"] == []
    assert result["dumped_data"] == []
    # and a clean sample never flips vulnerable:
    clean = OutputParsers.parse_sqlmap_output("# clean\nno findings here\n")
    assert clean["vulnerable"] is False


# ------------------------------------------------------------- nuclei v2
def test_v2_nuclei_parse_all_fields():
    result = OutputParsers.parse_nuclei_output(NUCLEI_PATH.read_text())
    assert set(result) == {"vulnerabilities", "by_severity", "total_findings"}
    rows = result["vulnerabilities"]
    assert result["total_findings"] == 6  # malformed tail line skipped
    assert result["by_severity"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}
    first = rows[0]
    assert first["template"] == "cves/2017/CVE-2017-0144"
    assert first["name"] == "MS17-010 SMBv1 RCE"
    assert first["severity"] == "high"
    assert first["host"] == "192.0.2.10"
    assert first["matched_at"] == "192.0.2.10:445"
    assert first["tags"] == ["cve", "smb", "rce"]
    unknown = rows[5]
    assert unknown["severity"] == "unknown"  # listed, not counted


# ------------------------------------------------- crackmapexec v2
def test_v2_crackmapexec_parse_pinned_current_behavior():
    result = OutputParsers.parse_crackmapexec_output(CME_PATH.read_text())
    assert set(result) == {"hosts", "credentials", "shares", "sessions"}
    assert result["credentials"] == [
        {"domain": "LAB", "username": "jroberts",
         "password": "Winter2026!"}]  # only the Authenticated line
    # FIXED at KA-INT-2: the session host = the CME line's second
    # token (the IP column), not the bracket junk the old regex gave.
    assert result["sessions"] == [
        {"host": "192.0.2.10", "status": "pwned"},
        {"host": "198.51.100.20", "status": "pwned"}]
    assert result["hosts"] == [] and result["shares"] == []  # unimplemented


def test_fixture_provenance_headers():
    assert "KA-003 parser fixture" in NMAP_XML_PATH.read_text()  # xml comment
    assert "KA-003 parser fixture" in SQLMAP_PATH.read_text()
    assert "KA-003 parser fixture" in CME_PATH.read_text()
    # the nuclei JSONL stays pure JSON-lines: provenance lives in the test
    first_line = NUCLEI_PATH.read_text().splitlines()[0]
    json.loads(first_line)  # parses as JSON (no header comments allowed)
