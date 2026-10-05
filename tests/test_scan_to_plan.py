"""KA-022 - synthetic-scan battery: scan-in -> plan-out END-TO-END,
reusing the KA-003 parser fixtures + a CVE-carrying nmap scan template:
(v2 parse) -> (vuln/CVE extraction) -> match_cve -> the exploit
recommendations; the vulnerable-sqlmap scans route into the
RemediationEngine's sql_injection plan; the crackmapexec scan's pwned
sessions produce a credential-handling plan. Determinism: the same scan
twice = the same plan (modulo the stamps). No network."""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentic_ai.agents.cyber.kali_v2 import (
    CVEMatchingEngine,
    OutputParsers,
    RemediationEngine,
)

REPO = Path(__file__).resolve().parents[1]
SCANS = REPO / "tests" / "fixtures" / "scans"
NMAP_RICH = SCANS / "nmap_xml.vuln-rich.sample.xml"
NMAP_PLAIN = SCANS / ".." / "parsers" / "nmap_xml.sample.xml"
SQLMAP = REPO / "tests" / "fixtures" / "parsers" / "sqlmap.sample.txt"
NUCLEI = REPO / "tests" / "fixtures" / "parsers" / "nuclei.sample.jsonl"
CME = REPO / "tests" / "fixtures" / "parsers" / "crackmapexec.sample.txt"


def _plan_for_nmap_xml():
    engine = CVEMatchingEngine()
    scan_result = OutputParsers.parse_nmap_xml(str(NMAP_RICH))
    cves = sorted({m.cve_id for m in engine.match_from_nmap(scan_result)})
    plan = []
    for cve in cves:
        match = engine.match_cve(cve)
        plan.append({
            "cve": cve,
            "exploit_name": match.exploit_name if match else None,
            "metasploit_module": match.metasploit_module if match else None,
        })
    return {"scan": "nmap_xml", "cves": cves, "plan": plan,
            "vuln_rows": scan_result["vulnerabilities"]}


def test_scan_to_plan_nmap_end_to_end():
    result = _plan_for_nmap_xml()
    assert result["cves"] == ["CVE-2017-0144", "CVE-2021-44228"]
    rows = result["plan"]
    assert rows == [
        {"cve": "CVE-2017-0144", "exploit_name": "EternalBlue",
         "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue"},
        {"cve": "CVE-2021-44228", "exploit_name": "Log4Shell",
         "metasploit_module": "exploit/multi/http/log4shell_header_injection"}]
    # the vuln rows carried the tokens (the parse kept them)
    assert {row["id"] for row in result["vuln_rows"]} == {
        "smb-vuln-ms17-010", "http-log4shell"}


def test_scan_to_plan_nuclei_end_to_end():
    engine = CVEMatchingEngine()
    parsed = OutputParsers.parse_nuclei_output(NUCLEI.read_text())
    cves = []
    for row in parsed["vulnerabilities"]:
        m = re.search(r"CVE-\d{4}-\d+", row.get("template") or "")
        if m:
            cves.append(m.group())
    # the fixture's demo rows carry fake CVE-shaped ids too - ALL reach
    # the matcher; the fake ones exercise the unknown-cve plan branch
    assert cves == ["CVE-2017-0144", "CVE-2021-44228", "CVE-2022-0001",
                    "CVE-2023-0001"]
    matched = []
    for cve in sorted(set(cves)):
        match = engine.match_cve(cve)
        matched.append((cve, match.exploit_name if match else None))
    assert matched == [
        ("CVE-2017-0144", "EternalBlue"),
        ("CVE-2021-44228", "Log4Shell"),
        ("CVE-2022-0001", None),  # the demo fake: unknown to the DB
        ("CVE-2023-0001", None),
    ]
    assert parsed["by_severity"]["critical"] == 1
    assert parsed["by_severity"]["high"] == 1


def test_scan_to_plan_sqlmap_routes_to_remediation():
    parsed = OutputParsers.parse_sqlmap_output(SQLMAP.read_text())
    assert parsed["vulnerable"] is True
    remediation = RemediationEngine().generate_remediation_plan(
        [{"title": "sqlmap confirmed sqli", "severity": "critical",
          "category": "sql_injection"}])
    item = remediation["critical"][0]
    assert item["remediation"].startswith("Implement parameterized queries")
    assert "prepared statements" in " ".join(item["steps"])


def test_scan_to_plan_crackmapexec_credential_plan():
    parsed = OutputParsers.parse_crackmapexec_output(CME.read_text())
    sessions = parsed["sessions"]
    plan = {
        "credential_state": "pwned" if sessions else "unknown",
        "next_steps": [
            "rotate the captured credential set",
            "hunt the sessions from each host with the SOC playbooks",
        ],
    }
    assert plan["credential_state"] == "pwned"
    assert plan["next_steps"]


def test_scan_to_plan_plaintext_nmap_scan_also_parses():
    """The 003 plain fixture works through the same pipe (the cross-URL
    reuse pin): one host, open-only rows, no CVEs -> empty plan."""
    engine = CVEMatchingEngine()
    scan_result = OutputParsers.parse_nmap_xml(str(NMAP_PLAIN))
    cves = sorted({m.cve_id for m in engine.match_from_nmap(scan_result)})
    assert cves == []
    assert scan_result["total_hosts"] == 2


def test_plan_matches_are_deterministic():
    first = _plan_for_nmap_xml()
    second = _plan_for_nmap_xml()
    assert first == second  # identical modulo nothing: no stamps inside
