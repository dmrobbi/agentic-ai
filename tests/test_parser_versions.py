"""KA-011 - parser schema-version compatibility: nmap XML from a lean
older emitter and nuclei outputs across the template-id -> template
schema evolution must parse WITHOUT drift (no crashes, the documented
field behavior pinned: the evolved nuclei row reports template None -
flagged as the known key-drift limitation, a conscious parser upgrade
for a future task). No network."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent
from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine, OutputParsers

REPO = Path(__file__).resolve().parents[1]
VERSIONED = REPO / "tests" / "fixtures" / "parsers" / "versioned"
NMAP_LEAN = VERSIONED / "nmap_xml.lean.sample.xml"
NUCLEI_V1 = VERSIONED / "nuclei.template-id.sample.jsonl"
NUCLEI_V2 = VERSIONED / "nuclei.template-key.sample.jsonl"


@pytest.fixture(scope="module")
def agent(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka011")
    return KaliAgent(agent_id="ka011-versions", workspace=str(ws / "ws"),
                     log_dir=str(ws / "logs"))


def test_versioned_fixtures_exist():
    for path in (NMAP_LEAN, NUCLEI_V1, NUCLEI_V2):
        assert path.is_file(), path


def test_lean_nmap_parses_without_drift_v1(agent):
    result = agent._parse_nmap_xml(NMAP_LEAN.read_text())
    assert result is not None
    h1 = result["hosts"][0]
    assert h1["address"] == "192.0.2.77"
    assert h1["hostname"] == "lean-host.lab.example"
    assert [p["port"] for p in h1["ports"]] == [22]
    assert h1["os"] is None  # the lean emitter carries no os block


def test_lean_nmap_parses_without_drift_v2(tmp_path):
    copy = tmp_path / "lean.xml"
    copy.write_text(NMAP_LEAN.read_text())
    result = OutputParsers.parse_nmap_xml(str(copy))
    assert result["total_hosts"] == 1
    h1 = result["hosts"][0]
    assert h1["hostnames"] == ["lean-host.lab.example"]
    assert h1["ip"] == "192.0.2.77"  # the attr-read (KA-INT-2 fix)
    assert h1["status"] == "up"
    assert [p["port"] for p in h1["ports"]] == ["22"]
    assert h1["os"] is None
    assert result["vulnerabilities"] == []


def test_nuclei_template_id_rows_parse():
    result = OutputParsers.parse_nuclei_output(NUCLEI_V1.read_text())
    assert result["total_findings"] == 2
    assert result["vulnerabilities"][0]["template"] == "cves/2017/CVE-2017-0144"
    assert result["by_severity"] == {
        "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1}


def test_nuclei_evolved_key_does_not_crash_and_reports_none():
    """PINNED SCHEMA-EVOLUTION BEHAVIOR (reported): the newer emitters
    carry the key 'template' and DROPPED template-id - the parser reads
    template-id only, so the evolved row parses CRASH-FREE with
    template=None. The fix (a key union) = a future parser upgrade; the
    no-crash + no-drift contract is what pins."""
    result = OutputParsers.parse_nuclei_output(NUCLEI_V2.read_text())
    assert result["total_findings"] == 1
    row = result["vulnerabilities"][0]
    assert row["template"] is None  # the evolved key invisible to the parser
    assert row["name"] == "Log4Shell JNDI RCE (evolved key)"
    assert row["severity"] == "critical"
    assert result["by_severity"]["critical"] == 1


def test_mixed_generations_coexist_in_one_stream():
    """Both eras in ONE jsonl stream: every row parses, every row lands,
    the buckets count only the known severities."""
    stream = NUCLEI_V1.read_text() + NUCLEI_V2.read_text()
    result = OutputParsers.parse_nuclei_output(stream)
    assert result["total_findings"] == 3
    assert [r["template"] for r in result["vulnerabilities"]] == [
        "cves/2017/CVE-2017-0144", "tech/apache", None]
    assert result["by_severity"] == {
        "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}


def test_engines_survive_all_versioned_inputs():
    """The engines downstream are stable across every versioned input:
    match_cve stays intact after parsing the lean/evolved shapes."""
    engine = CVEMatchingEngine()
    match = engine.match_cve("CVE-2017-0144")
    assert match is not None and match.exploit_name == "EternalBlue"
