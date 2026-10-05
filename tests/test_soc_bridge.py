"""KA-066 tests - SOC findings bridge: the output schema (exact), the
known-CVE reference path (matcher facts in the plan), the real-but-absent
CVE note path, the generic no-CVE path, the unplannable routes (NO crash),
summary consistency, scrub_host behavior, the injected-matcher isolation
(the stub's match_cve is the ONLY thing the bridge can call), empty input,
and the planner-purity source scan (no exec/network facilities). No network,
no live SOC calls - by design."""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.soc_bridge import (
    CVE_RE,
    SocFindingsVerifier,
    scrub_host,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "findings" / "soc_findings.json"
)
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
FINDINGS = CORPUS["findings"]


def test_output_schema_exact_shape():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    assert set(result) == {"planned", "unplannable", "summary"}
    assert set(result["summary"]) == {
        "total", "planned", "unplannable", "with_known_cve"}
    for plan in result["planned"]:
        assert set(plan) == {
            "finding_id", "severity", "host", "cve",
            "verification_steps", "notes"}
    for row in result["unplannable"]:
        assert set(row) == {"finding_id", "reasons"}
        assert row["reasons"]


def test_known_cve_plan_references_matcher_facts():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    plan = next(p for p in result["planned"] if p["finding_id"] == "F-01")
    assert plan["cve"]["known"] is True
    assert plan["cve"]["exploit_name"] == "EternalBlue"
    assert plan["cve"]["port"] == 445
    assert any("-p 445" in s and "wks-a01.lab.example" in s
               for s in plan["verification_steps"])
    assert any(s.startswith("searchsploit") for s in plan["verification_steps"])
    assert any("excellent" in n for n in plan["notes"])


def test_known_cve_without_port_uses_generic_probe():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    plan = next(p for p in result["planned"] if p["finding_id"] == "F-03")
    assert plan["cve"]["known"] is True
    assert plan["cve"]["port"] is None
    assert not any("-p " in s for s in plan["verification_steps"])
    assert any(s.startswith("msfconsole") for s in plan["verification_steps"])


def test_real_but_absent_cve_notes_the_gap():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    for fid in ("F-06", "F-07"):
        plan = next(p for p in result["planned"] if p["finding_id"] == fid)
        assert plan["cve"]["known"] is False
        assert plan["cve"]["exploit_name"] is None
        assert any("absent from the internal exploit DB" in n
                   for n in plan["notes"])


def test_no_cve_generic_plan():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    plan = next(p for p in result["planned"] if p["finding_id"] == "F-04")
    assert plan["cve"] is None
    assert any(s.startswith("nmap") for s in plan["verification_steps"])
    assert any("manual triage" in n for n in plan["notes"])


def test_unplannable_routes_never_crash():
    result = SocFindingsVerifier().verify_findings(FINDINGS)
    by_id = {u["finding_id"]: u for u in result["unplannable"]}
    assert set(by_id) == {"F-901", "F-902", "F-903", "F-904"}
    text = json.dumps(by_id, default=str)
    assert "p1" in text  # severity reason surfaces
    assert any("disallowed characters" in r for r in by_id["F-903"]["reasons"])
    assert any("cve_id malformed" in r for r in by_id["F-904"]["reasons"])
    planned_ids = {p["finding_id"] for p in result["planned"]}
    assert not planned_ids & set(by_id)
    assert planned_ids == {
        "F-01", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-08"}
    summary = result["summary"]
    assert summary["total"] == 12
    assert summary["planned"] == 8
    assert summary["unplannable"] == 4
    assert summary["with_known_cve"] == 3


def test_scrub_host_module_level():
    assert scrub_host("  host-a01.lab.example ") == "host-a01.lab.example"
    with pytest.raises(ValueError):
        scrub_host("h; rm -rf")
    with pytest.raises(ValueError):
        scrub_host("")
    with pytest.raises(ValueError):
        scrub_host("two spaces")


class RecordingMatcher:
    def __init__(self):
        self.cves = []

    def match_cve(self, cve_id):
        self.cves.append(cve_id)
        return None  # deliberately bare; the bridge must handle it


def test_injected_matcher_is_the_only_external_call():
    matcher = RecordingMatcher()
    SocFindingsVerifier(matcher).verify_findings(FINDINGS)
    cve_rows = [f for f in FINDINGS
                if isinstance(f.get("cve_id"), str)
                and re.fullmatch(CVE_RE, f["cve_id"])]
    assert sorted(matcher.cves) == sorted(f["cve_id"] for f in cve_rows)


def test_planner_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.soc_bridge")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "wazuh"):
        assert banned not in source, banned


def test_empty_findings_zero_counts():
    result = SocFindingsVerifier().verify_findings([])
    assert result == {
        "planned": [],
        "unplannable": [],
        "summary": {
            "total": 0, "planned": 0, "unplannable": 0, "with_known_cve": 0,
        },
    }
