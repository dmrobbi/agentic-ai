"""KA-018 - Remediation-eval corpus: 30 realistic findings pinned through
RemediationEngine.generate_remediation_plan. Pins: the severity-bucket
segmentation (9/9/8/4), the exact steps of ALL five known remediations
(Log4Shell JndiLookup removal, EternalBlue patching, weak-password policy
among them), the generic fallback shape (including the nuance that generic
items drop the cve field even when cve_id was provided), and the effort-band
boundaries. No network."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest
import yaml

from agentic_ai.agents.cyber.kali_v2 import RemediationEngine

CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "findings" / "remediations.yaml"
)

DOC = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))
FINDINGS = DOC["findings"]

SEVERITY_COUNTS = {"critical": 9, "high": 9, "medium": 8, "low": 4}
GENERIC_STEPS = [
    "Consult security team",
    "Research vulnerability",
    "Apply appropriate fix",
]
GENERIC_REMEDIATION = "Review and address security finding"


def _finding_id(f):
    return f.get("cve_id") or f.get("category", "unknown")


def _mapped_rows():
    out = {}
    unmapped = []
    known_ids = set(RemediationEngine().remediations)
    for f in FINDINGS:
        fid = _finding_id(f)
        if fid in known_ids:
            out.setdefault(fid, []).append(f)
        else:
            unmapped.append(f)
    return out, unmapped


def test_corpus_shape():
    assert set(DOC) == {"meta", "findings"}
    assert len(FINDINGS) == 30
    ids = [f["id"] for f in FINDINGS]
    assert len(set(ids)) == 30, "duplicate row ids"
    assert set(FINDINGS[0]) == {"id", "title", "severity", "cve_id", "category"}
    for f in FINDINGS:
        assert f["severity"] in SEVERITY_COUNTS
        assert f["cve_id"] is None or re.fullmatch(r"CVE-\d{4}-\d+", f["cve_id"])


def test_corpus_distribution_and_engine_coverage():
    assert dict(Counter(f["severity"] for f in FINDINGS)) == SEVERITY_COUNTS
    mapped, unmapped = _mapped_rows()
    known_ids = set(RemediationEngine().remediations)
    assert sum(len(v) for v in mapped.values()) == 10, "mapped row count"
    assert len(unmapped) == 20
    assert set(mapped) == known_ids  # every engine key covered by the corpus


def test_segmentation_counts_total_and_effort():
    plan = RemediationEngine().generate_remediation_plan(FINDINGS)
    assert set(plan) == {
        "critical", "high", "medium", "low", "estimated_effort",
        "total_findings",
    }
    for sev, n in SEVERITY_COUNTS.items():
        assert len(plan[sev]) == n, sev
    assert plan["total_findings"] == 30
    assert plan["estimated_effort"] == "high (1-2 weeks)"


@pytest.mark.parametrize("known_id", sorted(RemediationEngine().remediations))
def test_known_remediations_exact(known_id):
    engine = RemediationEngine()
    rem = engine.remediations[known_id]
    mapped, _unmapped = _mapped_rows()
    assert known_id in mapped
    for f in mapped[known_id]:
        plan = engine.generate_remediation_plan([f])
        assert len(plan[f["severity"]]) == 1
        item = plan[f["severity"]][0]
        assert item["remediation"] == rem["summary"]
        assert item["steps"] == rem["steps"]
        assert item["effort"] == rem["effort"]
        assert item["finding"] == f["title"]
        assert item.get("cve") == f["cve_id"]


@pytest.mark.parametrize(
    "row",
    _mapped_rows()[1],
    ids=[f["id"] for f in _mapped_rows()[1]],
)
def test_generic_fallback_shape(row):
    plan = RemediationEngine().generate_remediation_plan([row])
    assert len(plan[row["severity"]]) == 1
    item = plan[row["severity"]][0]
    assert item["remediation"] == GENERIC_REMEDIATION
    assert item["steps"] == GENERIC_STEPS
    assert item["effort"] == "medium"
    assert item["finding"] == row["title"]
    assert "cve" not in item


def test_real_cve_context_dropped_in_generic():
    # F-06/F-07 are REAL CVEs known to the matching engine but absent from
    # the remediation map: they fall through to generic - and the item
    # silently drops their cve context. Pinned as-is; reported to the owner.
    engine = RemediationEngine()
    for row in FINDINGS:
        if row["id"] in ("F-06", "F-07"):
            assert row["cve_id"]
            item = engine.generate_remediation_plan([row])[row["severity"]][0]
            assert item["remediation"] == GENERIC_REMEDIATION
            assert "cve" not in item


def test_empty_findings_plan():
    plan = RemediationEngine().generate_remediation_plan([])
    assert plan["total_findings"] == 0
    assert plan["estimated_effort"] == "low (1-2 days)"
    for sev in ("critical", "high", "medium", "low"):
        assert plan[sev] == []


def test_single_generic_low_band():
    gen = [{"title": "Single finding", "severity": "high"}]
    plan = RemediationEngine().generate_remediation_plan(gen)
    assert plan["estimated_effort"] == "low (1-2 days)"


def test_five_known_low_boundary():
    five = [
        {"title": "SMBv1 host %d" % i, "severity": "critical",
         "cve_id": "CVE-2017-0144"}
        for i in range(5)
    ]
    plan = RemediationEngine().generate_remediation_plan(five)
    assert plan["estimated_effort"] == "low (1-2 days)"  # 5*1 = 5 -> low band


def test_seven_generic_medium_band():
    seven = [{"title": "G%d" % i, "severity": "medium"} for i in range(7)]
    plan = RemediationEngine().generate_remediation_plan(seven)
    assert plan["estimated_effort"] == "medium (3-5 days)"  # 14 -> medium


def test_eight_generic_high_band():
    eight = [{"title": "G%d" % i, "severity": "medium"} for i in range(8)]
    plan = RemediationEngine().generate_remediation_plan(eight)
    assert plan["estimated_effort"] == "high (1-2 weeks)"  # 16 -> high


def test_cve_takes_precedence_over_category():
    f = {"title": "Both ids present", "severity": "high",
         "cve_id": "CVE-9999-0000", "category": "weak_passwords"}
    item = RemediationEngine().generate_remediation_plan([f])["high"][0]
    # the cve id (unknown) wins over the KNOWN category: still generic
    assert item["remediation"] == GENERIC_REMEDIATION


def test_missing_title_and_severity_defaults():
    engine = RemediationEngine()
    f1 = {"severity": "medium"}  # no title
    item1 = engine.generate_remediation_plan([f1])["medium"][0]
    assert item1["finding"] == "Unknown"
    f2 = {"title": "Only title"}  # no severity -> low bucket
    item2 = engine.generate_remediation_plan([f2])["low"][0]
    assert item2["finding"] == "Only title"
