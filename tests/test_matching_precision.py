"""KA-010 - matching-precision eval: seed service rows (true positives,
patched-but-adjacent, EOL-banner labels, irrelevant ports); run the REAL
match_from_services pipeline over every case; MEASURE precision/recall;
assert the committed baseline (the drift alarm) and render a small
report table in the summary. The version-blindness limitation is pinned,
not hidden. No network."""

from __future__ import annotations

import json
from pathlib import Path

from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "cve" / "precision_cases.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CASES = FIXTURE["cases"]
BASELINE = FIXTURE["meta"]["baseline"]


def _measure():
    engine = CVEMatchingEngine()
    measured = {}
    for case in CASES:
        matches = engine.match_from_services([case["service"]])
        measured[case["id"]] = {
            "label": case["label"],
            "matched": bool(matches),
            "cves": sorted({m.cve_id for m in matches}),
        }
    return measured


def test_corpus_shape():
    assert len(CASES) == BASELINE["cases"] == 14
    assert len({c["id"] for c in CASES}) == len(CASES)
    labels = {c["label"] for c in CASES}
    assert labels == {"vulnerable", "patched", "irrelevant"}
    for c in CASES:
        assert isinstance(c["service"].get("port"), int)


def test_precision_and_recall_measured():
    measured = _measure()
    vulnerable = [c for c in CASES if c["label"] == "vulnerable"]
    matched_cases = [cid for cid, m in measured.items() if m["matched"]]
    true_positive = [cid for cid in matched_cases
                     if measured[cid]["label"] == "vulnerable"]
    precision = len(true_positive) / len(matched_cases)
    recall = len(true_positive) / len(vulnerable)
    assert len(matched_cases) == BASELINE["matched_cases"] == 10
    assert len(true_positive) == BASELINE["true_positive_cases"] == 6
    assert round(precision, 2) == BASELINE["precision"] == 0.6
    assert round(recall, 2) == BASELINE["recall"] == 1.0


def test_patched_rows_still_match_the_version_blindness():
    measured = _measure()
    patched_matched = [cid for cid, m in measured.items()
                       if m["label"] == "patched" and m["matched"]]
    assert sorted(patched_matched) == ["P-07", "P-08", "P-09", "P-10"]
    for cid in patched_matched:
        # the pinned limitation: the pipeline never sees versions
        assert measured[cid]["cves"], cid


def test_irrelevant_rows_never_match():
    measured = _measure()
    for case in CASES:
        if case["label"] == "irrelevant":
            assert not measured[case["id"]]["matched"], case["id"]


def test_recommendation_buckets_measured():
    engine = CVEMatchingEngine()
    # a vulnerable service row through the FULL recommendation pipeline
    recs = engine.generate_exploit_recommendations(
        {"services": [{"service": "smb", "port": 445},
                      {"service": "http", "port": 80},
                      {"service": "rdp", "port": 3389}]})
    # smb@445 -> EternalBlue (rank 5, critical); http@80 -> Log4Shell+
    # ProxyShell (5+5, critical); rdp@3389 -> BlueKeep (rank 4, high)
    assert recs["total_matches"] == 4
    critical_cves = {row["cve"] for row in recs["critical_exploits"]}
    assert critical_cves == {"CVE-2017-0144", "CVE-2021-44228", "CVE-2021-34473"}
    high_cves = {row["cve"] for row in recs["high_exploits"]}
    assert high_cves == {"CVE-2019-0708"}
    assert recs["medium_exploits"] == []


def test_match_cve_case_shapes_verbatim():
    engine = CVEMatchingEngine()
    match = engine.match_from_services([{"service": "smb", "port": 445}])
    assert match and match[0].exploit_name == "EternalBlue"
    assert match[0].rank == 5
    none_case = engine.match_from_services([{"service": "dns", "port": 53}])
    assert none_case == []
