"""KA-067 tests - kevstig bridge: the REAL API shape pinned field-by-field
against the committed live snapshot, the catalog equation, the
multi-platform overlap invariant, the routed/unrouted split, the matcher
fan-out (unknown path via the real fixture rows; the KNOWN path via a
labeled synthetic overlay using the engine's actual EternalBlue row),
matcher isolation, validation errors, and the purity scan. No network."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kev_bridge import (
    TOP_KEYS,
    route_coverage,
    validate_coverage,
)
from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "scans" / "kev_bridge_coverage.json"
)
SNAP = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
COVERAGE = SNAP["coverage"]
PLATFORM_ROW_KEYS = {
    "platform", "label", "ckls", "rules_maintained",
    "kev_routed_total", "kev_routed_30d", "newest_KEV",
}
ENTRY_ROW_KEYS = {
    "cve", "vendor", "product", "name", "description",
    "dateAdded", "note", "platforms", "coveredByMaintenance",
}


def test_fixture_carries_the_real_api_shape():
    assert set(SNAP) == {"meta", "coverage"}
    assert set(COVERAGE) == set(TOP_KEYS)
    for row in COVERAGE["platforms"]:
        assert set(row) == PLATFORM_ROW_KEYS
    for entry in COVERAGE["entries"]:
        assert set(entry) == ENTRY_ROW_KEYS
    assert SNAP["meta"]["trimmed"]["entries_in_fixture"] == len(
        COVERAGE["entries"])


def test_catalog_equation_holds():
    counts = COVERAGE
    assert counts["catalog_count"] == (
        counts["routed_count"] + counts["uncovered_count"])
    assert counts["catalog_count"] == 1734


def test_multi_platform_overlap_invariant():
    routed_total = sum(p["kev_routed_total"] for p in COVERAGE["platforms"])
    assert routed_total >= COVERAGE["routed_count"]
    assert routed_total == 358  # the live snapshot's measured sum (22 rows)
    assert COVERAGE["routed_count"] == 298


def test_route_coverage_output_schema():
    result = route_coverage(COVERAGE)
    assert set(result) == {
        "counts", "routed_entries", "routed_by_platform",
        "recommendations", "unrouted_sample", "notes",
    }
    assert result["counts"] == {
        "catalog_count": 1734, "routed_count": 298, "uncovered_count": 1436}
    for rec in result["recommendations"]:
        assert set(rec) == {
            "cve", "platform", "known", "exploit_name",
            "metasploit_module", "reliability", "port", "rank"}


def test_routed_extraction_and_platform_grouping():
    result = route_coverage(COVERAGE)
    routed = [e for e in COVERAGE["entries"] if e["coveredByMaintenance"]]
    assert len(result["routed_entries"]) == 5 == len(routed)
    grouping = result["routed_by_platform"]
    assert len(grouping["windows"]) == 2
    assert grouping["rhel7"] == ["CVE-2015-3246"]
    assert "vsphere67" in grouping and "macos" in grouping
    # group rows exceed routed rows (one entry routed to 3 RHEL baselines,
    # one vCenter entry routed to all four vSphere rows)
    assert sum(len(v) for v in grouping.values()) == 10


def test_recommendations_unknown_path_is_the_majority():
    # every committed row decodes to nothing in the internal exploit DB -
    # the honest-majority artifact the upstream tool publishes on purpose
    result = route_coverage(COVERAGE)
    recs = result["recommendations"]
    assert len(recs) == 10
    assert all(r["known"] is False for r in recs)
    assert all(r["exploit_name"] is None for r in recs)


def _overlay_coverage():
    """FIXTURE COPY + one labeled synthetic routed row whose cve the
    internal engine knows (EternalBlue) - demonstrates the KNOWN path;
    the committed fixture itself stays 100% real data."""
    overlay = json.loads(json.dumps(COVERAGE))  # deep copy
    overlay["entries"] = [
        {
            "cve": "CVE-2017-0144",          # SYNTHETIC OVERLAY (test only)
            "vendor": "Microsoft",           # dateAdded illustrative; the
            "product": "Windows SMBv1",      # assert pins matcher facts
            "name": "MS17-010 EternalBlue",  # only, never this row's text
            "description": "synthetic overlay row for the known-path demo",
            "dateAdded": "2021-11-03",
            "note": "",
            "platforms": ["windows"],
            "coveredByMaintenance": True,
        },
        *COVERAGE["entries"],
    ]
    return overlay


def test_recommendations_known_path_via_overlay():
    result = route_coverage(_overlay_coverage())
    known = [r for r in result["recommendations"] if r["known"]]
    assert len(known) == 1
    rec = known[0]
    assert rec["cve"] == "CVE-2017-0144"
    assert rec["platform"] == "windows"
    assert rec["exploit_name"] == "EternalBlue"
    assert rec["metasploit_module"] == (
        "exploit/windows/smb/ms17_010_eternalblue")
    assert rec["reliability"] == "excellent"
    assert rec["port"] == 445
    assert rec["rank"] == 5


class RecordingMatcher:
    """Records match_cve calls, then delegates to the real engine - the
    bridge sees the real answers only through the injected boundary."""

    def __init__(self, inner=None):
        self._inner = inner
        self.cves = []

    def match_cve(self, cve_id):
        self.cves.append(cve_id)
        return self._inner.match_cve(cve_id) if self._inner else None


def test_matcher_called_once_per_unique_cve():
    matcher = RecordingMatcher(CVEMatchingEngine())
    overlay = _overlay_coverage()
    overlay["entries"].append(dict(overlay["entries"][0],
                                   platforms=["rhel7"]))  # 2nd platform
    result = route_coverage(overlay, matcher=matcher)
    unique_routed = {e["cve"] for e in overlay["entries"]
                     if e["coveredByMaintenance"]}
    assert "CVE-2017-0144" in matcher.cves
    # once per unique routed cve - no re-match across platform rows
    assert len(matcher.cves) == len(set(matcher.cves)) == len(unique_routed)
    known = [r for r in result["recommendations"] if r["known"]]
    assert len(known) == 2  # both platform rows carry the same real facts
    assert {r["platform"] for r in known} == {"windows", "rhel7"}


def test_actionable_validation_errors():
    with pytest.raises(ValueError) as missing:
        route_coverage({"entries": []})
    assert "missing required keys" in str(missing.value)
    assert "catalog_count" in str(missing.value)
    bad_row = json.loads(json.dumps(COVERAGE))
    bad_row["entries"][0]["cve"] = "not-a-cve"
    with pytest.raises(ValueError) as malformed:
        route_coverage(bad_row)
    assert "cve malformed" in str(malformed.value)
    validate_coverage(COVERAGE)  # the real fixture validates clean


def test_unrouted_sample_is_the_artifact():
    result = route_coverage(COVERAGE)
    sample = result["unrouted_sample"]
    assert sample and sample[0]["cve"] == "CVE-2026-88779"  # newest unrouted
    assert len(sample) == 4
    assert any(e["product"] == "NetScaler" for e in sample)


def test_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.kev_bridge")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
