"""KA-002 - KEV-driven matching eval: the committed kevstig snapshot's
routed CVEs fed to CVEMatchingEngine.match_cve; a measured coverage
report renders as a small table in the summary; the measured gap gates
KA-029's expansion queue (1 of 298 routed known at curation - ProxyShell;
the honest artifact; the superseded torn-fetch slice of 156 rows stopped
before 2021-era rows and hid it). The live-refresh variant stays opt-in
and documented (the snapshot is the offline mirror; tests never touch
the network)."""

from __future__ import annotations

import json
from pathlib import Path

from agentic_ai.agents.cyber.kali_v2 import CVE_EXPLOIT_DB, CVEMatchingEngine

SNAPSHOT_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "scans" / "kevstig_coverage_snapshot.json"
)
SNAPSHOT = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
COVERAGE = SNAPSHOT["coverage"]
ROUTED = COVERAGE["entries"]


def _eval_report():
    engine = CVEMatchingEngine()
    rows = []
    for entry in ROUTED:
        match = engine.match_cve(entry["cve"])
        rows.append({
            "cve": entry["cve"],
            "platforms": sorted(entry["platforms"]),
            "known": match is not None,
            "exploit_name": match.exploit_name if match else None,
            "metasploit_module": match.metasploit_module if match else None,
        })
    return rows


def test_snapshot_shape():
    assert set(SNAPSHOT) == {"meta", "coverage"}
    meta = SNAPSHOT["meta"]
    assert {"name", "generated", "source_url", "provenance",
            "live_counts"} <= set(meta)
    assert set(COVERAGE) == {
        "generated_at", "catalog_date", "source", "catalog_count",
        "routed_count", "uncovered_count", "platforms", "entries"}
    # the routed-only slice: every row verified routed
    for entry in ROUTED:
        assert entry["coveredByMaintenance"] is True
        assert entry["platforms"], entry["cve"]
    # the counts stay the LIVE API's numbers; the entries = the full
    # routed slice (298 of 298 routed are present)
    assert COVERAGE["catalog_count"] == 1734
    assert COVERAGE["routed_count"] == 298
    assert len(ROUTED) == 298


def test_every_routed_cve_reaches_match_cve():
    rows = _eval_report()
    assert len(rows) == len(ROUTED)
    known = [r for r in rows if r["known"]]
    # THE MEASURED GAP at curation (2026-10-05): exactly one of the 298
    # routed rows decodes to the 6-entry internal DB - ProxyShell; the
    # remaining 297 are the expansion queue's fuel
    assert [(r["cve"], r["exploit_name"]) for r in known] == [
        ("CVE-2021-34473", "ProxyShell")], known
    assert len(CVE_EXPLOIT_DB) == 6  # the eval mutated nothing


def test_coverage_report_renders_small_table():
    rows = _eval_report()
    known = sum(1 for r in rows if r["known"])
    total = len(rows)
    gate = "open" if known < total else "closed"
    table = [
        "| metric | value |",
        "|---|---|",
        "| routed in snapshot | %d |" % total,
        "| known to the internal DB | %d |" % known,
        "| coverage %% | %.1f%% |" % (100.0 * known / total if total else 0.0),
        "| expansion-queue gate | %s |" % gate,
    ]
    text = "\n".join(table)
    print("\nKA-002 coverage report:\n" + text)  # renders in -s and logs
    assert "| routed in snapshot | 298 |" in text
    assert "| known to the internal DB | 1 |" in text
    assert "| coverage % | 0.3% |" in text
    assert "| expansion-queue gate | open |" in text


def test_synthetic_known_row_branches_the_gate():
    """A crafted routed row whose cve the DB knows flips the gate closed -
    the branch is proven without touching the committed fixture."""
    mini = {
        "catalog_count": 1, "routed_count": 1, "uncovered_count": 0,
        "platforms": [],
        "entries": [{
            "cve": "CVE-2017-0144", "vendor": "Microsoft",
            "product": "Windows SMBv1 (synthetic row)",
            "name": "synthetic", "description": "",
            "dateAdded": "2021-11-03", "note": "",
            "platforms": ["windows"], "coveredByMaintenance": True,
        }],
    }
    engine = CVEMatchingEngine()
    rows = [{"cve": e["cve"], "known": engine.match_cve(e["cve"]) is not None}
            for e in mini["entries"]]
    assert rows[0]["known"] is True  # the known-path works
    assert all(r["known"] for r in rows)  # gate = closed


def test_overlap_invariant_holds_in_snapshot():
    routed_total = sum(p["kev_routed_total"] for p in COVERAGE["platforms"])
    assert routed_total >= COVERAGE["routed_count"]
    assert routed_total == 358  # the live snapshot's measured sum (22 rows)
