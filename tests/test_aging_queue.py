"""KA-068 tests - aging queue: the committed patch-report shape
fixture pinned field-by-field (meta provenance, exact top-level and
row key sets), the validation contract (actionable ValueErrors over a
hostile report/row corpus), the ages-x-availability grid (all twelve
tier x band cells pinned to exact band, tier, score, priority), band
boundaries at 730/365/30, patched-row suppression, deterministic
ordering with tie-breaks, limit semantics (the queue caps, the counts
never), by-host grouping, oldest-unpatched selection, exact result
shapes, JSON safety, and the module purity source-scan.

Fixture provenance (tests/fixtures/scans/patch_report_shape.json):
fully synthetic - models the SOC patch monitor's report shape (ages
and exploit-availability markers per finding); CVE ids are real public
identifiers used as labels only. No network."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import aging_queue as aging_queue_mod
from agentic_ai.agents.cyber.aging_queue import (
    AGE_MULTIPLIERS,
    EXPLOIT_WEIGHTS,
    P1_MIN_SCORE,
    P2_MIN_SCORE,
    QUEUE_ROW_KEYS,
    ROW_KEYS,
    SCRUB_LIMIT,
    TOP_KEYS,
    aging_priority_queue,
    derive_grade,
    validate_patch_report,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "scans" / "patch_report_shape.json"
)
SNAP = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
REPORT = SNAP["report"]

CTRL = "\x01\x7f\n\t"


def _row(**overrides):
    """A well-formed unpatched row; overrides per test."""
    base = {
        "cve": "CVE-2017-0144",
        "host": "lab-win01",
        "platform": "windows",
        "product": "Microsoft SMBv1",
        "patched": False,
        "age_days": 4000,
        "exploit_available": True,
        "kev": True,
    }
    base.update(overrides)
    return base


def _report(*rows, **top):
    """A well-formed minimal report; top-level overrides per test."""
    out = {
        "monitor": "patch-monitor",
        "generated_at": "2026-10-05T09:00:00+00:00",
        "source": "synthetic (test-built)",
        "rows": list(rows),
    }
    out.update(top)
    return out


# --- the committed fixture pins its own schema --------------------------


def test_fixture_wraps_the_report_with_provenance():
    assert set(SNAP) == {"meta", "report"}
    meta = SNAP["meta"]
    assert set(meta) == {"name", "synthetic", "provenance", "trimmed"}
    assert meta["synthetic"] is True
    assert "aging_queue" in meta["provenance"]  # points at its consumer
    assert set(meta["trimmed"]) == {"rows_total", "unpatched", "patched"}


def test_fixture_carries_the_report_shape_exactly():
    assert set(REPORT) == set(TOP_KEYS)
    for row in REPORT["rows"]:
        assert set(row) == set(ROW_KEYS)
    assert "patched" in REPORT["rows"][0]


def test_fixture_trimmed_counts_match_the_rows():
    trimmed = SNAP["meta"]["trimmed"]
    rows = REPORT["rows"]
    assert trimmed["rows_total"] == len(rows)
    assert trimmed["unpatched"] == sum(
        1 for row in rows if not row["patched"])
    assert trimmed["patched"] == sum(1 for row in rows if row["patched"])
    assert trimmed["rows_total"] == (
        trimmed["unpatched"] + trimmed["patched"])


def test_fixture_validates_clean_and_spreads_the_priorities():
    assert validate_patch_report(REPORT) is None
    result = aging_priority_queue(REPORT)
    priorities = {entry["priority"] for entry in result["queue"]}
    assert priorities == {"P1", "P2", "P3"}
    tiers = {entry["exploit_tier"] for entry in result["queue"]}
    assert {"weaponized", "public", "none"} <= tiers


# --- the ages x availability grid ----------------------------------------


@pytest.mark.parametrize(
    "age_days,band",
    [(0, "fresh"), (29, "fresh"), (30, "aging"), (364, "aging"),
     (365, "stale"), (729, "stale"), (730, "ancient")],
)
def test_age_band_boundaries_are_inclusive(age_days, band):
    grade = derive_grade(_row(age_days=age_days, kev=False,
                              exploit_available=False))
    assert grade["age_band"] == band


@pytest.mark.parametrize(
    "kev,exploit_available,tier",
    [(True, False, "weaponized"),   # KEV outranks the missing flag
     (True, True, "weaponized"),    # KEV outranks the plain flag
     (False, True, "public"),
     (False, False, "none")],
)
def test_exploit_tier_precedence(kev, exploit_available, tier):
    grade = derive_grade(_row(kev=kev, exploit_available=exploit_available))
    assert grade["exploit_tier"] == tier


GRID_CELLS = [
    # (age_days, kev, available) -> (band, tier, score, priority)
    (25, True, False, "fresh", "weaponized", 4, "P3"),
    (200, True, True, "aging", "weaponized", 8, "P2"),
    (540, True, False, "stale", "weaponized", 16, "P1"),
    (4000, True, True, "ancient", "weaponized", 32, "P1"),
    (14, False, True, "fresh", "public", 2, "P3"),
    (300, False, True, "aging", "public", 4, "P3"),
    (620, False, True, "stale", "public", 8, "P2"),
    (2000, False, True, "ancient", "public", 16, "P1"),
    (12, False, False, "fresh", "none", 1, "P3"),
    (210, False, False, "aging", "none", 2, "P3"),
    (380, False, False, "stale", "none", 4, "P3"),
    (890, False, False, "ancient", "none", 8, "P2"),
]


def test_grid_scores_and_priorities_cover_all_twelve_cells():
    assert len(GRID_CELLS) == 12  # three tiers x four bands
    for age, kev, available, band, tier, score, priority in GRID_CELLS:
        grade = derive_grade(_row(age_days=age, kev=kev,
                                  exploit_available=available))
        assert grade == {
            "age_band": band, "exploit_tier": tier,
            "score": score, "priority": priority,
        }
        # the grid is the constants' product, powers of two only
        assert EXPLOIT_WEIGHTS[tier] * AGE_MULTIPLIERS[band] == score
    # the P cuts sit between grid cells, never inside one
    assert P1_MIN_SCORE == 12 and P2_MIN_SCORE == 8


def test_grade_shape_and_row_validation():
    grade = derive_grade(_row())
    assert set(grade) == {"age_band", "exploit_tier", "score", "priority"}
    for bad_row in ({}, {"cve": "CVE-2017-0144"}, _row(age_days=True),
                    _row(cve="oops"), _row(kev=1)):
        with pytest.raises(ValueError):
            derive_grade(bad_row)


# --- the module scrub helper ---------------------------------------------


def test_scrub_helper_cleans_caps_and_passes_nonstrings_empty():
    cases = [
        ("lab" + CTRL + "win", "labwin"),   # control characters gone
        ("x\t \n y  z", "x y z"),           # whitespace runs collapse
        ("  padded  ", "padded"),           # outer whitespace stripped
        ("h" * 500, "h" * SCRUB_LIMIT),     # length capped
        ("lab\u00e9-01", "lab\u00e9-01"),   # unicode preserved
        ("lab-win01", "lab-win01"),         # clean identity
        (42, ""),                           # non-string -> empty
        (None, ""),
        (["x"], ""),
    ]
    for raw, expected in cases:
        assert aging_queue_mod._scrub_text(raw) == expected, raw[:20]


# --- the validator: refuse closed ----------------------------------------


@pytest.mark.parametrize("key", TOP_KEYS)
def test_missing_top_key_is_actionable(key):
    broken = json.loads(json.dumps(REPORT))
    del broken[key]
    with pytest.raises(ValueError) as err:
        validate_patch_report(broken)
    assert "missing required keys" in str(err.value)
    assert key in str(err.value)


def test_validator_refuses_closed_reports():
    hostile = [
        None, 42, "nope", [],
        {"monitor": "x"},                 # partially shaped top level
        _report(rows="nope"),             # rows not a list
        _report("not-a-dict", _row()),    # a non-mapping row
        _report(["still-not-a-dict", 42]),
    ]
    for bad_report in hostile:
        with pytest.raises(ValueError) as err:
            validate_patch_report(bad_report)
        assert str(err.value).strip()  # every refusal names its reason


ROW_FAILURES = [
    ("missing-cve", {k: v for k, v in _row().items() if k != "cve"}),
    ("missing-age", {k: v for k, v in _row().items() if k != "age_days"}),
    ("missing-kev", {k: v for k, v in _row().items() if k != "kev"}),
    ("cve-malformed", _row(cve="not-a-cve")),
    ("cve-not-string", _row(cve=42)),
    ("cve-trailing-newline", _row(cve="CVE-2017-0144" + "\n")),
    ("age-negative", _row(age_days=-1)),
    ("age-string", _row(age_days="4000")),
    ("age-bool", _row(age_days=True)),
    ("patched-not-bool", _row(patched="no")),
    ("kev-not-bool", _row(kev=1)),
    ("available-not-bool", _row(exploit_available=None)),
    ("host-blank", _row(host="   ")),
    ("host-not-string", _row(host=None)),
    ("product-blank", _row(product="")),
]


def test_malformed_rows_are_refused():
    for label, bad_row in ROW_FAILURES:
        with pytest.raises(ValueError) as err:
            validate_patch_report(_report(bad_row, _row()))
        assert "patch report row 0" in str(err.value), label


def test_validation_error_carries_row_index_and_field():
    report = _report(_row(), _row(cve="oops"))
    with pytest.raises(ValueError) as err:
        validate_patch_report(report)
    assert "row 1" in str(err.value)
    assert "cve malformed" in str(err.value)


# --- the priority report op ----------------------------------------------


def test_priority_report_output_schema_is_exact():
    result = aging_priority_queue(REPORT)
    assert set(result) == {
        "counts", "queue", "by_host", "oldest_unpatched", "notes"}
    assert set(result["counts"]) == {
        "total_rows", "unpatched", "patched", "p1", "p2", "p3"}
    for entry in result["queue"]:
        assert set(entry) == set(QUEUE_ROW_KEYS)
    assert len(result["notes"]) >= 3
    for note in result["notes"]:
        assert isinstance(note, str) and bool(note.strip())
    assert isinstance(result["by_host"], dict)
    assert isinstance(result["oldest_unpatched"], dict)


def test_counts_are_the_whole_reports_truth():
    counts = aging_priority_queue(REPORT)["counts"]
    assert counts == {
        "total_rows": 12, "unpatched": 10, "patched": 2,
        "p1": 3, "p2": 2, "p3": 5,
    }
    # always accounting: every unpatched row lands in exactly one band
    assert counts["p1"] + counts["p2"] + counts["p3"] == (
        counts["unpatched"])
    assert counts["unpatched"] + counts["patched"] == (
        counts["total_rows"])
    # even when the queue is limited, the counts never change
    assert (
        aging_priority_queue(REPORT, limit=1)["counts"] == counts)


def test_queue_order_is_deterministic_and_exact():
    result = aging_priority_queue(REPORT)
    assert result["queue"] == aging_priority_queue(REPORT)["queue"]
    assert [entry["cve"] for entry in result["queue"]] == [
        "CVE-2017-0144",   # weaponized x ancient, 3497d -> 32
        "CVE-2021-44228",  # weaponized x ancient, 1408d -> 32
        "CVE-2024-3400",   # weaponized x stale, 540d -> 16
        "CVE-2020-27350",  # none x ancient, 890d -> 8 (age wins the tie)
        "CVE-2019-0708",   # public x stale, 620d -> 8
        "CVE-2022-3602",   # none x stale, 380d -> 4 (age wins the tie)
        "CVE-2023-48795",  # public x aging, 300d -> 4
        "CVE-2025-3248",   # weaponized x fresh, 25d -> 4
        "CVE-2018-1000620",  # none x aging, 210d -> 2
        "CVE-2016-1000027",  # none x fresh, 12d -> 1
    ]
    assert [entry["priority"] for entry in result["queue"]] == [
        "P1", "P1", "P1", "P2", "P2", "P3", "P3", "P3", "P3", "P3"]


def test_score_ties_break_by_age_then_host_then_cve():
    tied = _report(
        _row(cve="CVE-9999-0001", host="lab-z", age_days=100),
        _row(cve="CVE-9999-0003", host="lab-a", age_days=100),
        _row(cve="CVE-9999-0002", host="lab-b", age_days=200),
        _row(cve="CVE-9999-0004", host="lab-b", age_days=100),
    )
    result = aging_priority_queue(tied)
    assert [(entry["cve"], entry["host"])
            for entry in result["queue"]] == [
        ("CVE-9999-0002", "lab-b"),  # age 200 first
        ("CVE-9999-0003", "lab-a"),  # age tie: host lab-a
        ("CVE-9999-0004", "lab-b"),  # then lab-b
        ("CVE-9999-0001", "lab-z"),  # same host: cve order
    ]
    # duplicate cves on different hosts are queueable and distinguishable
    assert len(result["queue"]) == 4


def test_patched_rows_never_enter_the_queue():
    result = aging_priority_queue(REPORT)
    cves = [entry["cve"] for entry in result["queue"]]
    assert len(cves) == 10
    assert "CVE-2016-2183" not in cves       # patched, unexploited
    assert "CVE-2020-1472" not in cves       # patched DESPITE a KEV flag
    raw_unpatched = {
        row["cve"] for row in REPORT["rows"] if not row["patched"]}
    assert set(cves) == raw_unpatched


def test_queue_echoes_are_scrubbed_and_json_safe():
    cases = [
        ("host", "lab" + CTRL + "win", "labwin"),
        ("product", "x" * 500, "x" * SCRUB_LIMIT),
        ("platform", "win\t dows", "win dows"),
    ]
    for field, raw, expected in cases:
        report = _report(_row(**{field: raw}))
        entry = aging_priority_queue(report)["queue"][0]
        assert entry[field] == expected
        assert all(ord(char) >= 0x20 for char in entry[field])
        assert json.dumps(aging_priority_queue(report))


def test_by_host_mirrors_the_published_queue():
    result = aging_priority_queue(REPORT)
    by_host = result["by_host"]
    hosts = [entry["host"] for entry in result["queue"]]
    assert list(by_host) == list(dict.fromkeys(hosts))  # first-seen order
    assert sum(len(v) for v in by_host.values()) == len(result["queue"])
    assert by_host["lab-app02"] == ["CVE-2021-44228", "CVE-2018-1000620"]
    assert "lab-dr01" not in by_host  # only patched rows on that host
    # grouped by host even for a single-finding host
    assert by_host["lab-win01"] == ["CVE-2017-0144"]


def test_top_of_queue_and_oldest_unpatched_are_exact():
    result = aging_priority_queue(REPORT)
    assert result["queue"][0] == {
        "cve": "CVE-2017-0144", "host": "lab-win01",
        "platform": "windows", "product": "Microsoft SMBv1",
        "age_days": 3497, "age_band": "ancient",
        "exploit_tier": "weaponized", "score": 32, "priority": "P1",
    }
    assert result["oldest_unpatched"] == {
        "cve": "CVE-2017-0144", "host": "lab-win01", "age_days": 3497}


def test_oldest_unpatched_tie_keeps_input_order():
    tied = _report(
        _row(cve="CVE-2017-0144", host="lab-a", age_days=99),
        _row(cve="CVE-2017-0144", host="lab-b", age_days=99),
    )
    result = aging_priority_queue(tied)
    assert result["oldest_unpatched"] == {
        "cve": "CVE-2017-0144", "host": "lab-a", "age_days": 99}


def test_limit_caps_the_queue_as_a_prefix_and_says_so():
    result = aging_priority_queue(REPORT, limit=3)
    full = aging_priority_queue(REPORT)
    assert [entry["cve"] for entry in result["queue"]] == [
        "CVE-2017-0144", "CVE-2021-44228", "CVE-2024-3400"]
    assert result["queue"] == full["queue"][:3]  # the top prefix
    assert result["counts"] == full["counts"]    # counts stay full
    assert set(result["by_host"]) == {"lab-win01", "lab-app02",
                                      "lab-fw01"}  # published only
    assert len(result["notes"]) == 4
    assert result["notes"][-1] == (
        "queue limited to the top 3 of 10 unpatched findings")


def test_limit_at_or_above_the_queue_changes_nothing():
    full = aging_priority_queue(REPORT)
    assert aging_priority_queue(REPORT, limit=10) == full
    assert aging_priority_queue(REPORT, limit=25) == full


@pytest.mark.parametrize("bad_limit", [0, -1, True, "3"])
def test_limit_must_be_none_or_a_positive_integer(bad_limit):
    with pytest.raises(ValueError) as err:
        aging_priority_queue(REPORT, limit=bad_limit)
    assert "limit" in str(err.value)


def test_all_patched_reports_queue_nothing():
    report = _report(
        _row(cve="CVE-2017-0144", patched=True),
        _row(cve="CVE-2019-0708", host="lab-b", patched=True),
    )
    result = aging_priority_queue(report)
    assert result["queue"] == []
    assert result["by_host"] == {}
    assert result["oldest_unpatched"] is None
    assert result["counts"] == {
        "total_rows": 2, "unpatched": 0, "patched": 2,
        "p1": 0, "p2": 0, "p3": 0,
    }


def test_empty_rows_reports_are_well_formed():
    result = aging_priority_queue(_report())
    assert result["queue"] == []
    assert result["by_host"] == {}
    assert result["oldest_unpatched"] is None
    assert result["counts"] == {
        "total_rows": 0, "unpatched": 0, "patched": 0,
        "p1": 0, "p2": 0, "p3": 0,
    }
    assert len(result["notes"]) == 3


def test_notes_pin_the_stance_in_lockstep_with_constants():
    notes = aging_priority_queue(REPORT)["notes"]
    assert len(notes) == 3
    assert notes[0].startswith("unpatched findings only: 2 of 12 ")
    assert "weaponized" in notes[1] and "public" in notes[1]
    assert ("P1 >= %d, P2 >= %d" % (P1_MIN_SCORE, P2_MIN_SCORE)
            ) in notes[2]
    assert "score = tier weight x age band multiplier" in notes[2]


def test_full_report_roundtrips_json():
    result = aging_priority_queue(REPORT)
    assert json.loads(json.dumps(result)) == result


# --- planner purity -------------------------------------------------------


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.aging_queue")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        # no chassis import (a pure planner)
        "from agentic_ai", "import agentic_ai",
        # no process spawning or dynamic execution
        "subprocess", "popen", "os.system", "eval(", "exec(",
        # no network facilities
        "urllib", "socket", "requests", "http.client",
        # no wall clock: the ages arrive in the report
        "utcnow", "time.time", "today(", "gmtime", "localtime",
    ):
        assert forbidden not in source, forbidden
