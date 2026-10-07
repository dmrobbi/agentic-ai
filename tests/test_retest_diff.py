"""KA-085 tests - retest diff: the exact output schema (top-level keys,
counts keys, entry and warning key sets), the full classification
matrix on a canned two-run scenario (resolved/new/regressed/unchanged,
scalar truths), matched pairs, resolved-by-absence echoes, retest-side
echoing, not_present spellings, fingerprint fallback (normalized
title + target), identity precedence and the id/fingerprint
never-cross rule, case-sensitive ids, duplicate identities (first
kept + warned), a hostile corpus (non-mappings, non-lists,
identity-less findings, blank/unknown statuses - never raising),
warnings shape and side order, DIFF_CAP enforcement with counts
carrying the uncapped truth, deterministic ordering across input
permutations, JSON safety, the scrub helper, and the module purity
source-scan. Fully synthetic findings; no network."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import retest_diff as retest_diff_mod
from agentic_ai.agents.cyber.retest_diff import (
    COUNT_KEYS,
    DIFF_CAP,
    ENTRY_KEYS,
    NOTE_CLASSIFICATION,
    NOTE_DISCIPLINE,
    NOTE_MATCHING,
    OUTPUT_KEYS,
    SCRUB_LIMIT,
    STATUSES,
    WARNING_KEYS,
    diff_retests,
)


def _find(fid=None, title=None, severity=None, status=None, host=None,
          target=None, **extra):
    """One finding dict; only the given keys are present."""
    out = {}
    if fid is not None:
        out["id"] = fid
    if title is not None:
        out["title"] = title
    if severity is not None:
        out["severity"] = severity
    if status is not None:
        out["status"] = status
    if host is not None:
        out["host"] = host
    if target is not None:
        out["target"] = target
    out.update(extra)
    return out


def _canned_runs():
    """Two runs over the same target touching every classification
    cell: an unchanged pair, a resolved pair, a pair resolved by
    absence, a regressed pair, a returning not_present finding, an
    unlabelled-title fingerprint pair, a retest-only finding, and a
    retest not_present row without a counterpart."""
    baseline = [
        _find(fid="V-01", title="ssh root login", severity="high",
              status="open", host="lab-1"),        # unchanged pair
        _find(fid="V-02", title="outdated openssl",
              severity="medium", status="open"),   # resolves (fixed)
        _find(fid="V-03", title="default creds", severity="low",
              status="fixed"),                     # regresses
        _find(fid="V-04", title="info banner", severity="info",
              status="fixed"),                     # unchanged pair
        _find(fid="V-05", title="weak tls", severity="medium",
              status="not_present"),               # returns -> new
        _find(fid="V-06", title="gone", severity="low",
              status="not_present"),               # retest silent
        _find(title="legacy no id", status="open", host="lab-2"),
    ]                                              # fingerprint pair
    retest = [
        _find(fid="V-01", title="ssh root login", severity="high",
              status="open", host="lab-1"),
        _find(fid="V-02", title="outdated openssl", severity="high",
              status="fixed"),
        _find(fid="V-03", title="default creds", severity="critical",
              status="open"),
        _find(fid="V-04", title="info banner", severity="info",
              status="fixed"),
        _find(fid="V-05", title="weak tls", severity="medium",
              status="open"),
        _find(title="legacy no id", severity="low", status="fixed",
              host="lab-2"),
        _find(fid="V-99", title="fresh hit", severity="high",
              status="open"),                      # retest-only
        _find(fid="V-98", title="still absent", severity="info",
              status="not_present"),               # no counterpart
    ]
    return baseline, retest


# --- the op's output schema -------------------------------------------------


def test_output_schema_is_exact():
    assert STATUSES == ("open", "fixed", "not_present")
    assert DIFF_CAP == 25 and SCRUB_LIMIT == 128
    baseline, retest = _canned_runs()
    result = diff_retests(baseline, retest)
    assert set(result) == set(OUTPUT_KEYS)
    assert set(result["counts"]) == set(COUNT_KEYS)
    for bucket in ("resolved", "new", "regressed"):
        for entry in result[bucket]:
            assert set(entry) == set(ENTRY_KEYS)
    for warning in result["warnings"]:
        assert set(warning) == set(WARNING_KEYS)
    for note in result["notes"]:
        assert isinstance(note, str) and bool(note.strip())


def test_canned_scenario_counts_scalars_and_lists_exactly():
    baseline, retest = _canned_runs()
    result = diff_retests(baseline, retest)
    assert result["counts"] == {
        "resolved": 2, "new": 2, "regressed": 1,
        "unchanged": 4, "matched": 6, "warnings": 0,
    }
    assert result["matched_count"] == 6
    assert result["unchanged_count"] == 4
    assert result["resolved"] == [
        {"id": "V-02", "title": "outdated openssl", "severity": "high",
         "target": "", "baseline_status": "open",
         "retest_status": "fixed", "matched_by": "id"},
        {"id": "", "title": "legacy no id", "severity": "low",
         "target": "lab-2", "baseline_status": "open",
         "retest_status": "fixed", "matched_by": "fingerprint"},
    ]
    assert result["new"] == [
        {"id": "V-05", "title": "weak tls", "severity": "medium",
         "target": "", "baseline_status": "not_present",
         "retest_status": "open", "matched_by": "id"},
        {"id": "V-99", "title": "fresh hit", "severity": "high",
         "target": "", "baseline_status": None,
         "retest_status": "open", "matched_by": "unmatched"},
    ]
    assert result["regressed"] == [
        {"id": "V-03", "title": "default creds", "severity": "critical",
         "target": "", "baseline_status": "fixed",
         "retest_status": "open", "matched_by": "id"},
    ]
    assert result["warnings"] == []


# --- the classification matrix -------------------------------------------


def test_open_to_fixed_resolves_echoing_the_retest_side():
    result = diff_retests(
        [_find(fid="V-1", title="x", severity="medium", status="open",
               host="h1")],
        [_find(fid="V-1", title="x", severity="high", status="fixed",
               host="h1")])
    assert result["resolved"] == [{
        "id": "V-1", "title": "x", "severity": "high", "target": "h1",
        "baseline_status": "open", "retest_status": "fixed",
        "matched_by": "id",
    }]
    assert result["counts"]["resolved"] == 1
    assert result["matched_count"] == 1
    assert result["unchanged_count"] == 0


def test_open_with_no_retest_counterpart_resolves_by_absence():
    result = diff_retests(
        [_find(fid="V-1", title="x", severity="medium", status="open",
               host="h1")], [])
    assert result["resolved"] == [{
        "id": "V-1", "title": "x", "severity": "medium", "target": "h1",
        "baseline_status": "open", "retest_status": None,
        "matched_by": "unmatched",
    }]
    assert result["counts"] == {"resolved": 1, "new": 0, "regressed": 0,
                                "unchanged": 0, "matched": 0,
                                "warnings": 0}


@pytest.mark.parametrize("spelling", ["not_present", "not present",
                                      "not-present", "notpresent"])
def test_open_to_not_present_spellings_resolve(spelling):
    result = diff_retests(
        [_find(fid="V-1", title="x", status="open")],
        [_find(fid="V-1", title="x", status=spelling)])
    assert result["counts"]["resolved"] == 1
    assert result["matched_count"] == 1
    assert result["resolved"][0]["retest_status"] == "not_present"


def test_fixed_baseline_stays_unchanged_without_a_reopen():
    # equal statuses, a listed not_present, and plain absence: none
    # of them churns a fixed finding
    cases = [("fixed", 1), ("not_present", 1), ("absent", 0)]
    for retest_status, expected_matched in cases:
        retest = [] if retest_status == "absent" else [
            _find(fid="V-1", title="x", status=retest_status)]
        result = diff_retests(
            [_find(fid="V-1", title="x", status="fixed")], retest)
        assert result["unchanged_count"] == 1, retest_status
        assert result["matched_count"] == expected_matched, retest_status
        assert result["resolved"] == [] and result["new"] == []
        assert result["regressed"] == []


def test_fixed_to_open_regresses():
    result = diff_retests(
        [_find(fid="V-1", title="x", severity="info", status="fixed")],
        [_find(fid="V-1", title="x", severity="info", status="open")])
    assert result["regressed"] == [{
        "id": "V-1", "title": "x", "severity": "info", "target": "",
        "baseline_status": "fixed", "retest_status": "open",
        "matched_by": "id",
    }]
    assert result["counts"]["regressed"] == 1
    assert result["matched_count"] == 1


@pytest.mark.parametrize("status", ["open", "fixed"])
def test_not_present_baseline_returning_is_new(status):
    result = diff_retests(
        [_find(fid="V-1", title="x", status="not_present")],
        [_find(fid="V-1", title="x", status=status)])
    assert result["counts"]["new"] == 1
    assert result["matched_count"] == 1
    assert result["new"] == [{
        "id": "V-1", "title": "x", "severity": "", "target": "",
        "baseline_status": "not_present", "retest_status": status,
        "matched_by": "id",
    }]


def test_not_present_staying_quiet_is_never_churn():
    result = diff_retests(
        [_find(fid="V-1", title="x", status="not_present")],
        [_find(fid="V-1", title="x", status="not_present")])
    assert result["unchanged_count"] == 1
    assert result["matched_count"] == 1
    result = diff_retests(
        [_find(fid="V-1", title="x", status="not_present")], [])
    assert result["unchanged_count"] == 1
    assert result["matched_count"] == 0
    assert result["counts"]["new"] == 0


@pytest.mark.parametrize("status", ["open", "fixed"])
def test_unmatched_retest_finding_is_new(status):
    result = diff_retests(
        [_find(fid="V-1", title="other", status="open")],
        [_find(fid="V-2", title="x", status=status, host="lab-9")])
    assert result["counts"]["new"] == 1
    assert result["matched_count"] == 0
    assert result["new"] == [{
        "id": "V-2", "title": "x", "severity": "",
        "target": "lab-9", "baseline_status": None,
        "retest_status": status, "matched_by": "unmatched",
    }]


def test_unmatched_retest_not_present_is_no_churn():
    result = diff_retests(
        [_find(fid="V-1", title="x", status="open")],
        [_find(fid="V-1", title="x", status="open"),
         _find(fid="V-2", title="y", status="not_present")])
    assert result["counts"] == {
        "resolved": 0, "new": 0, "regressed": 0,
        "unchanged": 2, "matched": 1, "warnings": 0}


# --- identity: explicit ids, fingerprint fallback, precedence -------------


def test_id_matching_is_case_sensitive_with_no_fingerprint_fallback():
    result = diff_retests(
        [_find(fid="V-1", title="x", status="open")],
        [_find(fid="v-1", title="x", status="fixed")])
    assert result["matched_count"] == 0
    assert result["counts"]["resolved"] == 1
    assert result["counts"]["new"] == 1
    assert result["resolved"][0]["matched_by"] == "unmatched"
    assert result["new"][0]["matched_by"] == "unmatched"


@pytest.mark.parametrize("hint_key", ["host", "target"])
def test_fingerprint_fallback_normalizes_title_and_target(hint_key):
    baseline = [_find(title="  SQL   Injection   in Login ",
                      status="open", **{hint_key: "lab-1"})]
    retest = [_find(title="sql injection in login", status="fixed",
                    **{hint_key: "LAB-1"})]
    result = diff_retests(baseline, retest)
    assert result["counts"]["resolved"] == 1
    assert result["matched_count"] == 1
    assert result["resolved"][0]["matched_by"] == "fingerprint"


def test_fingerprint_requires_a_matching_target():
    result = diff_retests(
        [_find(title="same title", status="open", host="lab-1")],
        [_find(title="same title", status="fixed", host="lab-2")])
    assert result["matched_count"] == 0
    assert result["counts"]["resolved"] == 1
    assert result["counts"]["new"] == 1
    # title-only fingerprints (no hints at all) still meet
    result = diff_retests(
        [_find(title="same title", status="open")],
        [_find(title="same title", status="fixed")])
    assert result["matched_count"] == 1
    assert result["counts"]["resolved"] == 1


def test_explicit_ids_never_cross_match_fingerprints():
    # the retest starts labelling ids over unlabeled titles
    result = diff_retests(
        [_find(title="x", status="open", host="h")],
        [_find(fid="A-1", title="x", status="fixed", host="h")])
    assert result["matched_count"] == 0
    assert result["counts"]["resolved"] == 1
    assert result["counts"]["new"] == 1
    # and the reverse: the baseline labels, the retest drops them
    result = diff_retests(
        [_find(fid="A-1", title="x", status="open", host="h")],
        [_find(title="x", status="fixed", host="h")])
    assert result["matched_count"] == 0
    assert result["counts"]["resolved"] == 1
    assert result["counts"]["new"] == 1


def test_target_hint_prefers_host_over_target():
    result = diff_retests(
        [_find(title="t", status="fixed", host="lab-1",
               target="10.0.0.1")],
        [_find(title="t", status="open", host="lab-1",
               target="10.9.9.9")])
    assert result["counts"]["regressed"] == 1
    assert result["matched_count"] == 1
    result = diff_retests(
        [_find(title="t", status="open", host="lab-1",
               target="10.0.0.1")],
        [_find(title="t", status="open", host="lab-2",
               target="10.0.0.1")])
    assert result["matched_count"] == 0
    assert result["counts"]["regressed"] == 0
    assert result["resolved"][0]["target"] == "lab-1"  # baseline echo
    assert result["new"][0]["target"] == "lab-2"       # retest echo


def test_duplicate_id_keeps_the_first_and_warns():
    result = diff_retests(
        [_find(fid="V-1", title="first", status="open"),
         _find(fid="V-1", title="second", status="fixed")],
        [_find(fid="V-1", title="first", status="open")])
    assert result["matched_count"] == 1
    assert result["unchanged_count"] == 1
    assert result["counts"]["warnings"] == 1
    warning = result["warnings"][0]
    assert warning["side"] == "baseline" and warning["index"] == 1
    assert "duplicate id" in warning["reason"]
    assert "V-1" in warning["reason"] and "index 0" in warning["reason"]
    assert warning["id"] == "V-1" and warning["title"] == "second"


def test_duplicate_fingerprint_keeps_the_first_and_warns():
    result = diff_retests(
        [_find(title="dup", status="open", host="h")],
        [_find(title="dup", status="open", host="h"),
         _find(title="dup", status="fixed", host="h")])
    assert result["matched_count"] == 1
    assert result["unchanged_count"] == 1
    assert result["counts"]["warnings"] == 1
    warning = result["warnings"][0]
    assert warning["side"] == "retest" and warning["index"] == 1
    assert "duplicate fingerprint" in warning["reason"]


# --- the warnings bucket over a hostile corpus ----------------------------


@pytest.mark.parametrize("bad", [None, 42, "x"])
def test_non_mapping_rows_warn(bad):
    result = diff_retests([_find(fid="V-1", status="open"), bad], [])
    warnings = [w for w in result["warnings"] if w["index"] == 1]
    assert len(warnings) == 1 and warnings[0]["side"] == "baseline"
    assert "not a mapping" in warnings[0]["reason"]
    assert warnings[0]["id"] == "" and warnings[0]["title"] == ""
    assert result["counts"]["warnings"] == 1
    assert result["counts"]["resolved"] == 1  # the valid row resolves


def test_run_levels_that_are_not_lists_warn_and_treat_empty():
    for bad in (None, 42, "x", {"id": "V-1"}):
        result = diff_retests(bad, [])
        assert set(result) == set(OUTPUT_KEYS)
        assert result["counts"] == {
            "resolved": 0, "new": 0, "regressed": 0,
            "unchanged": 0, "matched": 0, "warnings": 1}
        warning = result["warnings"][0]
        assert warning["side"] == "baseline" and warning["index"] is None
        assert warning["reason"].startswith("not a list")
        # the mirrored side warns the same way
        result = diff_retests([], bad)
        assert result["warnings"][0]["side"] == "retest"
        assert result["counts"]["new"] == 0


def test_findings_without_id_and_title_warn():
    result = diff_retests(
        [{}, {"status": "open"}, {"id": "", "title": "  "},
         {"severity": "high"}], [])
    assert result["counts"]["warnings"] == 4
    assert [w["index"] for w in result["warnings"]] == [0, 1, 2, 3]
    for warning in result["warnings"]:
        assert "no id and no title" in warning["reason"]
        assert warning["id"] == "" and warning["title"] == ""
    # a non-string id scrubs away and falls back to the fingerprint
    result = diff_retests(
        [{"id": 42, "title": "t", "status": "open"}],
        [{"title": "t", "status": "fixed"}])
    assert result["matched_count"] == 1
    assert result["counts"]["resolved"] == 1


def test_missing_status_warns_but_the_pair_counts_and_never_classifies():
    result = diff_retests(
        [_find(fid="V-2", title="x")],
        [_find(fid="V-2", title="x", status="open")])
    assert result["counts"] == {
        "resolved": 0, "new": 0, "regressed": 0,
        "unchanged": 0, "matched": 1, "warnings": 1}
    warning = result["warnings"][0]
    assert warning["side"] == "baseline" and warning["index"] == 0
    assert "no status" in warning["reason"]


def test_unknown_status_warns_the_same_way():
    result = diff_retests(
        [_find(fid="V-3", title="x", status="wip")],
        [_find(fid="V-3", title="x", status="open")])
    assert result["counts"] == {
        "resolved": 0, "new": 0, "regressed": 0,
        "unchanged": 0, "matched": 1, "warnings": 1}
    warning = result["warnings"][0]
    assert "unknown status" in warning["reason"]
    assert "'wip'" in warning["reason"]


def test_warnings_shape_side_order_and_best_effort_echoes():
    result = diff_retests(
        ["nope", _find(fid="V-A", title="ok", status="open"), {}],
        [_find(fid="V-B", title="meh")])
    assert [(w["side"], w["index"]) for w in result["warnings"]] == [
        ("baseline", 0), ("baseline", 2), ("retest", 0)]
    assert result["warnings"][0]["reason"] == "not a mapping; skipped"
    assert result["warnings"][0]["id"] == ""
    assert "no id and no title" in result["warnings"][1]["reason"]
    assert "no status" in result["warnings"][2]["reason"]
    assert result["warnings"][2]["id"] == "V-B"  # best-effort echo
    # the clean baseline row resolves by absence; the status-less
    # retest finding leaves the new bucket alone
    assert result["counts"]["resolved"] == 1
    assert result["counts"]["new"] == 0
    assert result["counts"]["matched"] == 0


# --- the house cap ---------------------------------------------------------


def _churn_case(bucket):
    """Thirty churn entries for one bucket."""
    if bucket == "resolved":
        return ([_find(fid="V-%03d" % n, title="f%d" % n, status="open")
                 for n in range(30)], [])
    if bucket == "new":
        return ([], [_find(fid="V-%03d" % n, title="f%d" % n,
                           status="open") for n in range(30)])
    return (
        [_find(fid="V-%03d" % n, title="f%d" % n, status="fixed")
         for n in range(30)],
        [_find(fid="V-%03d" % n, title="f%d" % n, status="open")
         for n in range(30)])


@pytest.mark.parametrize("bucket", ["resolved", "new", "regressed"])
def test_churn_lists_cap_at_diff_cap_with_counts_carrying_truth(bucket):
    baseline, retest = _churn_case(bucket)
    result = diff_retests(baseline, retest)
    assert result["counts"][bucket] == 30
    assert result["counts"]["unchanged"] == 0
    assert len(result[bucket]) == DIFF_CAP
    assert result[bucket][0]["id"] == "V-000"
    assert len(result["warnings"]) == 0
    assert result["notes"][-1] == (
        "%s limited to the first 25 of 30 entries" % bucket)


def test_warnings_cap_at_diff_cap_with_count_truth():
    result = diff_retests([42 for _ in range(40)], [])
    assert result["counts"]["warnings"] == 40
    assert len(result["warnings"]) == DIFF_CAP
    assert len(result["notes"]) == 4
    assert result["notes"][-1] == (
        "warnings limited to the first 25 of 40 entries")
    assert result["counts"]["resolved"] == 0


# --- echoes, notes, JSON, scrub, purity ------------------------------------


def test_severity_echo_scrubs_from_the_echoed_side():
    result = diff_retests(
        [_find(fid="V-1", title="x", status="open", severity="medium")],
        [_find(fid="V-1", title="x", status="fixed",
               severity="  hi\x01gh\r sev  ")])
    assert result["resolved"][0]["severity"] == "high sev"
    # a resolved-by-absence entry echoes the baseline severity, and a
    # non-string severity scrubs to "" without a warning
    result = diff_retests(
        [_find(fid="V-9", title="x", status="open",
               severity=["not", "a", "string"])], [])
    assert result["resolved"][0]["severity"] == ""
    assert result["counts"]["warnings"] == 0


def test_extra_finding_keys_and_hostilities_do_not_leak():
    result = diff_retests(
        [_find(fid="V-1", title="t", status="open", host="h",
               description="probe me", cve="CVE-2026-0001",
               nested={"deep": [1, 2]})],
        [_find(fid="V-1", title="t", status="fixed", host="h",
               payload="<script>alert(1)</script>")])
    for entry in result["resolved"]:
        assert set(entry) == set(ENTRY_KEYS)
    text = json.dumps(result)
    assert "probe me" not in text
    assert "script" not in text


def test_empty_runs_produce_a_zeroed_report():
    result = diff_retests([], [])
    assert result == {
        "resolved": [], "new": [], "regressed": [],
        "unchanged_count": 0, "matched_count": 0, "warnings": [],
        "counts": {"resolved": 0, "new": 0, "regressed": 0,
                   "unchanged": 0, "matched": 0, "warnings": 0},
        "notes": [NOTE_MATCHING, NOTE_CLASSIFICATION, NOTE_DISCIPLINE],
    }


def test_notes_pin_the_derivation_stances():
    baseline, retest = _canned_runs()
    notes = diff_retests(baseline, retest)["notes"]
    assert len(notes) == 3
    assert "explicit id" in notes[0] and "fingerprint" in notes[0]
    for phrase in ("resolved", "regresses", "new", "unchanged"):
        assert phrase in notes[1]
    assert "never raises" in notes[2]
    assert "duplicate identities" in notes[2]


def test_report_is_deterministic_across_input_permutation():
    baseline, retest = _canned_runs()
    first = diff_retests(baseline, retest)
    assert first == diff_retests(baseline, retest)  # reruns agree
    assert first == diff_retests(  # input order cannot leak
        baseline[::-1], retest[::-1])


def test_full_report_roundtrips_json():
    result = diff_retests(*_canned_runs())
    assert json.loads(json.dumps(result)) == result


def test_scrub_helper_house_behaviour():
    cases = [
        ("lab\x01\x7fwin", "labwin"),       # control characters gone
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
        assert retest_diff_mod._scrub_text(raw) == expected, repr(raw)[:20]
    norm = retest_diff_mod._norm_status
    for raw, expected in [
        ("open", "open"), ("FIXED", "fixed"), ("not present", "not_present"),
        ("not-present", "not_present"), ("notpresent", "not_present"),
        ("  open ", "open"), ("", None), ("wip", None), (None, None),
    ]:
        assert norm(raw) == expected, repr(raw)


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.retest_diff")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        # no chassis import (a pure module)
        "from agentic_ai", "import agentic_ai",
        # no process spawning or dynamic execution
        "subprocess", "popen", "os.system", "eval(", "exec(",
        # no network facilities
        "urllib", "socket", "requests", "http.client",
        # no wall clock: the churn lives entirely in the two lists
        "utcnow", "time.time", "today(", "gmtime", "localtime",
    ):
        assert forbidden not in source, forbidden