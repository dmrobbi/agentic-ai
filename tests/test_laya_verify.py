"""KA-071 tests - laya double-check: the independent verifier over laya's
escalated decision rows.

Fixture provenance: tests/fixtures/findings/laya_decision_rows.json -
SYNTHETIC laya_gated_decision rows modeling the SOC audit-line shape
pinned by test_laya_replay.py (ts/kind/alert_id/severity/model/outcome/
duration_ms/detail); escalation/gate variants for the verdict
precedence; hostile/schema-violating rows for the unverifiable route.
CVEs reference the real-CVE universe of the KA-001 corpus (engine-known:
2021-44228 Log4Shell / 2017-0144 EternalBlue / 2019-0708 BlueKeep;
deliberately absent: 2026-4499). No live SOC data, no credentials, no
network, no file writes.

Pinned here: the corpus verdict matrix (every row routed), the
over-escalation / under-escalation guard edges, gate-marker semantics
per row and at batch level, intake shape tolerance (deliberate misses
land unverifiable, never crash), the once-per-unique-CVE matcher
protocol and injection isolation, exact summary/report shapes, JSON
safety, op docstring discipline, and the planner purity source scan
(the lazy engine default is the single allowed agentic_ai reference).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber import laya_verify
from agentic_ai.agents.cyber.laya_verify import (
    CALM_OUTCOMES,
    ESCALATION_BANDS,
    ESCALATION_OUTCOMES,
    MAX_DETAIL_CHARS,
    LayaVerifier,
    REASON_BAND_AGREES,
    REASON_CONSISTENT,
    REASON_GATE_FALSE,
    REASON_OVER_ESCALATION,
    REASON_UNDER_ESCALATION,
    REASON_UNKNOWN_OUTCOME,
    VERDICT_AGREE,
    VERDICT_DISAGREE,
    VERDICT_NOT_ESCALATED,
    VERDICT_REVIEW_ESCALATION,
    VERDICT_REVIEW_OUTCOME,
    scrub_decision_id,
    scrub_detail,
    severity_band,
    render_report,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / (
    "tests/fixtures/findings/laya_decision_rows.json")


def corpus_rows():
    with FIXTURE_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)["rows"]


def row_by_id(alert_id):
    return next(r for r in corpus_rows() if r["alert_id"] == alert_id)


def make_row(**overrides):
    """A valid calm decision row; overrides per test."""
    base = {
        "ts": "2026-10-05T09:00:00Z", "kind": "laya_gated_decision",
        "alert_id": "LAY-2700", "severity": 2,
        "model": "laya-typed-decisions", "outcome": "ok",
        "duration_ms": 950, "detail": "plain row detail",
    }
    base.update(overrides)
    return base


class RecordingMatcher:
    def __init__(self):
        self.calls = []

    def match_cve(self, cve):
        self.calls.append(cve)
        return None


# --- fixture corpus integrity --------------------------------------------


def test_fixture_corpus_schema():
    with FIXTURE_PATH.open(encoding="utf-8") as fh:
        fixture = json.load(fh)
    assert set(fixture["meta"]) == {"name", "generated", "provenance"}
    assert fixture["meta"]["provenance"]
    rows = fixture["rows"]
    assert len(rows) == 16
    assert [r["alert_id"] for r in rows] == [
        "LAY-%d" % n for n in range(2601, 2615)
    ] + ["LAY; rm -rf /", "LAY-2616"]
    base_keys = {"ts", "alert_id", "severity", "model",
                 "outcome", "duration_ms", "detail"}
    for row in rows:
        assert base_keys <= set(row), row["alert_id"]
    kindless = [r["alert_id"] for r in rows if "kind" not in r]
    assert kindless == ["LAY-2613"]  # the deliberate kindless variant


def test_default_engine_matches_pinned_log4shell_eternalblue():
    v = LayaVerifier()
    result1 = v.check_decision(row_by_id("LAY-2601"))
    result2 = v.check_decision(row_by_id("LAY-2602"))
    assert result1["independent"]["known_cves"] == [{
        "cve": "CVE-2021-44228", "exploit_name": "Log4Shell",
        "metasploit_module":
            "exploit/multi/http/log4shell_header_injection",
        "port": None, "rank": 5}]
    assert result2["independent"]["known_cves"] == [{
        "cve": "CVE-2017-0144", "exploit_name": "EternalBlue",
        "metasploit_module":
            "exploit/windows/smb/ms17_010_eternalblue",
        "port": 445, "rank": 5}]


def test_known_cargo_steps_exact():
    result = LayaVerifier().check_decision(row_by_id("LAY-2601"))
    assert result["verification_steps"] == [
        "searchsploit Log4Shell",
        "verify CVE-2021-44228 against the flagged asset's patch level "
        "(laya escalated; kali double-check)"]
    assert result["independent"]["unknown_cves"] == []


def test_unknown_cargo_manual_triage_step():
    result = LayaVerifier().check_decision(row_by_id("LAY-2611"))
    assert result["verdict"]["status"] == VERDICT_AGREE
    assert result["independent"]["known_cves"] == []
    assert result["independent"]["unknown_cves"] == ["CVE-2026-4499"]
    assert result["verification_steps"] == [
        "manual triage: CVE-2026-4499 absent from the internal DB (file "
        "into the KA-029 expansion queue)"]


def test_no_cargo_escalated_step_exact():
    result = LayaVerifier().check_decision(row_by_id("LAY-2603"))
    assert result["verdict"]["status"] == VERDICT_AGREE
    assert result["verification_steps"] == [
        "manual re-review of LAY-2603: escalated with no CVE cargo in "
        "the audit detail"]


def test_duplicate_cargo_deduped_and_matched_once():
    row = row_by_id("LAY-2616")
    matcher = RecordingMatcher()  # returns None: unknown-cargo route
    result = LayaVerifier(matcher=matcher).check_decision(row)
    # the duplicated cve inside one detail fires the matcher ONCE and
    # lands in the unknown list once
    assert result["independent"]["cves"] == ["CVE-2017-0144"]
    assert result["independent"]["unknown_cves"] == ["CVE-2017-0144"]
    assert result["independent"]["known_cves"] == []
    assert result["verdict"]["status"] == VERDICT_AGREE
    assert matcher.calls == ["CVE-2017-0144"]  # once per unique cve


# --- the independent severity bands ---------------------------------------


@pytest.mark.parametrize("sev,expected", [
    (0, "low"), (1, "low"), (3, "low"), (4, "medium"),
    (6, "medium"), (7, "high"), (9, "high"), (10, "critical"),
])
def test_severity_band_boundaries(sev, expected):
    assert severity_band(sev) == expected


def test_severity_band_rejects_non_int_garbage():
    for garbage in ("twelve", 12.0, 12.5, True, False, None, -1):
        with pytest.raises(ValueError):
            severity_band(garbage)


# --- the corpus verdict matrix (every row routed exactly) -----------------


def _expected_status(alert_id):
    matrix = {
        "LAY-2601": VERDICT_AGREE, "LAY-2602": VERDICT_AGREE,
        "LAY-2603": VERDICT_AGREE, "LAY-2604": VERDICT_DISAGREE,
        "LAY-2605": VERDICT_REVIEW_ESCALATION,
        "LAY-2606": VERDICT_NOT_ESCALATED,
        "LAY-2607": VERDICT_DISAGREE, "LAY-2608": "unverifiable",
        "LAY-2609": VERDICT_REVIEW_OUTCOME, "LAY-2610": "unverifiable",
        "LAY-2611": VERDICT_AGREE, "LAY-2612": VERDICT_NOT_ESCALATED,
        "LAY-2613": VERDICT_NOT_ESCALATED, "LAY-2614": "unverifiable",
        "LAY-2615": "unverifiable", "LAY-2616": VERDICT_AGREE,
    }
    return matrix[alert_id]


@pytest.mark.parametrize("alert_id", ["LAY-%d" % n
                                      for n in range(2601, 2617)])
def test_corpus_verdict_matrix(alert_id):
    v = LayaVerifier()
    index = int(alert_id.split("-")[1]) - 2601
    row = corpus_rows()[index]  # by position: the hostile-id row has no
    # usable id to navigate by
    result = v.check_decision(row)
    expected = _expected_status(alert_id)
    if expected == "unverifiable":
        assert "verdict" not in result
        assert set(result) == {"alert_id", "reasons"}
    else:
        assert result["verdict"]["status"] == expected


# --- the guard edges: over- and under-escalation ---------------------------


def test_over_escalation_reasons_and_steps_exact():
    result = LayaVerifier().check_decision(row_by_id("LAY-2604"))
    assert result["verdict"]["reasons"] == [REASON_OVER_ESCALATION]
    assert result["independent"]["band"] == "low"
    assert result["independent"]["escalation_warranted"] is False
    assert result["verification_steps"] == [
        "manual re-review of LAY-2604: escalated with no CVE cargo in "
        "the audit detail",
        "escalation review: confirm or demote LAY-2604 (laya severity "
        "3 = band low, below the independent escalation threshold)"]


def test_under_escalation_reasons_and_steps_exact():
    result = LayaVerifier().check_decision(row_by_id("LAY-2605"))
    assert result["verdict"]["reasons"] == [REASON_UNDER_ESCALATION]
    assert result["independent"]["band"] == "high"
    assert result["independent"]["escalation_warranted"] is True
    assert result["verification_steps"] == [
        "missed-escalation review: LAY-2605 left at severity 9 (band "
        "high, at or above the escalation threshold)"]
    assert LayaVerifier().check_decision(
        row_by_id("LAY-2605"))["escalated"] is False


def test_gate_false_on_escalated_row_forces_disagree():
    result = LayaVerifier().check_decision(row_by_id("LAY-2607"))
    assert result["verdict"]["status"] == VERDICT_DISAGREE
    # band warranted (critical) but the gate marker contradicts the
    # escalation's provenance: both reasons, band first
    assert result["verdict"]["reasons"] == [
        REASON_BAND_AGREES, REASON_GATE_FALSE]
    assert result["verification_steps"][0] == (
        "provenance check: gate engaged marker false on LAY-2607 - "
        "confirm the laya gate engaged (SOC-side healthcheck row)")
    assert "gate engaged marker false on a decision row" in result["notes"]


def test_calm_path_semantics_exact():
    # consistent no-escalation, gate-marker note, unrecognized outcome -
    # three calm rows, exact shapes
    consistent = LayaVerifier().check_decision(row_by_id("LAY-2606"))
    assert consistent["verdict"]["status"] == VERDICT_NOT_ESCALATED
    assert consistent["verdict"]["reasons"] == [REASON_CONSISTENT]
    assert consistent["verification_steps"] == []
    gate_note = LayaVerifier().check_decision(row_by_id("LAY-2612"))
    assert gate_note["verdict"]["status"] == VERDICT_NOT_ESCALATED
    assert gate_note["notes"] == [
        "gate engaged marker false on a decision row"]
    unrecognized = LayaVerifier().check_decision(row_by_id("LAY-2609"))
    assert unrecognized["verdict"]["status"] == VERDICT_REVIEW_OUTCOME
    assert unrecognized["verdict"]["reasons"] == [REASON_UNKNOWN_OUTCOME]
    assert unrecognized["verification_steps"] == []
    assert unrecognized["notes"] == [
        "outcome unrecognized; no signal asserted"]


def test_kind_absent_row_presumed_with_note():
    result = LayaVerifier().check_decision(row_by_id("LAY-2613"))
    assert result["verdict"]["status"] == VERDICT_NOT_ESCALATED
    assert result["notes"] == ["kind absent; presumed laya_gated_decision"]


def test_explicit_escalated_flag_wins_over_unknown_outcome():
    # outcome unrecognized but the explicit boolean flag asserts the
    # escalation: the escalated path runs (no conflict, no guessing)
    v = LayaVerifier()
    row = make_row(alert_id="LAY-2701", severity=8, outcome="deferred",
                   detail="explicit flag says escalate", escalated=True)
    result = v.check_decision(row)
    assert result["verdict"]["status"] == VERDICT_AGREE
    assert result["escalated"] is True
    assert result["laya_call"]["outcome"] == "deferred"
    assert result["independent"]["escalation_warranted"] is True
    assert "outcome unrecognized; no signal asserted" not in \
        result["notes"]


def test_escalation_signal_conflict_routes_unverifiable():
    v = LayaVerifier()
    # escalation outcome + explicit falsy flag
    conflict1 = make_row(alert_id="LAY-2702", severity=12,
                         outcome="escalate", escalated=False)
    # calm outcome + explicit truthy flag
    conflict2 = make_row(alert_id="LAY-2703", severity=2,
                         outcome="suppressed", escalated=True)
    for row in (conflict1, conflict2):
        result = v.check_decision(row)
        assert result == {"alert_id": row["alert_id"],
                          "reasons": ["escalation signals conflict"]}


# --- intake shape tolerance (deliberate misses never crash) ---------------


def _intake_case_params():
    return [
        ("not-a-mapping", 42),
        ("wrong-kind", make_row(alert_id="LAY-2691", kind="nmap_scan")),
        ("id-blank", make_row(alert_id="", severity=5)),
        ("severity-string", make_row(severity="twelve", outcome="ok")),
        ("severity-negative", make_row(severity=-2, outcome="ok")),
        ("outcome-blank", make_row(outcome="")),
        ("escalated-nonbool", make_row(escalated="yes")),
    ]


@pytest.mark.parametrize("label,bad_row", _intake_case_params(),
                         ids=[c[0] for c in _intake_case_params()])
def test_intake_tolerance_unverifiable(label, bad_row):
    v = LayaVerifier()
    result = v.check_decision(bad_row)
    assert "verdict" not in result
    assert result["reasons"], label


def test_intake_non_mapping_marker():
    result = LayaVerifier().check_decision(42)
    assert result == {"alert_id": "<missing-id>",
                      "reasons": ["decision row is not a mapping"]}


def test_intake_wrong_kind_reason_text():
    result = LayaVerifier().check_decision(
        make_row(alert_id="LAY-2691", kind="nmap_scan"))
    assert result["alert_id"] == "LAY-2691"
    assert result["reasons"] == ["unexpected row kind: 'nmap_scan'"]


def test_ts_and_detail_garbage_tolerated():
    # non-string ts echoes "" and non-string detail reads as no cargo:
    # tolerated shapes, not intake rejections
    row = make_row(alert_id="LAY-2692", severity=2, ts=20261005,
                   detail=None)
    result = LayaVerifier().check_decision(row)
    assert result["ts"] == ""
    assert result["independent"]["cves"] == []
    assert result["verdict"]["status"] == VERDICT_NOT_ESCALATED


# --- gate semantics --------------------------------------------------------


def test_gate_engagement_fixture_exact():
    assert LayaVerifier().gate_engagement(corpus_rows()) == {
        "decision_rows": 15,  # every corpus row but the wrong-kind one
        "gate_markers_true": 0, "gate_markers_false": 2,
        "gate_presumed_by_kind": False, "gate_engaged": False}


def test_gate_engagement_no_rows():
    assert LayaVerifier().gate_engagement(None) == {
        "decision_rows": 0, "gate_markers_true": 0,
        "gate_markers_false": 0, "gate_presumed_by_kind": False,
        "gate_engaged": False}


def test_gate_engagement_all_markers_true():
    rows = [make_row(alert_id="LAY-2801", gate_engaged=True),
            make_row(alert_id="LAY-2802", gate_engaged=True)]
    assert LayaVerifier().gate_engagement(rows) == {
        "decision_rows": 2, "gate_markers_true": 2,
        "gate_markers_false": 0, "gate_presumed_by_kind": False,
        "gate_engaged": True}


def test_gate_engagement_mixed_markers_not_engaged():
    rows = [make_row(alert_id="LAY-2803", gate_engaged=True),
            make_row(alert_id="LAY-2804", gate_engaged=False)]
    result = LayaVerifier().gate_engagement(rows)
    assert result["gate_markers_true"] == 1
    assert result["gate_markers_false"] == 1
    assert result["gate_engaged"] is False


def test_gate_engagement_presumed_by_kind():
    rows = [make_row(alert_id="LAY-2805"),
            make_row(alert_id="LAY-2806"),
            make_row(alert_id="LAY-2807")]
    assert LayaVerifier().gate_engagement(rows) == {
        "decision_rows": 3, "gate_markers_true": 0,
        "gate_markers_false": 0, "gate_presumed_by_kind": True,
        "gate_engaged": True}


def test_gate_markers_truthiness_and_non_decision_rows_ignored():
    rows = ["not-a-row", make_row(alert_id="LAY-2808", kind="nmap_scan"),
            make_row(alert_id="LAY-2809", gate_engaged="yes"),
            make_row(alert_id="LAY-2810", gate_engaged=0),
            12]
    result = LayaVerifier().gate_engagement(rows)
    # only the two kindless decision rows count; truthy "yes" is a
    # marker, falsy 0 is a marker
    assert result["decision_rows"] == 2
    assert result["gate_markers_true"] == 1
    assert result["gate_markers_false"] == 1
    assert result["gate_engaged"] is False


# --- verify_decisions: fan-out, summary, order, defaults -------------------


def test_verify_summary_exact_and_json_safe():
    result = LayaVerifier().verify_decisions(corpus_rows())
    assert result["summary"] == {
        "rows_in": 16, "escalated": 7, "plans": 7, "reviews": 2,
        "not_escalated": 3, "unverifiable": 4, "agreements": 5,
        "disagreements": 2, "agreement_rate": 5 / 7}
    assert json.dumps(result)  # the whole payload stays JSON-safe
    assert json.loads(json.dumps(result)) == result


def test_verify_bucket_ordering_is_input_order():
    result = LayaVerifier().verify_decisions(corpus_rows())
    assert [r["alert_id"] for r in result["plans"]] == [
        "LAY-2601", "LAY-2602", "LAY-2603", "LAY-2604", "LAY-2607",
        "LAY-2611", "LAY-2616"]
    assert [r["alert_id"] for r in result["reviews"]] == [
        "LAY-2605", "LAY-2609"]
    assert [r["alert_id"] for r in result["unverifiable"]] == [
        "LAY-2608", "LAY-2610", "LAY-2614", "<missing-id>"]


def test_verify_rows_none_default_and_kwargs_absorbed():
    v = LayaVerifier()
    empty = v.verify_decisions(None)
    assert empty == {
        "plans": [], "reviews": [], "unverifiable": [],
        "summary": {"rows_in": 0, "escalated": 0, "plans": 0,
                    "reviews": 0, "not_escalated": 0, "unverifiable": 0,
                    "agreements": 0, "disagreements": 0,
                    "agreement_rate": 0.0}}
    row = row_by_id("LAY-2607")
    assert v.check_decision(row, legacy=1, bogus=None) \
        == v.check_decision(row)


# --- matcher injection isolation -------------------------------------------


def test_recording_matcher_called_once_per_row_unique_cve():
    matcher = RecordingMatcher()
    LayaVerifier(matcher=matcher).verify_decisions(
        [row_by_id("LAY-2601"), row_by_id("LAY-2602"),
         row_by_id("LAY-2616")])
    # per-row independence: each row consults the matcher for its own
    # unique cargo; the duplicated cve inside LAY-2616 fires once
    assert matcher.calls == ["CVE-2021-44228", "CVE-2017-0144",
                             "CVE-2017-0144"]


def test_injected_stub_echo_is_attribute_tolerant():
    stub_match = SimpleNamespace(
        exploit_name="StubExploit", metasploit_module="exploit/stub",
        port=443, rank=5, reliability="excellent")

    class StubMatcher:
        def match_cve(self, cve):
            return stub_match

    row = make_row(alert_id="LAY-2901", severity=12, outcome="escalated",
                   detail="stub cargo CVE-2021-44228")
    result = LayaVerifier(matcher=StubMatcher()).check_decision(row)
    assert result["independent"]["known_cves"] == [{
        "cve": "CVE-2021-44228", "exploit_name": "StubExploit",
        "metasploit_module": "exploit/stub", "port": 443, "rank": 5}]
    assert "reliability" not in result["independent"]["known_cves"][0]


def test_matcher_failure_isolated_and_routed_unknown():
    class BoomMatcher:
        def match_cve(self, cve):
            raise RuntimeError("boom")

    row = make_row(alert_id="LAY-2902", severity=12, outcome="escalated",
                   detail="boom cargo CVE-2021-44228")
    result = LayaVerifier(matcher=BoomMatcher()).check_decision(row)
    assert result["verdict"]["status"] == VERDICT_AGREE  # band still holds
    assert result["independent"]["unknown_cves"] == ["CVE-2021-44228"]
    assert result["notes"] == [
        "matcher failed for CVE-2021-44228; treated as unknown"]
    assert result["verification_steps"] == [
        "manual triage: CVE-2021-44228 absent from the internal DB "
        "(file into the KA-029 expansion queue)"]


def test_none_returning_matcher_routes_manual_triage():
    row = make_row(alert_id="LAY-2903", severity=7, outcome="referred",
                   detail="none cargo CVE-2019-0708")
    result = LayaVerifier(matcher=RecordingMatcher()).check_decision(row)
    assert result["independent"]["known_cves"] == []
    assert result["independent"]["unknown_cves"] == ["CVE-2019-0708"]
    assert result["verdict"]["status"] == VERDICT_AGREE


# --- the scrub helpers -----------------------------------------------------


def test_scrub_decision_id_accepts():
    assert scrub_decision_id("  LAY-2601  ") == "LAY-2601"
    assert scrub_decision_id("a_b.c-d") == "a_b.c-d"
    assert scrub_decision_id("X" * 64) == "X" * 64
    assert LayaVerifier._scrub_id("LAY-2601") == "LAY-2601"  # the thin
    # staticmethod wrapper on the class stays wired to the helper
    with pytest.raises(ValueError):
        LayaVerifier._scrub_id("a b")


@pytest.mark.parametrize("garbage", ["", "   ", None, "a b", "a;b",
                                     "X" * 65])
def test_scrub_decision_id_rejects(garbage):
    with pytest.raises(ValueError):
        scrub_decision_id(garbage)


def test_scrub_detail_non_string_is_empty():
    assert scrub_detail(None) == ""
    assert scrub_detail(42) == ""
    assert scrub_detail(["x"]) == ""


def test_scrub_detail_control_characters_neutralized():
    raw = "cargo CVE-2021-44228\x00tail\n\tmore\x1b[0m"
    assert scrub_detail(raw) == "cargo CVE-2021-44228 tail more [0m"


def test_scrub_detail_length_capped():
    assert len(scrub_detail("x" * (MAX_DETAIL_CHARS + 88))) \
        == MAX_DETAIL_CHARS
    assert scrub_detail("x" * (MAX_DETAIL_CHARS + 88)) == "x" * 512


def test_scrub_detail_preserves_clean_text_and_unicode():
    assert scrub_detail("clean detail") == "clean detail"
    assert scrub_detail("sévérité élevée") == "sévérité élevée"


# --- module constants + docstring discipline -------------------------------


def test_module_constants_pinned():
    assert laya_verify.DECISION_KIND == "laya_gated_decision"
    assert ESCALATION_OUTCOMES == frozenset(
        ("escalate", "escalated", "referred"))
    assert CALM_OUTCOMES == frozenset(("ok", "suppressed", "dismissed"))
    assert ESCALATION_BANDS == frozenset(("critical", "high"))
    assert (laya_verify.SEVERITY_BAND_CRITICAL,
            laya_verify.SEVERITY_BAND_HIGH,
            laya_verify.SEVERITY_BAND_MEDIUM,
            laya_verify.SEVERITY_BAND_LOW) == (10, 7, 4, 1)
    assert (laya_verify.VERDICT_AGREE, laya_verify.VERDICT_DISAGREE,
            laya_verify.VERDICT_REVIEW_ESCALATION,
            laya_verify.VERDICT_REVIEW_OUTCOME,
            laya_verify.VERDICT_NOT_ESCALATED) == (
        "agree", "disagree", "review_escalation", "review_outcome",
        "not_escalated")
    assert (laya_verify.REASON_BAND_AGREES,
            laya_verify.REASON_OVER_ESCALATION,
            laya_verify.REASON_UNDER_ESCALATION,
            laya_verify.REASON_GATE_FALSE,
            laya_verify.REASON_UNKNOWN_OUTCOME,
            laya_verify.REASON_CONSISTENT) == (
        "severity_band_matches_escalation",
        "severity_band_below_escalation_threshold",
        "severity_band_at_or_above_escalation_threshold",
        "gate_evidence_marker_false",
        "outcome_unrecognized_no_signal_asserted",
        "consistent_no_escalation")
    assert MAX_DETAIL_CHARS == 512


def test_every_op_docstring_leads_with_cli_card_line():
    callables = (severity_band, scrub_decision_id, scrub_detail,
                 LayaVerifier.check_decision, LayaVerifier.verify_decisions,
                 LayaVerifier.gate_engagement, render_report)
    for op in callables:
        first = (op.__doc__ or "").strip().splitlines()[0]
        assert first, op.__name__


# --- the report ------------------------------------------------------------


def test_report_empty_result_renders_zeros():
    report = render_report(LayaVerifier().verify_decisions(None))
    assert report.startswith("# laya double-check report")
    assert "rows checked:   0" in report
    assert "agreement rate: 0.00" in report
    assert "(unverifiable rows: none;" in report


def test_report_fixture_substrings():
    report = render_report(LayaVerifier().verify_decisions(corpus_rows()))
    assert "rows checked:   16" in report
    assert "escalated rows: 7" in report
    assert "plans: 7   agreements: 5   disagreements: 2" in report
    assert "agreement rate: 0.71" in report
    assert "reviews filed: 2" in report
    assert ("| LAY-2604 | disagree | 3 | low | "
            "severity_band_below_escalation_threshold |") in report
    assert ("| LAY-2607 | disagree | 12 | critical | "
            "severity_band_matches_escalation; "
            "gate_evidence_marker_false |") in report
    assert "| LAY-2605 | review_escalation | 9 | high |" in report


# --- results carry through the fan-out verbatim ----------------------------


def test_check_decision_result_fields_exact_for_agree_row():
    result = LayaVerifier().check_decision(row_by_id("LAY-2601"))
    assert result == {
        "alert_id": "LAY-2601",
        "ts": "2026-10-05T09:00:01Z",
        "escalated": True,
        "laya_call": {"severity": 12, "outcome": "escalated",
                      "gate_engaged": None},
        "independent": {
            "cves": ["CVE-2021-44228"],
            "known_cves": [{
                "cve": "CVE-2021-44228", "exploit_name": "Log4Shell",
                "metasploit_module":
                    "exploit/multi/http/log4shell_header_injection",
                "port": None, "rank": 5}],
            "unknown_cves": [],
            "band": "critical",
            "escalation_warranted": True},
        "verdict": {
            "status": "agree",
            "reasons": ["severity_band_matches_escalation"]},
        "verification_steps": [
            "searchsploit Log4Shell",
            "verify CVE-2021-44228 against the flagged asset's patch "
            "level (laya escalated; kali double-check)"],
        "notes": []}


def test_check_decision_result_fields_exact_for_gate_contradiction():
    result = LayaVerifier().check_decision(row_by_id("LAY-2607"))
    assert result == {
        "alert_id": "LAY-2607",
        "ts": "2026-10-05T09:03:05Z",
        "escalated": True,
        "laya_call": {"severity": 12, "outcome": "escalated",
                      "gate_engaged": False},
        "independent": {
            "cves": [], "known_cves": [], "unknown_cves": [],
            "band": "critical", "escalation_warranted": True},
        "verdict": {
            "status": "disagree",
            "reasons": ["severity_band_matches_escalation",
                        "gate_evidence_marker_false"]},
        "verification_steps": [
            "provenance check: gate engaged marker false on LAY-2607 - "
            "confirm the laya gate engaged (SOC-side healthcheck row)",
            "manual re-review of LAY-2607: escalated with no CVE cargo "
            "in the audit detail"],
        "notes": ["gate engaged marker false on a decision row"]}


# --- planner purity --------------------------------------------------------


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.laya_verify")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "exec(", "popen",
                   "socket", "urllib", "requests", "http.client",
                   "utcnow", "time.time", "today()", "open("):
        assert banned not in source, banned
    # the lazy engine default is the single allowed agentic_ai
    # reference, and it must stay lazy (function-local)
    assert "import agentic_ai" not in source
    assert source.count("from agentic_ai") == 1
    assert "from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine" \
        in source


def test_no_mixin_chassis_surface():
    # a pure module: no Mixin class, no BaseAgent import surface
    module = importlib.import_module("agentic_ai.agents.cyber.laya_verify")
    assert not [n for n in dir(module) if n.endswith("Mixin")]
    assert module.LayaVerifier.__doc__ 