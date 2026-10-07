"""KA-089 tests - severity calibration: the CVSS band table at every
boundary, score/report input guards, the agreed/over/under/missing
verdicts against the real lazily-imported laya rule surface and an
injected one, the re-authored fallback (import failure, missing/
raising/garbage rule surfaces), the fallback-vs-live-module drift
alarm, summary counts, row JSON round-trips, and the planner-purity
source scan. laya_verify is READ-ONLY here; no network, no exec, no
file I/O - by design."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import laya_verify as laya_verify_module
from agentic_ai.agents.cyber.severity_calibration import (
    BAND_CRITICAL,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    BAND_NONE,
    CVSS_BANDS,
    LAYA_MODULE_NAME,
    LAYA_SOURCE_FALLBACK,
    LAYA_SOURCE_MODULE,
    MISSING_REF,
    REASON_AGREE,
    REASON_CVSS_SPLIT,
    REASON_NOT_MAPPING,
    REASON_OVER,
    REASON_REPORTED,
    REASON_SCORE,
    REASON_UNDER,
    REPORTABLE_SEVERITIES,
    VERDICTS,
    VERDICT_AGREE,
    VERDICT_MISSING_INPUTS,
    VERDICT_OVER,
    VERDICT_UNDER,
    calibrate_findings,
    cvss_band,
    laya_rule_band,
    laya_rule_source,
)


class StubLaya:
    """A rule surface standing in for the laya module."""

    def __init__(self, answer):
        self.answer = answer

    def severity_band(self, severity):
        return self.answer


class RaisingLaya:
    """A rule surface whose severity_band blows up."""

    def severity_band(self, severity):
        raise RuntimeError("laya rule surface unavailable (injected)")


def finding(**overrides):
    """A canonical finding row (provenance: an engagement bundle)."""
    row = {"id": "F-01", "severity": "high", "cvss": 7.4}
    row.update(overrides)
    return row


def single(**overrides):
    """calibrate_findings over one canonical finding -> its row."""
    return calibrate_findings([finding(**overrides)])["rows"][0]


# --- the CVSS band table + boundary exactness -----------------------------


def test_cvss_band_table_constants():
    assert CVSS_BANDS == (
        (0.0, BAND_NONE),
        (0.1, BAND_LOW),
        (4.0, BAND_MEDIUM),
        (7.0, BAND_HIGH),
        (9.0, BAND_CRITICAL),
    )


def test_cvss_band_boundaries_are_exact():
    # every published boundary of the band table, probed directly
    boundaries = (
        (0.0, BAND_NONE),
        (0.1, BAND_LOW),
        (3.9, BAND_LOW),
        (4.0, BAND_MEDIUM),
        (6.9, BAND_MEDIUM),
        (7.0, BAND_HIGH),
        (8.9, BAND_HIGH),
        (9.0, BAND_CRITICAL),
        (10.0, BAND_CRITICAL),
    )
    for score, band in boundaries:
        assert cvss_band(score) == band, (score, band)


@pytest.mark.parametrize("bad", [-0.1, 10.1, "9.8", True])
def test_cvss_band_rejects_garbage_scores(bad):
    with pytest.raises(ValueError, match="score must be a number"):
        cvss_band(bad)


# --- the reported-severity intake -----------------------------------------


@pytest.mark.parametrize("bad", ["banana", None])
def test_reported_garbage_routes_to_missing(bad):
    row = single(severity=bad)
    assert row["reported_severity"] is None
    assert row["verdict"] == VERDICT_MISSING_INPUTS
    assert row["reason"] == REASON_REPORTED % (bad,)
    # the usable score side of the row still answers as evidence
    assert row["cvss"] == {"score": 7.4, "band": "high"}
    assert row["rule"] == BAND_HIGH


@pytest.mark.parametrize("bad", [None, "9.8", float("nan")])
def test_score_garbage_routes_to_missing(bad):
    row = single(cvss=bad)
    assert row["cvss"] == {"score": None, "band": None}
    assert row["rule"] is None
    assert row["verdict"] == VERDICT_MISSING_INPUTS
    assert row["reason"] == REASON_SCORE % ("cvss", bad)


def test_missing_inputs_collect_both_misses_in_order():
    row = single(severity=None, cvss=None)
    assert row == {
        "finding_ref": "F-01",
        "reported_severity": None,
        "cvss": {"score": None, "band": None},
        "rule": None,
        "verdict": VERDICT_MISSING_INPUTS,
        "reason": (REASON_REPORTED % (None,) + "; "
                   + REASON_SCORE % ("cvss", None)),
    }


# --- the verdict rows -------------------------------------------------------


def test_agree_exact_row_shape():
    row = single()
    assert row == {
        "finding_ref": "F-01",
        "reported_severity": "high",
        "cvss": {"score": 7.4, "band": "high"},
        "rule": BAND_HIGH,  # laya on int(7.4) = 7 -> high
        "verdict": VERDICT_AGREE,
        "reason": REASON_AGREE,
    }


@pytest.mark.parametrize(
    "reported,score,expected_rule,verdict,reason",
    [(" HIGH ", 2.0, BAND_LOW, VERDICT_OVER, REASON_OVER),
     ("low", 7.5, BAND_HIGH, VERDICT_UNDER, REASON_UNDER)],
)
def test_over_and_under_verdicts(reported, score, expected_rule, verdict,
                                 reason):
    row = single(severity=reported, cvss=score)
    assert row["reported_severity"] == reported.strip().casefold()
    assert row["rule"] == expected_rule == row["cvss"]["band"]
    assert row["verdict"] == verdict
    assert row["reason"] == reason


def test_agreed_with_cvss_split_at_9_8():
    # the one band-vs-rule split inside the reportable range, on the
    # agreed side: laya's rules bless "high" at 9.8 (int 9), the CVSS
    # band is critical, the reason carries both
    row = single(severity="high", cvss=9.8)
    assert row["rule"] == BAND_HIGH
    assert row["cvss"] == {"score": 9.8, "band": BAND_CRITICAL}
    assert row["verdict"] == VERDICT_AGREE
    assert row["reason"] == (REASON_AGREE + "; "
                             + REASON_CVSS_SPLIT % ("critical", "high"))


def test_over_with_cvss_split_at_9_8():
    # reported critical MATCHES the cvss band yet over-calls the SOC's
    # rule - the over-call wins the verdict, the split stays visible
    row = single(severity="critical", cvss=9.8)
    assert row["rule"] == BAND_HIGH
    assert row["cvss"]["band"] == BAND_CRITICAL
    assert row["verdict"] == VERDICT_OVER
    assert row["reason"] == (REASON_OVER + "; "
                             + REASON_CVSS_SPLIT % ("critical", "high"))


def test_under_with_cvss_split_at_zero():
    row = single(severity="none", cvss=0.0)
    assert row["rule"] == BAND_LOW
    assert row["cvss"] == {"score": 0.0, "band": BAND_NONE}
    assert row["verdict"] == VERDICT_UNDER
    assert row["reason"] == (REASON_UNDER + "; "
                             + REASON_CVSS_SPLIT % ("none", "low"))


def test_clean_agree_at_full_score():
    # 10.0 is the one clean "critical" agreement (band == rule)
    row = single(severity="critical", cvss=10.0)
    assert row == {
        "finding_ref": "F-01",
        "reported_severity": "critical",
        "cvss": {"score": 10.0, "band": BAND_CRITICAL},
        "rule": BAND_CRITICAL,
        "verdict": VERDICT_AGREE,
        "reason": REASON_AGREE,
    }


# --- malformed findings never raise -----------------------------------------


def test_non_mapping_findings_tolerated():
    bundle = calibrate_findings(["nope", None, 42])
    expected = {
        "finding_ref": MISSING_REF,
        "reported_severity": None,
        "cvss": None,
        "rule": None,
        "verdict": VERDICT_MISSING_INPUTS,
        "reason": REASON_NOT_MAPPING,
    }
    assert bundle["rows"] == [expected, expected, expected]
    assert bundle["summary"] == {
        "findings": 3, "agreed": 0, "over": 0, "under": 0,
        "missing_inputs": 3, "rule_source": LAYA_SOURCE_MODULE}


def test_ref_label_marker_and_strip():
    # a label only: unusable ids never block the calibration itself
    bundle = calibrate_findings([
        {"severity": "high", "cvss": 7.4},   # no id key at all
        finding(id="   "),                    # blank id
        finding(id="  AF-77 "),               # padded id -> stripped
    ])
    refs = [row["finding_ref"] for row in bundle["rows"]]
    assert refs == [MISSING_REF, MISSING_REF, "AF-77"]
    assert all(row["verdict"] == VERDICT_AGREE for row in bundle["rows"])


# --- the cvss_key and batch contract ----------------------------------------


def test_custom_cvss_key():
    alt = {"id": "F-02", "severity": "medium", "score": 5.5}
    row = calibrate_findings([alt], cvss_key="score")["rows"][0]
    assert row["cvss"] == {"score": 5.5, "band": BAND_MEDIUM}
    assert row["rule"] == BAND_MEDIUM
    assert row["verdict"] == VERDICT_AGREE
    default = calibrate_findings([alt])["rows"][0]
    assert default["verdict"] == VERDICT_MISSING_INPUTS
    assert default["rule"] is None


def test_empty_findings_bundle():
    assert calibrate_findings([]) == {
        "rows": [],
        "summary": {"findings": 0, "agreed": 0, "over": 0, "under": 0,
                    "missing_inputs": 0,
                    "rule_source": LAYA_SOURCE_MODULE}}


def test_caller_errors_raise():
    for bad_findings in (None, 42, "rows", {"a": 1}):
        with pytest.raises(ValueError, match="findings must be a list"):
            calibrate_findings(bad_findings)
    for bad_key in (7, None, "", "   "):
        with pytest.raises(ValueError, match="cvss_key"):
            calibrate_findings([finding()], cvss_key=bad_key)


def test_summary_counts():
    bundle = calibrate_findings([
        finding(severity="medium", cvss=5.5),   # agreed
        finding(severity="high", cvss=2.0),     # over
        finding(severity="low", cvss=7.5),      # under
        finding(severity="banana", cvss=5.5),   # missing (reported)
        finding(),                              # F-01 again, agreed
        "nope",                                 # missing (not a mapping)
    ])
    assert bundle["summary"] == {
        "findings": 6, "agreed": 2, "over": 1, "under": 1,
        "missing_inputs": 2, "rule_source": LAYA_SOURCE_MODULE}


# --- the laya rule surface: injected, real, and the fallback ----------------


def test_injected_rule_surface_wins():
    bundle = calibrate_findings([finding(severity="high", cvss=7.5)],
                                laya=StubLaya("medium"))
    row = bundle["rows"][0]
    assert row["rule"] == BAND_MEDIUM        # the STUB's answer
    assert row["cvss"]["band"] == BAND_HIGH
    assert row["verdict"] == VERDICT_OVER
    assert row["reason"] == (REASON_OVER + "; "
                             + REASON_CVSS_SPLIT % ("high", "medium"))
    # the injected surface resolves as the module surface
    assert bundle["summary"]["rule_source"] == LAYA_SOURCE_MODULE


@pytest.mark.parametrize("behavior,stub",
                         [("garbage-answer", StubLaya("banana")),
                          ("raises", RaisingLaya()),
                          ("no-attr", object())])
def test_unusable_surface_routes_to_fallback(behavior, stub):
    bundle = calibrate_findings([finding(severity="low", cvss=3.1)],
                                laya=stub)
    row = bundle["rows"][0]
    assert row["rule"] == BAND_LOW        # the re-authored constants
    assert row["cvss"]["band"] == BAND_LOW
    assert row["verdict"] == VERDICT_AGREE
    assert bundle["summary"]["rule_source"] == LAYA_SOURCE_FALLBACK


def test_import_failure_routes_to_fallback(monkeypatch):
    real_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name == LAYA_MODULE_NAME:
            raise ImportError("laya offline (injected)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    bundle = calibrate_findings([finding(severity="medium", cvss=5.5)])
    row = bundle["rows"][0]
    assert row["rule"] == BAND_MEDIUM
    assert row["cvss"]["band"] == BAND_MEDIUM
    assert row["verdict"] == VERDICT_AGREE
    assert bundle["summary"]["rule_source"] == LAYA_SOURCE_FALLBACK


def test_real_laya_module_source_and_rule():
    # the lazy default import path: calibrate against the SOC's own
    # laya module, which is importable in this repo
    bundle = calibrate_findings([finding(severity="high", cvss=9.8)])
    assert bundle["summary"]["rule_source"] == LAYA_SOURCE_MODULE
    row = bundle["rows"][0]
    assert row["rule"] == laya_verify_module.severity_band(int(9.8))
    assert row["rule"] == BAND_HIGH  # 9.8 truncates to 9: laya says high


@pytest.mark.parametrize("score,laya_int",
                         [(5.5, 5), (9.8, 9), (10.0, 10)])
def test_fallback_tracks_the_live_laya_module(score, laya_int):
    # drift alarm: the re-authored constants must equal the live
    # module's export (the object() surface routes to the fallback)
    assert (laya_rule_band(score, laya=object())
            == laya_verify_module.severity_band(laya_int))


# --- output hygiene -----------------------------------------------------------


def test_rows_survive_json_roundtrip():
    bundle = calibrate_findings([
        finding(), finding(severity="banana", cvss=None), "nope"])
    clone = json.loads(json.dumps(bundle))
    assert clone == bundle


def test_verdict_and_constants_pin():
    assert VERDICTS == ("agreed", "over", "under", "missing_inputs")
    assert MISSING_REF == "<missing-id>"
    assert REPORTABLE_SEVERITIES == frozenset(
        ("none", "low", "medium", "high", "critical"))
    assert LAYA_MODULE_NAME == "agentic_ai.agents.cyber.laya_verify"
    assert laya_rule_source(StubLaya("low")) == LAYA_SOURCE_MODULE
    assert laya_rule_source(object()) == LAYA_SOURCE_FALLBACK


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.severity_calibration")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned