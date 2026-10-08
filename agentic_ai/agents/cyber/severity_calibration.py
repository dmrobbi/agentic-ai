"""Finding severity calibration (KA-089): an engagement's findings are
cross-checked against two independent severity references - the CVSS
qualitative score band and the SOC's deterministic severity rules,
laya's (KA-075/KA-071 landed them in laya_verify) - and each finding
gets a calibration row: reported_severity, the cvss score+band, the
laya-derived rule severity, and a verdict of agreed, over, under, or
missing_inputs. Malformed findings calibrate to missing_inputs with the
miss named in the reason; they never raise.

VERDICT SEMANTICS (the reported label against the laya rule):
  agreed          reported == the laya rule's severity;
  over            reported ranks ABOVE the laya rule's severity;
  under           reported ranks BELOW the laya rule's severity;
  missing_inputs  the reported label or the score is unusable (or the
                  finding is not a mapping) - no verdict is guessed.
The CVSS band is the second witness, not a second verdict: the row
carries score+band and the reason flags band-vs-rule split ranges
instead of flipping the verdict (score 0.0: cvss "none" vs laya "low";
scores 9.0-9.9: cvss "critical" vs laya "high" - laya's critical
threshold sits at its integer scale's 10). A 10.0 score is therefore
the one clean "critical" agreement; a reported critical on a 9.x score
over-calls the SOC's rule even when it matches the CVSS band.

LAYA RULE SURFACE: laya_verify is imported LAZILY inside the op and
strictly READ-ONLY (house anti-cycle rule - never a module-level
import); its exported severity_band is the rule of record, applied to
the score truncated toward zero (int(score); laya's scale is integer
severities from 0 with critical only at 10). When no rule surface is
usable - the import fails, the surface lacks severity_band, its
probe call (a severity-0 call) raises or answers garbage, or a row
answer falls outside the band vocabulary - the equivalent mapping
RE-AUTHORED from READING laya_verify answers instead (LAYA_RULE_BANDS:
low below 4, medium below 7, high below 10, critical at 10 under that
truncation); this docstring is the provenance note, and the drift-alarm
test cross-checks the constants against the live module's export. A
caller may inject a rule surface (laya=...) for tests.

PURPOSE: the SOC calls the severity once (laya's deterministic rules)
and CVSS scores the finding independently; a kali finding reported
above or below the rule is an over-call or an under-call worth routing
to review, and the split ranges are exactly where the two references
disagree - the reason text keeps both stories straight in one line.

PURE PLANNER: nothing here spawns a process, touches the network, reads
or writes a file, or reads a wall clock; findings come from the caller
only. The score is looked up under cvss_key (default "cvss") and echoed
as the validated float; the finding id is a LABEL (stripped verbatim,
<missing-id> when unavailable - never charset-enforced, never a lookup
key); unknown finding keys are absorbed silently.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, List, Optional

# --- the CVSS qualitative band table (the drift alarm; tests pin it) ----

BAND_NONE = "none"
BAND_LOW = "low"
BAND_MEDIUM = "medium"
BAND_HIGH = "high"
BAND_CRITICAL = "critical"

# Lowest qualifying threshold first; the LAST threshold the score meets
# names the band. Boundary exact: 0.0 none / low 0.1-3.9 / medium
# 4.0-6.9 / high 7.0-8.9 / critical 9.0-10.0.
CVSS_BANDS = (
    (0.0, BAND_NONE),
    (0.1, BAND_LOW),
    (4.0, BAND_MEDIUM),
    (7.0, BAND_HIGH),
    (9.0, BAND_CRITICAL),
)

CVSS_MIN = 0.0
CVSS_MAX = 10.0

# The reported-severity vocabulary (the CVSS vocabulary; "none" is
# reportable and ranks below "low" against the laya rules).
REPORTABLE_SEVERITIES = frozenset(
    (BAND_NONE, BAND_LOW, BAND_MEDIUM, BAND_HIGH, BAND_CRITICAL))
SEVERITY_RANK = {
    BAND_NONE: 0, BAND_LOW: 1, BAND_MEDIUM: 2, BAND_HIGH: 3,
    BAND_CRITICAL: 4,
}

# --- verdicts + reason templates (stable; tests pin them literally) -----

VERDICT_AGREE = "agreed"
VERDICT_OVER = "over"
VERDICT_UNDER = "under"
VERDICT_MISSING_INPUTS = "missing_inputs"
VERDICTS = (VERDICT_AGREE, VERDICT_OVER, VERDICT_UNDER,
            VERDICT_MISSING_INPUTS)

REASON_NOT_MAPPING = "calibration finding is not a mapping"
REASON_REPORTED = ("reported severity unusable: %r (wanted "
                   "none|low|medium|high|critical)")
REASON_SCORE = ("score under key %r unusable: %r (wanted a number in "
                "0.0-10.0)")
REASON_AGREE = "reported severity matches the laya rule"
REASON_OVER = "reported severity sits above the laya rule's severity"
REASON_UNDER = "reported severity sits below the laya rule's severity"
REASON_CVSS_SPLIT = "cvss band %s disagrees with the laya rule %s"

MISSING_REF = "<missing-id>"

# --- the laya rule surface (lazy, READ-ONLY; fallback re-authored) -------

LAYA_MODULE_NAME = "agentic_ai.agents.cyber.laya_verify"
LAYA_SOURCE_MODULE = "laya_module"
LAYA_SOURCE_FALLBACK = "laya_fallback"

# Re-authored from laya_verify.severity_band's thresholds (10/7/4, the
# lowest band "low"; provenance above): the score truncated toward zero
# through these integer frontier bands.
LAYA_RULE_BANDS = (
    (0, BAND_LOW),
    (4, BAND_MEDIUM),
    (7, BAND_HIGH),
    (10, BAND_CRITICAL),
)


def _score_ok(value: Any) -> bool:
    """The score-intake guard: bools are not scores; NaN/inf fail the
    range chain on their own; True is never a 1.0 score."""
    return (not isinstance(value, bool)
            and isinstance(value, (int, float))
            and 0.0 <= value <= 10.0)


def _require_score(score: Any) -> float:
    """A finite number in 0.0-10.0 -> float, ValueError otherwise."""
    if not _score_ok(score):
        raise ValueError(
            "score must be a number in 0.0-10.0, got: %r" % (score,))
    return float(score)


def cvss_band(score: Any) -> str:
    """cvss_band(score) -> str; the CVSS qualitative severity band of a
    0.0-10.0 score (CVSS_BANDS), ValueError on any non-number or
    out-of-range garbage."""
    value = _require_score(score)
    band = CVSS_BANDS[0][1]
    for threshold, label in CVSS_BANDS:
        if value >= threshold:
            band = label
    return band


def _laya_rule_band_fallback(score: Any) -> str:
    """The re-authored laya mapping (provenance in the module docstring):
    the score truncated toward zero through the LAYA_RULE_BANDS
    frontier; ValueError on a bad score."""
    value = _require_score(score)
    band = LAYA_RULE_BANDS[0][1]
    for threshold, label in LAYA_RULE_BANDS:
        if int(value) >= threshold:
            band = label
    return band


def _resolve_rule_fn(laya: Any) -> Optional[Any]:
    """The rule function for one calibration call: the surface's
    exported severity_band when callable AND probe-qualified (laya None
    -> the LAZY READ-ONLY laya_verify import), None otherwise - an
    import failure or an unusable surface never raises. The probe (a
    call at laya severity 0) must answer a band string inside the
    vocabulary: a surface that lacks severity_band, raises, or answers
    garbage does not qualify (the batch resolves to the fallback)."""
    if laya is None:
        try:
            laya = importlib.import_module(LAYA_MODULE_NAME)
        except Exception:
            return None
    fn = getattr(laya, "severity_band", None)
    if not callable(fn):
        return None
    try:
        probe = fn(0)
    except Exception:
        return None
    return fn if isinstance(probe, str) and probe in SEVERITY_RANK else None


def laya_rule_band(score: Any, laya: Any = None) -> str:
    """laya_rule_band(score, laya=None) -> str; the laya-derived expected
    severity band for one 0.0-10.0 score: laya's exported severity_band
    on the score truncated toward zero when the rule surface answers
    inside the band vocabulary, the re-authored constants otherwise;
    ValueError on a bad score."""
    value = _require_score(score)
    fn = _resolve_rule_fn(laya)
    if fn is not None:
        try:
            answer = fn(int(value))
        except Exception:
            answer = None
        if isinstance(answer, str) and answer in SEVERITY_RANK:
            return answer
    return _laya_rule_band_fallback(value)


def laya_rule_source(laya: Any = None) -> str:
    """laya_rule_source(laya=None) -> str; where the rule surface
    resolves for this call: 'laya_module' (an injected or lazily
    imported laya_verify with a callable severity_band) or
    'laya_fallback' (the re-authored constants)."""
    return (LAYA_SOURCE_MODULE
            if _resolve_rule_fn(laya) is not None
            else LAYA_SOURCE_FALLBACK)


def _severity_norm(value: Any) -> Optional[str]:
    """The reported severity normalized to lowercase, or None when
    non-conforming (case- and whitespace-tolerant)."""
    if isinstance(value, str) \
            and value.strip().casefold() in REPORTABLE_SEVERITIES:
        return value.strip().casefold()
    return None


def _ref_label(finding: Dict[str, Any]) -> str:
    """The finding's reference label: the stripped id when one exists,
    MISSING_REF otherwise (a label, never a lookup key)."""
    raw = finding.get("id")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return MISSING_REF


def _calibrate_one(finding: Any, cvss_key: str, laya: Any) -> Dict[str, Any]:
    """One finding in -> one calibration row out (the contract lives in
    calibrate_findings); malformed findings calibrate to missing_inputs
    and never raise."""
    if not isinstance(finding, dict):
        return {
            "finding_ref": MISSING_REF,
            "reported_severity": None,
            "cvss": None,
            "rule": None,
            "verdict": VERDICT_MISSING_INPUTS,
            "reason": REASON_NOT_MAPPING,
        }
    misses: List[str] = []
    raw_reported = finding.get("severity")
    reported = _severity_norm(raw_reported)
    if reported is None:
        misses.append(REASON_REPORTED % (raw_reported,))
    raw_score = finding.get(cvss_key)
    score = band = rule = None
    if _score_ok(raw_score):
        score = float(raw_score)
        band = cvss_band(score)
        rule = laya_rule_band(score, laya)
    else:
        misses.append(REASON_SCORE % (cvss_key, raw_score))
    if misses:
        verdict, reason = VERDICT_MISSING_INPUTS, "; ".join(misses)
    else:
        reported_rank = SEVERITY_RANK[reported]
        rule_rank = SEVERITY_RANK[rule]
        if reported_rank == rule_rank:
            verdict, base = VERDICT_AGREE, REASON_AGREE
        elif reported_rank > rule_rank:
            verdict, base = VERDICT_OVER, REASON_OVER
        else:
            verdict, base = VERDICT_UNDER, REASON_UNDER
        reason = base
        if band != rule:
            reason = base + "; " + REASON_CVSS_SPLIT % (band, rule)
    return {
        "finding_ref": _ref_label(finding),
        "reported_severity": reported,
        "cvss": {"score": score, "band": band},
        "rule": rule,
        "verdict": verdict,
        "reason": reason,
    }


def calibrate_findings(findings: Any, cvss_key: str = "cvss",
                       laya: Any = None) -> Dict[str, Any]:
    """calibrate_findings(findings, cvss_key="cvss", laya=None): an
    engagement's findings in -> the calibration bundle out ({"rows",
    "summary"}): one calibration row per finding - agreed/over/under
    against the laya rule, missing_inputs when a finding's inputs are
    unusable (every malformed finding lands there) - plus a verdict-count
    summary and the rule_source the laya surface resolved from. A
    non-list findings input or a blank cvss_key is a caller error
    (ValueError, tickets_bridge precedent)."""
    if not isinstance(findings, (list, tuple)):
        raise ValueError("findings must be a list, got: %r" % (findings,))
    if not isinstance(cvss_key, str) or not cvss_key.strip():
        raise ValueError(
            "cvss_key must be a non-blank string, got: %r" % (cvss_key,))
    rows = [_calibrate_one(row, cvss_key, laya) for row in findings]
    summary: Dict[str, Any] = {"findings": len(rows)}
    for verdict in VERDICTS:
        summary[verdict] = sum(
            1 for row in rows if row["verdict"] == verdict)
    summary["rule_source"] = laya_rule_source(laya)
    return {"rows": rows, "summary": summary}
