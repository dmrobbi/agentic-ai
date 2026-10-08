"""Laya double-check (KA-071): independent verification plans for laya's
escalated decisions.

laya is the SOC's gated decision engine: its decisions land in the SOC
audit log as rows - the laya_gated_decision shape pinned by
test_laya_replay.py (ts/kind/alert_id/severity/model/outcome/
duration_ms/detail), with the gate engagement proven SOC-side by the
thing1 healthcheck's "laya gate engaging" check. Per OPT-71, the kali
agent becomes the INDEPENDENT double-check layer over those decisions:

- every laya-escalated decision is re-derived INDEPENDENTLY from the
  row's own cargo - this module's own deterministic severity bands plus
  an injected CVE matcher - and given a verdict: agree, disagree, or a
  review route;
- non-escalated rows are still swept for MISSED escalations (the
  false-negative guard); escalated rows whose severity band the
  independent rules do not warrant are flagged over-escalations (the
  false-positive guard);
- an escalated row that carries an explicit gate_engaged=false marker
  is refused as a provenance contradiction: a decision the gate never
  engaged for cannot be trusted as an escalation.

UNRECOGNIZED outcomes never guess: absent an explicit boolean escalated
signal, a row with an outcome outside the pinned vocabulary routes to
review_outcome instead of being silently treated as calm or escalated.

PURE PLANNER: nothing here spawns a process, touches the network,
reads a file, or reads a wall clock; the live audit-log pull and the
healthcheck's live gate check stay SOC-side wiring. Rows come from
committed fixtures/the caller only. The matcher default imports LAZILY
(the bridge lesson: a module-level chassis import would cycle).

INDEPENDENT-BY-CONSTRUCTION: the band rules below are this module's
own; laya's internal severity engine left the SOC box only as recorded
rows, never as code. Agreement/disagreement is therefore the kali
agent's independent call on laya's recorded call.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

DECISION_KIND = "laya_gated_decision"

# The escalation vocabulary laya's rows are read with (synthetic-but-
# realistic per the corpus provenance: "escalated" rows carry one of
# these outcomes unless an explicit boolean escalated field says
# otherwise). Calm outcomes are the explicitly-decided-quiet vocabulary.
# Anything else is UNRECOGNIZED: the double-check never guesses.
ESCALATION_OUTCOMES = frozenset(("escalate", "escalated", "referred"))
CALM_OUTCOMES = frozenset(("ok", "suppressed", "dismissed"))

# The INDEPENDENT severity bands (lowest qualifying threshold first).
# Band = the first entry whose threshold the severity meets; severity
# below the lowest threshold is low. These are kali's own rules - the
# drift alarm if the house ever retunes the escalation frontier.
SEVERITY_BAND_CRITICAL = 10
SEVERITY_BAND_HIGH = 7
SEVERITY_BAND_MEDIUM = 4
SEVERITY_BAND_LOW = 1

BAND_CRITICAL = "critical"
BAND_HIGH = "high"
BAND_MEDIUM = "medium"
BAND_LOW = "low"

# Bands whose re-derived call WARRANTS escalation (the escalation
# frontier laya's calls are checked against).
ESCALATION_BANDS = frozenset((BAND_CRITICAL, BAND_HIGH))

# Verdict statuses (stable; tests pin them literally).
VERDICT_AGREE = "agree"
VERDICT_DISAGREE = "disagree"
VERDICT_REVIEW_ESCALATION = "review_escalation"
VERDICT_REVIEW_OUTCOME = "review_outcome"
VERDICT_NOT_ESCALATED = "not_escalated"

# Reason codes (stable; tests pin them literally).
REASON_BAND_AGREES = "severity_band_matches_escalation"
REASON_OVER_ESCALATION = "severity_band_below_escalation_threshold"
REASON_UNDER_ESCALATION = "severity_band_at_or_above_escalation_threshold"
REASON_GATE_FALSE = "gate_evidence_marker_false"
REASON_UNKNOWN_OUTCOME = "outcome_unrecognized_no_signal_asserted"
REASON_CONSISTENT = "consistent_no_escalation"

ID_RE = r"[A-Za-z0-9_.\-]{1,64}"
CVE_RE = r"CVE-\d{4}-\d+"
MAX_DETAIL_CHARS = 512
REPORT_TEMPLATE = """# laya double-check report

rows checked:   {rows_in}
escalated rows: {escalated}
plans: {plans}   agreements: {agreements}   disagreements: {disagreements}
agreement rate: {agreement_rate:.2f}
reviews filed: {reviews}

| alert_id | status | laya severity | independent band | reasons |
|---|---|---|---|---|
{table_rows}

(unverifiable rows: {unverifiable_lines}; the live gate check stays on
the thing1 healthcheck - laya's own reasoning is not consulted here)
"""


def severity_band(severity: Any) -> str:
    """severity_band(severity) -> str; map a laya severity int onto an
    independent band (critical/high/medium/low), ValueError on any
    non-int garbage."""
    if isinstance(severity, bool) or not isinstance(severity, int):
        raise ValueError("severity must be an int, got: %r" % (severity,))
    if severity < 0:
        raise ValueError(
            "severity must be non-negative, got: %r" % (severity,))
    if severity >= SEVERITY_BAND_CRITICAL:
        return BAND_CRITICAL
    if severity >= SEVERITY_BAND_HIGH:
        return BAND_HIGH
    if severity >= SEVERITY_BAND_MEDIUM:
        return BAND_MEDIUM
    return BAND_LOW


def scrub_decision_id(value: Any) -> str:
    """scrub_decision_id(value) -> str; validate a laya alert id against
    the charset pin and return it stripped, ValueError otherwise."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "alert id must be a non-empty string, got: %r" % (value,))
    scrubbed = value.strip()
    if not re.fullmatch(ID_RE, scrubbed):
        raise ValueError(
            "rejected alert id with disallowed characters: %r" % (value,))
    return scrubbed


def scrub_detail(value: Any) -> str:
    """scrub_detail(value) -> str; neutralize a laya detail line: control
    characters out, whitespace runs collapsed, length capped."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(
        " " if (ord(ch) < 32 or ord(ch) == 127) else ch for ch in value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:MAX_DETAIL_CHARS]


def _extract_cves(text: str) -> List[str]:
    """Distinct CVE ids from a detail blob, first-occurrence order."""
    found = re.findall(CVE_RE, text)
    seen, out = set(), []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _match_reference(cve: str, match: Any) -> Dict[str, Any]:
    """The laya-convention echo of one matcher hit (attribute-tolerant:
    the duck-typed engine's fields are read defensively)."""
    return {
        "cve": cve,
        "exploit_name": getattr(match, "exploit_name", None),
        "metasploit_module": getattr(match, "metasploit_module", None),
        "port": getattr(match, "port", None),
        "rank": getattr(match, "rank", None),
    }


def _unverifiable(row: Any, reasons: List[str]) -> Dict[str, Any]:
    """Best-effort unverifiable entry: the scrubbed id when one can be
    recovered, "<missing-id>" otherwise."""
    raw = row.get("alert_id") if isinstance(row, dict) else None
    try:
        marker = scrub_decision_id(raw)
    except ValueError:
        marker = "<missing-id>"
    return {"alert_id": marker, "reasons": reasons}


class LayaVerifier:
    """Independent double-check for laya decision rows (planners only):
    no execution, no clock, no network; rows are consumed as given."""

    _scrub_id = staticmethod(scrub_decision_id)

    def __init__(self, matcher=None):
        if matcher is not None:
            self.matcher = matcher
        else:
            # lazy default: a module-level import would make a chassis
            # import cycle (the bridge lesson, applied)
            from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine
            self.matcher = CVEMatchingEngine()

    # -- intake ------------------------------------------------------------

    def _intake(self, row: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Normalize one row contract; (normalized, []) on success or
        (None, reasons) on a deliberate schema miss - never a raise."""
        if not isinstance(row, dict):
            return None, ["decision row is not a mapping"]
        reasons: List[str] = []

        kind = row.get("kind")
        if kind is not None and kind != DECISION_KIND:
            reasons.append("unexpected row kind: %r" % (kind,))

        try:
            alert_id = scrub_decision_id(row.get("alert_id"))
        except ValueError as exc:
            reasons.append(str(exc))

        severity = row.get("severity")
        if isinstance(severity, bool) or not isinstance(severity, int) \
                or severity < 0:
            reasons.append("severity not a non-negative int: %r" % (severity,))

        outcome = row.get("outcome")
        if not isinstance(outcome, str) or not outcome.strip():
            reasons.append("outcome not a non-blank string: %r" % (outcome,))

        escalated_flag = row.get("escalated")
        if escalated_flag is not None and not isinstance(escalated_flag, bool):
            reasons.append("escalated flag not a boolean: %r"
                           % (escalated_flag,))
        else:
            outcome_norm = (
                outcome.strip().casefold() if isinstance(outcome, str)
                else "")
            if escalated_flag is False and outcome_norm in ESCALATION_OUTCOMES:
                reasons.append("escalation signals conflict")
            if escalated_flag is True and outcome_norm in CALM_OUTCOMES:
                reasons.append("escalation signals conflict")

        if reasons:
            return None, reasons

        outcome_norm = outcome.strip().casefold()
        if escalated_flag is not None:
            escalated = escalated_flag
        else:
            escalated = outcome_norm in ESCALATION_OUTCOMES
        if "gate_engaged" in row:
            gate = True if row["gate_engaged"] else False
        else:
            gate = None
        return {
            "alert_id": alert_id,
            "ts": row.get("ts") if isinstance(row.get("ts"), str) else "",
            "severity": severity,
            "outcome": outcome_norm,
            "detail": scrub_detail(row.get("detail")),
            "escalated": escalated,
            "gate_engaged": gate,
        }, []

    def _derivation(
        self, normalized: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Independent re-derivation over one normalized row: band,
        cargo, matcher split. Returns (derivation, notes)."""
        notes: List[str] = []
        cves = _extract_cves(normalized["detail"])
        known: List[Dict[str, Any]] = []
        unknown: List[str] = []
        for cve in cves:
            try:
                match = self.matcher.match_cve(cve)
            except Exception:
                notes.append("matcher failed for %s; treated as unknown"
                             % cve)
                match = None
            if match is not None:
                known.append(_match_reference(cve, match))
            else:
                unknown.append(cve)
        band = severity_band(normalized["severity"])
        return {
            "cves": cves,
            "known_cves": known,
            "unknown_cves": unknown,
            "band": band,
            "escalation_warranted": band in ESCALATION_BANDS,
        }, notes

    # -- the double-check op -------------------------------------------------

    def check_decision(self, row: Any, **_kwargs) -> Dict[str, Any]:
        """check_decision(row): one laya decision row in -> the
        independent double-check dict out (verdict, plan, notes); never
        raises. Unknown kwargs from legacy callers are absorbed."""
        del _kwargs
        normalized, reasons = self._intake(row)
        if normalized is None:
            return _unverifiable(row, reasons)

        derivation, notes = self._derivation(normalized)
        gate = normalized["gate_engaged"]
        steps: List[str] = []

        if normalized["escalated"]:
            verdict_reasons: List[str] = []
            if derivation["escalation_warranted"]:
                verdict_reasons.append(REASON_BAND_AGREES)
                status = VERDICT_AGREE
            else:
                verdict_reasons.append(REASON_OVER_ESCALATION)
                status = VERDICT_DISAGREE
            if gate is False:
                status = VERDICT_DISAGREE
                verdict_reasons.append(REASON_GATE_FALSE)
                steps.append(
                    "provenance check: gate engaged marker false on %s - "
                    "confirm the laya gate engaged (SOC-side healthcheck row)"
                    % normalized["alert_id"])
            for ref in derivation["known_cves"]:
                steps.append("searchsploit %s" % ref["exploit_name"])
                steps.append(
                    "verify %s against the flagged asset's patch level "
                    "(laya escalated; kali double-check)" % ref["cve"])
            for cve in derivation["unknown_cves"]:
                steps.append(
                    "manual triage: %s absent from the internal DB (file "
                    "into the KA-029 expansion queue)" % cve)
            if not derivation["cves"]:
                steps.append(
                    "manual re-review of %s: escalated with no CVE cargo "
                    "in the audit detail" % normalized["alert_id"])
            if status == VERDICT_DISAGREE \
                    and REASON_OVER_ESCALATION in verdict_reasons:
                steps.append(
                    "escalation review: confirm or demote %s (laya "
                    "severity %d = band %s, below the independent "
                    "escalation threshold)"
                    % (normalized["alert_id"], normalized["severity"],
                       derivation["band"]))
        else:
            verdict_reasons = []
            if derivation["escalation_warranted"]:
                status = VERDICT_REVIEW_ESCALATION
                verdict_reasons.append(REASON_UNDER_ESCALATION)
                steps.append(
                    "missed-escalation review: %s left at severity %d "
                    "(band %s, at or above the escalation threshold)"
                    % (normalized["alert_id"], normalized["severity"],
                       derivation["band"]))
            elif normalized["outcome"] not in ESCALATION_OUTCOMES \
                    and normalized["outcome"] not in CALM_OUTCOMES:
                status = VERDICT_REVIEW_OUTCOME
                verdict_reasons.append(REASON_UNKNOWN_OUTCOME)
                notes.append("outcome unrecognized; no signal asserted")
            else:
                status = VERDICT_NOT_ESCALATED
                verdict_reasons.append(REASON_CONSISTENT)

        if gate is False:
            notes.append("gate engaged marker false on a decision row")
        if row.get("kind") is None:
            notes.append("kind absent; presumed laya_gated_decision")

        return {
            "alert_id": normalized["alert_id"],
            "ts": normalized["ts"],
            "escalated": normalized["escalated"],
            "laya_call": {
                "severity": normalized["severity"],
                "outcome": normalized["outcome"],
                "gate_engaged": gate,
            },
            "independent": derivation,
            "verdict": {"status": status, "reasons": verdict_reasons},
            "verification_steps": steps,
            "notes": notes,
        }

    # -- the batch fan-out ------------------------------------------------------

    def verify_decisions(
        self, rows: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """verify_decisions(rows): a laya decision batch in -> the
        double-check fan-out out (plans/reviews/unverifiable/summary);
        bad rows land in the unverifiable bucket, never a crash."""
        plans: List[Dict[str, Any]] = []
        reviews: List[Dict[str, Any]] = []
        unverifiable: List[Dict[str, Any]] = []
        batch = list(rows) if rows else []
        not_escalated = 0
        agreements = 0
        disagreements = 0
        escalated_rows = 0
        for row in batch:
            result = self.check_decision(row)
            if "verdict" not in result:
                unverifiable.append(result)
                continue
            status = result["verdict"]["status"]
            if status in (VERDICT_AGREE, VERDICT_DISAGREE):
                plans.append(result)
                escalated_rows += 1
                if status == VERDICT_AGREE:
                    agreements += 1
                else:
                    disagreements += 1
            elif status == VERDICT_NOT_ESCALATED:
                not_escalated += 1
            else:
                reviews.append(result)
                # a review_escalation row is kali PROPOSING escalation;
                # it is not part of laya's recorded escalated count
        denominator = agreements + disagreements
        rate = agreements / denominator if denominator else 0.0
        return {
            "plans": plans,
            "reviews": reviews,
            "unverifiable": unverifiable,
            "summary": {
                "rows_in": len(batch),
                "escalated": escalated_rows,
                "plans": len(plans),
                "reviews": len(reviews),
                "not_escalated": not_escalated,
                "unverifiable": len(unverifiable),
                "agreements": agreements,
                "disagreements": disagreements,
                "agreement_rate": rate,
            },
        }

    # -- gate evidence (planner-side analog of the healthcheck row) ----------

    def gate_engagement(
        self, rows: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """gate_engagement(rows): a decision batch in -> the planner-side
        gate-evidence dict out (does the batch show the gate engaging?)."""
        batch = list(rows) if rows else []
        decision_rows = [
            row for row in batch
            if isinstance(row, dict)
            and (row.get("kind") is None
                 or row.get("kind") == DECISION_KIND)]
        markers_true = 0
        markers_false = 0
        for row in decision_rows:
            if "gate_engaged" in row:
                if row["gate_engaged"]:
                    markers_true += 1
                else:
                    markers_false += 1
        if not decision_rows:
            engaged = False
            presumed = False
        elif markers_true or markers_false:
            engaged = markers_true > 0 and markers_false == 0
            presumed = False
        else:
            engaged = True
            presumed = True
        return {
            "decision_rows": len(decision_rows),
            "gate_markers_true": markers_true,
            "gate_markers_false": markers_false,
            "gate_presumed_by_kind": presumed,
            "gate_engaged": engaged,
        }


def render_report(result: Dict[str, Any]) -> str:
    """render_report(result): a verify_decisions result in -> the
    markdown double-check report out."""
    summary = result.get("summary", {})
    table_rows: List[str] = []
    for entry in list(result.get("plans", [])) + list(result.get("reviews", [])):
        verdict = entry.get("verdict", {})
        laya_call = entry.get("laya_call", {})
        independent = entry.get("independent", {})
        laya_severity = laya_call.get("severity")
        table_rows.append("| %s | %s | %s | %s | %s |" % (
            entry.get("alert_id", "<missing-id>"),
            verdict.get("status", ""),
            laya_severity if laya_severity is not None else "",
            independent.get("band", ""),
            "; ".join(verdict.get("reasons", []))))
    unverifiable = list(result.get("unverifiable", []))
    unverifiable_lines = "; ".join(
        "%s (%s)" % (entry.get("alert_id", "<missing-id>"),
                     ", ".join(entry.get("reasons", [])))
        for entry in unverifiable) or "none"
    return REPORT_TEMPLATE.format(
        rows_in=summary.get("rows_in", 0),
        escalated=summary.get("escalated", 0),
        plans=summary.get("plans", 0),
        agreements=summary.get("agreements", 0),
        disagreements=summary.get("disagreements", 0),
        agreement_rate=summary.get("agreement_rate", 0.0),
        reviews=summary.get("reviews", 0),
        table_rows="\n".join(table_rows),
        unverifiable_lines=unverifiable_lines,
    )
