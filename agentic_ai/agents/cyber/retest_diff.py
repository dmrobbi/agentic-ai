"""Retest-diff op (KA-085): the findings-churn report between two
scanner runs on the same target - what resolved, what is new, what
regressed, and what stayed put.

A pure module in the aging_queue shape: two finding lists in (the
house finding shape - id, title, severity, status, plus host/target
hints), one deterministic churn report out. No chassis import, no
process spawning, no network facilities, no wall-clock reads: every
judgement comes from the two lists themselves.

THE FINDING SHAPE (both runs speak it; echoed keys only):
  id       - a run's explicit finding id, identity precedence one;
  title    - fallback identity ingredient, precedence two;
  severity - optional, echoed scrubbed;
  status   - one of open | fixed | not_present (accepted spellings of
             the third: not_present, not-present, not present,
             notpresent); blank or unknown statuses keep the finding
             matchable but warn it out of classification;
  host /   - target hints: the fingerprint target is the first
  target     non-blank of host, target.

IDENTITY AND MATCHING:
  - a finding's identity is its explicit id when the id scrubs to a
    non-blank string, else its fingerprint: the whitespace-collapsed
    lowercased title + "|" + the lowercased target hint;
  - a retest finding matches a baseline finding only on an equal
    identity of the same kind: explicit ids never cross-match
    fingerprints (when a retest starts labelling ids over previously
    unlabelled titles, the honest churn is resolved + new, not a
    guessed pairing);
  - ids match case-sensitively after scrubbing; fingerprints
    case-fold;
  - duplicate identities within one side keep the FIRST occurrence
    and warn about the rest.

CLASSIFICATION (a listed not_present entry is the retest calling a
finding gone; absence from the retest list says the same):
  baseline open        + retest fixed/not_present/absent -> resolved
  baseline fixed       + retest open                     -> regressed
  baseline fixed       + retest fixed/not_present/absent -> unchanged
  baseline not_present + retest open/fixed               -> new
  baseline not_present + retest not_present/absent       -> unchanged
  no baseline counterpart (retest open/fixed)            -> new
  retest not_present with no baseline counterpart        -> unchanged

DISCIPLINE:
  - anything the op can not use is WARNED and skipped, never raised:
    non-mapping rows, findings with no id and no title, blank or
    unknown statuses, duplicate identities; a run level that is not a
    list is warned and treated as empty;
  - matched_count counts every identity pair formed, including pairs
    one side of which can not classify (they are warned, never
    silently classified);
  - unchanged_count counts every no-churn classification: equal
    pairs, still-fixed absences, still-absent retest not_present rows;
  - order: returned lists sort id-identified entries before
    fingerprint-identified ones, each by its identity string, input
    position breaking remaining ties - fully deterministic, the same
    input renders the same report;
  - every returned list caps at DIFF_CAP; the counts carry the
    uncapped truth for the whole report, and a note names each cap
    that actually cut.

REPORT SHAPE (exact):
  resolved / new / regressed: churn entries
    {id, title, severity, target, baseline_status, retest_status,
    matched_by}; each entry echoes the retest finding when one exists
    (the retest is current truth) or the baseline finding for a
    resolved-by-absence entry; retest_status is None for absence,
    baseline_status is None for a new entry; matched_by is "id",
    "fingerprint", or "unmatched";
  unchanged_count, matched_count: the scalar truths;
  counts: {resolved, new, regressed, unchanged, matched, warnings} -
    the uncapped truth;
  warnings: {side, index, reason, id, title}; index is the position in
    the finding's own side's list (None on a run-level warning);
    baseline warnings precede retest warnings;
  notes: deterministic derivation notes, then one note per cap that
    actually cut.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

DIFF_CAP = 25
SCRUB_LIMIT = 128

STATUS_OPEN = "open"
STATUS_FIXED = "fixed"
STATUS_NOT_PRESENT = "not_present"
STATUSES = (STATUS_OPEN, STATUS_FIXED, STATUS_NOT_PRESENT)

RESOLVED = "resolved"
NEW = "new"
REGRESSED = "regressed"
UNCHANGED = "unchanged"

ENTRY_KEYS = ("id", "title", "severity", "target",
              "baseline_status", "retest_status", "matched_by")
WARNING_KEYS = ("side", "index", "reason", "id", "title")
COUNT_KEYS = ("resolved", "new", "regressed", "unchanged",
              "matched", "warnings")
OUTPUT_KEYS = ("resolved", "new", "regressed", "unchanged_count",
               "matched_count", "warnings", "counts", "notes")

# The pair-class table: (baseline status, retest status) -> churn
# class; a None retest side (absence) is classified by the op itself.
PAIR_CLASS = {
    (STATUS_OPEN, STATUS_OPEN): UNCHANGED,
    (STATUS_OPEN, STATUS_FIXED): RESOLVED,
    (STATUS_OPEN, STATUS_NOT_PRESENT): RESOLVED,
    (STATUS_FIXED, STATUS_OPEN): REGRESSED,
    (STATUS_FIXED, STATUS_FIXED): UNCHANGED,
    (STATUS_FIXED, STATUS_NOT_PRESENT): UNCHANGED,
    (STATUS_NOT_PRESENT, STATUS_NOT_PRESENT): UNCHANGED,
    (STATUS_NOT_PRESENT, STATUS_OPEN): NEW,
    (STATUS_NOT_PRESENT, STATUS_FIXED): NEW,
}

# The standing derivation notes (order and content pinned by tests).
NOTE_MATCHING = (
    "matching: explicit id first, then the fingerprint "
    "(whitespace-collapsed lowercased title + target); the two "
    "identity kinds never cross")
NOTE_CLASSIFICATION = (
    "classification: an open baseline finding is resolved when the "
    "retest marks it fixed, not present, or finds nothing there; a "
    "fixed baseline finding re-opened by the retest regresses; a "
    "retest finding with no baseline counterpart is new; equal states "
    "are unchanged")
NOTE_DISCIPLINE = (
    "data quality: unusable findings warn and are skipped - the op "
    "never raises on its inputs; duplicate identities keep the first "
    "occurrence")

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WS_RE = re.compile(r"\s+")


def _scrub_text(value: Any) -> str:
    """Module-level input scrub: control characters removed, whitespace
    runs collapsed to single spaces, outer whitespace stripped, length
    capped at SCRUB_LIMIT. Non-string input scrubs to "". Every
    external string entering the report passes through here."""
    if not isinstance(value, str):
        return ""
    text = _CTRL_RE.sub("", value)
    text = _WS_RE.sub(" ", text).strip()
    return text[:SCRUB_LIMIT]


def _norm_status(value: Any) -> Optional[str]:
    """One status's normalized class (open/fixed/not_present) or None
    when blank or outside the vocabulary; never raises."""
    text = _scrub_text(value).lower().replace(" ", "_").replace("-", "_")
    if text == "notpresent":
        text = STATUS_NOT_PRESENT
    if text in STATUSES:
        return text
    return None


def _target_hint(raw: Dict[str, Any]) -> str:
    """One finding's target hints collapse to one echo: the first
    non-blank scrubbed hint of host, target."""
    host = _scrub_text(raw.get("host"))
    if host:
        return host
    return _scrub_text(raw.get("target"))


def _fingerprint(title: str, target: str) -> str:
    """The fallback identity: case-folded title + "|" + case-folded
    target; the title is blank-guarded by the caller."""
    return title.lower() + "|" + target.lower()


def _warning(side: str, index: Optional[int], reason: str,
             fid: str = "", title: str = "") -> Dict[str, Any]:
    """One warning record; id/title are the best-effort scrubbed echoes
    ("" when the finding carries nothing usable)."""
    return {"side": side, "index": index, "reason": reason,
            "id": fid, "title": title}


def _parse_side(
    findings: Any,
    side: str,
    warnings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, int]]:
    """Parse one run's findings into identity entries plus the side's
    first-wins identity indexes. Findings that can not contribute warn
    and drop out; entries keep input order; never raises."""
    entries: List[Dict[str, Any]] = []
    id_index: Dict[str, int] = {}
    fp_index: Dict[str, int] = {}
    if not isinstance(findings, list):
        warnings.append(_warning(
            side, None,
            "not a list (got %s); treated as empty"
            % type(findings).__name__))
        return entries, id_index, fp_index
    for index, raw in enumerate(findings):
        if not isinstance(raw, dict):
            warnings.append(_warning(side, index, "not a mapping; skipped"))
            continue
        fid = _scrub_text(raw.get("id"))
        title = _scrub_text(raw.get("title"))
        if not fid and not title:
            warnings.append(_warning(
                side, index,
                "no id and no title: nothing to match on; skipped"))
            continue
        severity = _scrub_text(raw.get("severity"))
        target = _target_hint(raw)
        if fid:
            kind, value = "id", fid
        else:
            kind, value = "fingerprint", _fingerprint(title, target)
        taken = id_index if kind == "id" else fp_index
        if value in taken:
            warnings.append(_warning(
                side, index,
                "duplicate %s %r: the first occurrence (index %d) is kept"
                % (kind, value, taken[value]), fid, title))
            continue
        taken[value] = index
        status_raw = _scrub_text(raw.get("status"))
        status = _norm_status(status_raw)
        if status is None:
            if status_raw:
                warnings.append(_warning(
                    side, index,
                    "unknown status %r: expected open|fixed|not_present"
                    % (status_raw,), fid, title))
            else:
                warnings.append(_warning(
                    side, index,
                    "no status: finding can not be classified", fid, title))
        entries.append({
            "index": index, "kind": kind, "value": value,
            "status": status, "severity": severity, "target": target,
            "id": fid, "title": title,
        })
    return entries, id_index, fp_index


def _entry(parsed: Dict[str, Any],
           baseline_status: Optional[str],
           retest_status: Optional[str],
           matched_by: str) -> Dict[str, Any]:
    """One churn entry: the retest finding echoes when one exists (the
    retest is current truth), the baseline finding for a
    resolved-by-absence entry; _sort is internal, stripped at publish."""
    return {
        "id": parsed["id"],
        "title": parsed["title"],
        "severity": parsed["severity"],
        "target": parsed["target"],
        "baseline_status": baseline_status,
        "retest_status": retest_status,
        "matched_by": matched_by,
        "_sort": (0 if parsed["kind"] == "id" else 1,
                  parsed["value"], parsed["index"]),
    }


def diff_retests(baseline_findings: Any, retest_findings: Any) -> Dict[str, Any]:
    """The findings-churn report between two runs on the same target:
    resolved/new/regressed entries with scalar and count truths; never
    raises - unusable findings warn into the warnings bucket."""
    warnings: List[Dict[str, Any]] = []
    baseline_entries, _, _ = _parse_side(
        baseline_findings, "baseline", warnings)
    retest_entries, retest_by_id, retest_by_fp = _parse_side(
        retest_findings, "retest", warnings)

    counters = {RESOLVED: 0, NEW: 0, REGRESSED: 0, UNCHANGED: 0}
    buckets: Dict[str, List[Dict[str, Any]]] = {
        RESOLVED: [], NEW: [], REGRESSED: []}
    matched = 0
    matched_retest: set = set()
    retest_by_list_index = {entry["index"]: entry
                            for entry in retest_entries}

    for parsed in baseline_entries:
        index_map = retest_by_id if parsed["kind"] == "id" else retest_by_fp
        counterpart_index = index_map.get(parsed["value"])
        if counterpart_index is None:
            if parsed["status"] == STATUS_OPEN:
                counters[RESOLVED] += 1
                buckets[RESOLVED].append(
                    _entry(parsed, STATUS_OPEN, None, "unmatched"))
            elif parsed["status"] is not None:
                counters[UNCHANGED] += 1
            continue  # a None status already warned at parse
        counterpart = retest_by_list_index[counterpart_index]
        matched += 1
        matched_retest.add(counterpart_index)
        if parsed["status"] is None or counterpart["status"] is None:
            continue  # warned at parse; never silently classified
        churn = PAIR_CLASS[(parsed["status"], counterpart["status"])]
        if churn == UNCHANGED:
            counters[UNCHANGED] += 1
            continue
        counters[churn] += 1
        buckets[churn].append(_entry(
            counterpart, parsed["status"], counterpart["status"],
            parsed["kind"]))

    for parsed in retest_entries:
        if parsed["index"] in matched_retest:
            continue
        if parsed["status"] is None:
            continue  # warned at parse
        if parsed["status"] in (STATUS_OPEN, STATUS_FIXED):
            counters[NEW] += 1
            buckets[NEW].append(
                _entry(parsed, None, parsed["status"], "unmatched"))
        else:  # a not_present row with no counterpart: no churn
            counters[UNCHANGED] += 1

    notes = [NOTE_MATCHING, NOTE_CLASSIFICATION, NOTE_DISCIPLINE]
    published: Dict[str, List[Dict[str, Any]]] = {}
    for bucket in (RESOLVED, NEW, REGRESSED):
        entries = buckets[bucket]
        entries.sort(key=lambda item: item["_sort"])
        total = len(entries)
        published[bucket] = [
            {key: entry[key] for key in ENTRY_KEYS}
            for entry in entries[:DIFF_CAP]
        ]
        if total > DIFF_CAP:
            notes.append("%s limited to the first %d of %d entries"
                         % (bucket, DIFF_CAP, total))
    warnings_total = len(warnings)
    if warnings_total > DIFF_CAP:
        notes.append("warnings limited to the first %d of %d entries"
                     % (DIFF_CAP, warnings_total))
    counts = {
        RESOLVED: counters[RESOLVED],
        NEW: counters[NEW],
        REGRESSED: counters[REGRESSED],
        UNCHANGED: counters[UNCHANGED],
        "matched": matched,
        "warnings": warnings_total,
    }
    return {
        "resolved": published[RESOLVED],
        "new": published[NEW],
        "regressed": published[REGRESSED],
        "unchanged_count": counters[UNCHANGED],
        "matched_count": matched,
        "warnings": warnings[:DIFF_CAP],
        "counts": counts,
        "notes": notes,
    }