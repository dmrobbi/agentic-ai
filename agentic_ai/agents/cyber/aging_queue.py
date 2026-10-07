"""Aging-exploitable queue (KA-068): the unpatched-vulnerability
priority report - the patch monitor's ages x exploit availability.

A pure planner module in the kev_bridge shape: a patch monitor's report
in (the committed fixture shape, tests/fixtures/scans/
patch_report_shape.json) -> a deterministic priority queue out (what is
old, unpatched, and exploitable). No chassis import, no process
spawning, no network facilities, no wall-clock reads: the monitor's
ages arrive per row as age_days, so the planner never needs a clock.

THE PATCH-REPORT SHAPE (the planner's input contract):
  top-level: monitor, generated_at, source, rows
  row:       cve, host, platform, product, patched, age_days,
             exploit_available, kev
  age_days = how long the monitor says this finding has sat unpatched.
  Every age and marker is monitor-reported, never computed here: a
  planner without a clock cannot invent an age.

DERIVATION - the ages x exploit-availability grid (weights and
multipliers are powers of two, so a score is one fleet-wide
comparable integer; exact cells pinned by tests):

  tier:  kev listing          -> "weaponized" (weight 4)
         (a CISA KEV listing means exploited in the wild, so it
         outranks the monitor's softer exploit_available marker)
         else exploit flag    -> "public"      (weight 2)
         else                 -> "none"        (weight 1)

  band:  age >= 730 -> "ancient" (x8)   >= 365 -> "stale" (x4)
         age >= 30  -> "aging"   (x2)   else   -> "fresh" (x1)

  score = tier weight x band multiplier:
             fresh  aging  stale  ancient
  weaponized   4      8      16      32
  public       2      4       8      16
  none         1      2       4       8

  priority: score >= 12 -> P1 (act now); >= 8 -> P2 (this cycle);
  else P3 (scheduled). P1 is weaponized at stale+ and public at
  ancient; a weaponized fresh row still grades P3 - this is an AGING
  queue: age is the weighting spine, and a just-disclosed exploited
  CVE rides the monitor's own escalation, not age debt.

QUEUE DISCIPLINE:
  - only UNPATCHED rows enter; patched rows are suppressed, not
    scored, and audited in the report's counts;
  - order: score desc, then age desc, then (host, cve) - fully
    deterministic, same input renders the same report;
  - every external string echoed into the report (cve, host,
    platform, product) passes the module scrub helper first.

REPORT SHAPE (the planner's output contract, exact):
  counts:           total_rows, unpatched, patched, p1, p2, p3 -
                    truth for the WHOLE report even when the queue is
                    limited;
  queue:            the ordered grade rows, limited when a limit is
                    passed (row: cve, host, platform, product,
                    age_days, age_band, exploit_tier, score, priority);
  by_host:          host -> [cve...] in queue order, mirroring the
                    published queue;
  oldest_unpatched: {cve, host, age_days} for the maximum-age
                    unpatched row (input-order-first tie-break), None
                    when nothing is unpatched;
  notes:            deterministic derivation notes, plus one limiting
                    note when a cap actually cut rows.

Validation refuses closed: an actionable ValueError on any contract
miss (the message names the offending keys/rows - the
registry-unknown-ID error pattern). Optional parameters get safe
defaults (limit=None publishes the whole queue).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

TOP_KEYS = ("monitor", "generated_at", "source", "rows")
ROW_KEYS = (
    "cve", "host", "platform", "product",
    "patched", "age_days", "exploit_available", "kev",
)
QUEUE_ROW_KEYS = (
    "cve", "host", "platform", "product",
    "age_days", "age_band", "exploit_tier", "score", "priority",
)
CVE_RE = r"CVE-\d{4}-\d+"

# Age bands (the queue's weighting spine): days-sat-unpatched at which
# a band flips - each boundary is inclusive, at-and-after.
AGE_BAND_AGING = 30    # a month of patch debt
AGE_BAND_STALE = 365   # a year of patch debt
AGE_BAND_ANCIENT = 730  # two years of patch debt

# Exploit availability tiers -> weights (the x-availability factor).
TIER_WEAPONIZED = "weaponized"  # CISA KEV listing: exploited in the wild
TIER_PUBLIC = "public"          # exploit-available marker, not KEV-listed
TIER_NONE = "none"              # no known exploit; the queue still ages it
EXPLOIT_WEIGHTS = {TIER_WEAPONIZED: 4, TIER_PUBLIC: 2, TIER_NONE: 1}

# Age bands -> multipliers (the ages factor).
AGE_MULTIPLIERS = {"ancient": 8, "stale": 4, "aging": 2, "fresh": 1}

# Named priorities off the score grid.
P1_MIN_SCORE = 12  # weaponized at stale+, public-grade at ancient
P2_MIN_SCORE = 8   # exactly one grid cell below P1

# Echoed external strings are capped at this length.
SCRUB_LIMIT = 128

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WS_RE = re.compile(r"\s+")


def _scrub_text(value: Any) -> str:
    """Module-level input scrub: control characters removed, whitespace
    runs collapsed to single spaces, outer whitespace stripped, length
    capped at SCRUB_LIMIT. Non-string input scrubs to "". Every
    external string echoed into the report passes through here."""
    if not isinstance(value, str):
        return ""
    text = _CTRL_RE.sub("", value)
    text = _WS_RE.sub(" ", text).strip()
    return text[:SCRUB_LIMIT]


def _validate_row(row: Any, where: str) -> None:
    """One row's contract: exact presence, CVE identifier shape, sane
    types. The ValueError message always carries `where`."""
    if not isinstance(row, dict):
        raise ValueError("%s not a mapping: %r" % (where, row))
    missing = [key for key in ROW_KEYS if key not in row]
    if missing:
        raise ValueError("%s missing required keys: %s" % (where, missing))
    cve = row["cve"]
    if not isinstance(cve, str) or not re.fullmatch(CVE_RE, cve):
        raise ValueError("%s cve malformed: %r" % (where, cve))
    for key in ("host", "platform", "product"):
        value = row[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "%s %s not a non-blank string: %r" % (where, key, value))
    age = row["age_days"]
    if isinstance(age, bool) or not isinstance(age, int) or age < 0:
        raise ValueError(
            "%s age_days not a non-negative integer: %r" % (where, age))
    for key in ("patched", "exploit_available", "kev"):
        if not isinstance(row[key], bool):
            raise ValueError(
                "%s %s not a boolean: %r" % (where, key, row[key]))


def validate_patch_report(report: Any) -> None:
    """An actionable ValueError on any patch-report contract miss
    (missing top-level keys, rows not a list, malformed rows); None
    when the report is well-formed."""
    if not isinstance(report, dict):
        raise ValueError("patch report not a mapping: %r" % (report,))
    missing = [key for key in TOP_KEYS if key not in report]
    if missing:
        raise ValueError("patch report missing required keys: %s" % missing)
    rows = report["rows"]
    if not isinstance(rows, list):
        raise ValueError("patch report rows not a list: %r" % (rows,))
    for index, row in enumerate(rows):
        _validate_row(row, "patch report row %d" % index)


def _age_band(age_days: int) -> str:
    """The band edges are inclusive, at-and-after: 730+/365+/30+."""
    if age_days >= AGE_BAND_ANCIENT:
        return "ancient"
    if age_days >= AGE_BAND_STALE:
        return "stale"
    if age_days >= AGE_BAND_AGING:
        return "aging"
    return "fresh"


def _exploit_tier(kev: bool, exploit_available: bool) -> str:
    """A KEV listing outranks a plain exploit-available marker: known
    exploited in the wild beats a softer availability flag."""
    if kev:
        return TIER_WEAPONIZED
    if exploit_available:
        return TIER_PUBLIC
    return TIER_NONE


def derive_grade(row: Dict[str, Any]) -> Dict[str, Any]:
    """The ages-x-availability grid for one report row:
    {age_band, exploit_tier, score, priority}."""
    _validate_row(row, "grade input")
    band = _age_band(row["age_days"])
    tier = _exploit_tier(row["kev"], row["exploit_available"])
    score = EXPLOIT_WEIGHTS[tier] * AGE_MULTIPLIERS[band]
    if score >= P1_MIN_SCORE:
        priority = "P1"
    elif score >= P2_MIN_SCORE:
        priority = "P2"
    else:
        priority = "P3"
    return {
        "age_band": band,
        "exploit_tier": tier,
        "score": score,
        "priority": priority,
    }


def aging_priority_queue(
    report: Dict[str, Any],
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """The aging-exploitable priority report: unpatched findings only,
    deterministically ordered by the ages-x-availability score (P1 acts
    now, P2 this cycle, P3 scheduled)."""
    validate_patch_report(report)
    if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int)
            or limit < 1):
        raise ValueError(
            "limit must be None or a positive integer: %r" % (limit,))
    rows = report["rows"]
    unpatched = [row for row in rows if not row["patched"]]

    queue: List[Dict[str, Any]] = []
    for row in unpatched:
        grade = derive_grade(row)
        queue.append({
            "cve": _scrub_text(row["cve"]),
            "host": _scrub_text(row["host"]),
            "platform": _scrub_text(row["platform"]),
            "product": _scrub_text(row["product"]),
            "age_days": row["age_days"],
            "age_band": grade["age_band"],
            "exploit_tier": grade["exploit_tier"],
            "score": grade["score"],
            "priority": grade["priority"],
        })
    queue.sort(key=lambda entry: (
        -entry["score"], -entry["age_days"], entry["host"], entry["cve"]))

    counts = {
        "total_rows": len(rows),
        "unpatched": len(unpatched),
        "patched": len(rows) - len(unpatched),
        "p1": sum(1 for entry in queue if entry["priority"] == "P1"),
        "p2": sum(1 for entry in queue if entry["priority"] == "P2"),
        "p3": sum(1 for entry in queue if entry["priority"] == "P3"),
    }

    published = queue if limit is None else queue[:limit]
    by_host: Dict[str, List[str]] = {}
    for entry in published:  # mirrors the PUBLISHED queue
        by_host.setdefault(entry["host"], []).append(entry["cve"])

    # input order wins the tie for the single oldest unpatched finding
    oldest: Optional[Dict[str, Any]] = None
    for row in unpatched:
        if oldest is None or row["age_days"] > oldest["age_days"]:
            oldest = row
    oldest_unpatched = None if oldest is None else {
        "cve": _scrub_text(oldest["cve"]),
        "host": _scrub_text(oldest["host"]),
        "age_days": oldest["age_days"],
    }

    notes = [
        "unpatched findings only: %d of %d report rows suppressed as "
        "patched" % (counts["patched"], counts["total_rows"]),
        "tier: a CISA KEV listing grades weaponized (known exploited "
        "in the wild), a plain exploit-available marker grades "
        "public, otherwise none",
        "grid: score = tier weight x age band multiplier in powers of "
        "two; P1 >= %d, P2 >= %d, else P3 (age is the weighting spine)"
        % (P1_MIN_SCORE, P2_MIN_SCORE),
    ]
    if limit is not None and len(queue) > limit:
        notes.append("queue limited to the top %d of %d unpatched "
                     "findings" % (limit, len(queue)))
    return {
        "counts": counts,
        "queue": published,
        "by_host": by_host,
        "oldest_unpatched": oldest_unpatched,
        "notes": notes,
    }
