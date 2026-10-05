"""kevstig router bridge (KA-067): a coverage.json (the kevstig API
shape) in -> routed rows out -> matching recommendations out. The "daily
fan-out" planner core; the periodic execution is a P5 scheduled job, not
this module.

API SHAPE (pinned from the LIVE snapshot 2026-10-05; the committed fixture
carries it verbatim):
  top-level: generated_at, catalog_date, source, catalog_count,
             routed_count, uncovered_count, platforms, entries
  platform row: platform, label, ckls, rules_maintained,
                kev_routed_total, kev_routed_30d, newest_KEV
  entry row: cve, vendor, product, name, description, dateAdded,
             note, platforms, coveredByMaintenance

INVARIANTS (pinned from the live snapshot):
  - catalog_count == routed_count + uncovered_count (1734 = 273 + 1461)
  - SUM(platform.kev_routed_total) >= routed_count: multi-platform matches
    count once in the headline but appear per platform (279 vs 273 live)
  - routed entries: coveredByMaintenance True + non-empty platforms

OUTPUT SCHEMA (route_coverage):
{
  "counts": {"catalog_count", "routed_count", "uncovered_count"},
  "routed_entries": [...],            # coveredByMaintenance rows, input order
  "routed_by_platform": {platform: [cve...]},   # coverage-array order
  "recommendations": [                # the fan-out: one row per
    {"cve", "platform", "known",      # (platform, cve) pair; matcher
     "exploit_name", "metasploit_module", "reliability", "port", "rank"}
  ],
  "unrouted_sample": [...],           # the honest-majority artifact
  "notes": [...]
}

Validation: missing top-level keys or non-CVE cve / non-list platforms on
an entry raise ValueError with an actionable message. Matcher injected
(duck-typed match_cve), CVEMatchingEngine by default; the matcher is
called ONCE PER UNIQUE CVE even when a row spans platforms. Pure planner:
no exec, no network, no local I/O (source-scanned)."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine

TOP_KEYS = (
    "generated_at", "catalog_date", "source",
    "catalog_count", "routed_count", "uncovered_count",
    "platforms", "entries",
)
CVE_RE = r"CVE-\d{4}-\d+"


def validate_coverage(coverage: Dict[str, Any]) -> None:
    """Actionable ValueError on any contract miss (registry-unknown-ID
    pattern: the error text carries the offending items)."""
    missing = [k for k in TOP_KEYS if k not in coverage]
    if missing:
        raise ValueError("coverage.json missing required keys: %s" % missing)
    for entry in coverage["entries"]:
        cve = entry.get("cve")
        if not isinstance(cve, str) or not re.fullmatch(CVE_RE, cve):
            raise ValueError("coverage entry cve malformed: %r" % (cve,))
        if not isinstance(entry.get("platforms"), list):
            raise ValueError("coverage entry platforms not a list: %s" % cve)


def route_coverage(
    coverage: Dict[str, Any],
    matcher=None,
    unrouted_sample_size: int = 5,
) -> Dict[str, Any]:
    """The daily fan-out planning core over a kevstig coverage.json."""
    validate_coverage(coverage)
    engine = matcher if matcher is not None else CVEMatchingEngine()

    routed = [e for e in coverage["entries"] if e.get("coveredByMaintenance")]
    unrouted = [e for e in coverage["entries"] if not e.get("coveredByMaintenance")]

    ordered_platforms = [p["platform"] for p in coverage["platforms"]]
    per_platform: Dict[str, List[str]] = {key: [] for key in ordered_platforms}
    for entry in routed:
        for platform in entry["platforms"]:
            if platform in per_platform:
                per_platform[platform].append(entry["cve"])

    matches: Dict[str, Any] = {}
    for entry in routed:
        if entry["cve"] not in matches:
            matches[entry["cve"]] = engine.match_cve(entry["cve"])

    recommendations: List[Dict[str, Any]] = []
    for platform in ordered_platforms:
        for cve in per_platform[platform]:
            recommendations.append(
                _recommendation(cve, platform, matches[cve]))

    routed_total = sum(p.get("kev_routed_total", 0) for p in coverage["platforms"])
    notes = [
        "catalog equation holds: %d = %d + %d"
        % (coverage["catalog_count"], coverage["routed_count"],
           coverage["uncovered_count"]),
        "platform kev_routed_total sums to %d >= routed_count %d "
        "(multi-platform matches count once in the headline)"
        % (routed_total, coverage["routed_count"]),
        "routed is NOT remediated: recommendations reference exploit "
        "metadata only - nothing here claims a baseline rule neutralizes "
        "a CVE (the upstream contract, restated)",
    ]

    return {
        "counts": {
            "catalog_count": coverage["catalog_count"],
            "routed_count": coverage["routed_count"],
            "uncovered_count": coverage["uncovered_count"],
        },
        "routed_entries": routed,
        "routed_by_platform": {k: v for k, v in per_platform.items() if v},
        "recommendations": recommendations,
        "unrouted_sample": unrouted[:unrouted_sample_size],
        "notes": notes,
    }


def _recommendation(cve: str, platform: str, match):
    known = match is not None
    return {
        "cve": cve,
        "platform": platform,
        "known": known,
        "exploit_name": match.exploit_name if known else None,
        "metasploit_module": match.metasploit_module if known else None,
        "reliability": match.reliability if known else None,
        "port": match.port if known else None,
        "rank": match.rank if known else None,
    }
