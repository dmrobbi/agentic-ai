"""CVE dossier ops (2026-10-08 KA merge): deterministic defense-only
research notes for two confirmed real CVEs whose workspaces were
salvaged from the removed kaliagent-v4 leftover (git history c965747)
as part of the owner's merge order, before the dead-code cleanup.

The transplanted halves are the DEFENSIVE ones only: root-cause
analysis digests, affected surfaces, detection mapping (suricata/yara/
host-check concepts), and mitigation sequences. The PoC/exploit files
(poc.py, libnss_pwn.c, trigger.c, annotated exploit chains) were
deliberately NOT transposed - the catalog-data policy carries
methodology and links only; the PoC repositories are carried as links.

A pure module in the package_doctor/tool_kb shape: the catalog data
file is read LAZILY inside the ops (no chassis import; nothing bound
at module level but constants), no clock reads (the stamp arrives by
injection so clockless runs render deterministically), no process
spawning, no network facilities.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    "CONTENT_LIMIT",
    "DETECTION_SURFACES",
    "DOSSIERS_FILE",
    "DOSSIER_FIELDS",
    "SCRUB_LIMIT",
    "cve_dossier_outline",
    "cve_dossiers_index",
]

# Echoed identifiers cap at SCRUB_LIMIT (house cap); dossier CONTENT
# fields (summary/what/mitigation rows) are data, not echoes: they cap
# at CONTENT_LIMIT so the analysis survives the scrub.
SCRUB_LIMIT = 128
CONTENT_LIMIT = 2000

DETECTION_SURFACES = ("suricata", "yara", "shell")

DOSSIER_FIELDS = (
    "affected", "cwe", "cvss", "detection", "links", "mitigation",
    "one_liner", "patch", "product", "provenance", "published", "summary",
)

DOSSIERS_FILE = Path(__file__).resolve().parent / "data" / "cve_dossiers.json"

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WS_RE = re.compile(r"\s+")


def _scrub_text(value: Any, limit: Optional[int] = None) -> str:
    """Module-level input scrub: control characters removed, whitespace
    runs collapsed to single spaces, outer whitespace stripped, length
    capped (SCRUB_LIMIT by default, CONTENT_LIMIT for data fields).
    Non-string input scrubs to ""."""
    if not isinstance(value, str):
        return ""
    if limit is None:
        limit = SCRUB_LIMIT
    text = _CTRL_RE.sub("", value)
    text = _WS_RE.sub(" ", text).strip()
    return text[:limit]


def _load_dossiers() -> Dict[str, Dict[str, Any]]:
    """Lazy catalog read. Unlike a doctor (tolerated loud), these ops
    are query surfaces: a missing/unparsable/non-mapping catalog refuses
    closed with ValueError - never silently empty."""
    try:
        loaded = json.loads(DOSSIERS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(
            "cve dossier catalog unreadable: %s: %s"
            % (type(exc).__name__, _scrub_text("%s" % (exc,)))) from exc
    if not isinstance(loaded, dict):
        raise ValueError(
            "cve dossier catalog is not a mapping (%s)"
            % type(loaded).__name__)
    return loaded


def cve_dossiers_index(generated_at: Any = None) -> Dict[str, Any]:
    """CVE dossier index: the cve_id/cvss/published/product/one_liner
    rows for every dossier, sorted by cve_id."""
    catalog = _load_dossiers()
    rows = []
    for cve_id in sorted(catalog):
        row = catalog[cve_id]
        rows.append({
            "cve_id": _scrub_text(cve_id),
            "cvss": row.get("cvss"),
            "published": _scrub_text(row.get("published")),
            "product": _scrub_text(row.get("product"), CONTENT_LIMIT),
            "one_liner": _scrub_text(row.get("one_liner"), CONTENT_LIMIT),
        })
    return {
        "dossiers": rows,
        "count": len(rows),
        "generated_at": generated_at,
    }


def _outline_detection(rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    outlines = []
    for det in rows:
        outlines.append({
            "surface": _scrub_text(det.get("surface")),
            "what": _scrub_text(det.get("what"), CONTENT_LIMIT),
            "artifact": _scrub_text(det.get("artifact"), CONTENT_LIMIT),
        })
    return outlines


def cve_dossier_outline(
    cve_id: Any = None, generated_at: Any = None,
) -> Dict[str, Any]:
    """Defense planning outline for one CVE dossier: the full defensive
    row (summary, affected surfaces, patch reference, detection mapping,
    mitigation sequence, links). Unknown or hostile ids refuse closed."""
    key = _scrub_text(cve_id)
    if not key:
        raise ValueError("cve id required: a non-blank string")
    catalog = _load_dossiers()
    if key not in catalog:
        raise ValueError(
            "unknown cve id: %s (known: %s)"
            % (key, ", ".join(sorted(catalog))))
    row = catalog[key]
    outline: Dict[str, Any] = {
        "affected": [_scrub_text(item, CONTENT_LIMIT)
                     for item in row.get("affected", [])],
        "cwe": _scrub_text(row.get("cwe"), CONTENT_LIMIT),
        "cvss": row.get("cvss"),
        "detection": _outline_detection(row.get("detection", [])),
        "links": {
            _scrub_text(name): _scrub_text(url, CONTENT_LIMIT)
            for name, url in row.get("links", {}).items()
        },
        "mitigation": [_scrub_text(item, CONTENT_LIMIT)
                       for item in row.get("mitigation", [])],
        "one_liner": _scrub_text(row.get("one_liner"), CONTENT_LIMIT),
        "patch": _scrub_text(row.get("patch"), CONTENT_LIMIT),
        "product": _scrub_text(row.get("product"), CONTENT_LIMIT),
        "provenance": _scrub_text(row.get("provenance"), CONTENT_LIMIT),
        "published": _scrub_text(row.get("published")),
        "summary": _scrub_text(row.get("summary"), CONTENT_LIMIT),
    }
    return {
        "cve_id": key,
        "generated_at": generated_at,
        "dossier": outline,
    }
