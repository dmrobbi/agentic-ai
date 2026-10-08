"""Kali-package doctor (KA-091): every KALI_TOOLS_DB binary verified
present on the host - per-tool presence rows.

A pure doctor module in the aging_queue shape: a plain module whose op
reports, per catalog tool, whether the expected binary is on the host
and where it was found. No chassis import at module load (the catalog
is imported READ-ONLY and LAZILY inside the op - the house anti-cycle
rule - and the module stays loadable without the agent chassis); no
process spawning, no network facilities, no clock reads: the stamp
arrives by injection, so a clockless run renders it verbatim as None
and the report is fully deterministic.

THE RESOLVER SEAM (injected):
  resolver = callable(binary) -> path-or-None; one filesystem lookup
  per binary. Default = shutil.which (a filesystem lookup, not a
  spawned process). Tests inject dict-backed resolvers for
  determinism; a host doctor may inject its own PATH probe. A
  resolver that raises is tolerated loud not fatal: that binary
  reports missing with a warning naming it - a doctor must finish
  the checkup, never abort it.

THE CATALOG CONTRACT (read-only):
  KALI_TOOLS_DB maps tool key -> row; the consumed field is
  `command` (the binary the tool runs). Rows arrive as dataclass
  attribute rows; mapping rows are accepted for tolerance. A row is
  malformed when its key is not a non-blank string, it is neither a
  mapping nor an attribute carrier, or command is missing/blank -
  such rows are SKIPPED WITH A WARNING, never fatal, and never
  counted in the summary (only healthy, checked rows inflate
  present/missing/total).

RESULT SHAPE (exact keys, deterministic order):
  rows:         [{tool, binary, present, path}] sorted by (tool,
                binary); tool = the catalog key (scrubbed), binary =
                the scrubbed command (exactly what the resolver
                received), present a strict boolean, path the
                scrubbed found path or None.
  summary:      {present, missing, total} - truth for the whole
                report; total counts healthy, checked rows only.
  generated_at: the injected value verbatim (None by default; the
                caller owns the stamp).
  warnings:     non-blank strings, one per tolerated malformation,
                in encounter order; a clean catalog with a stable
                resolver renders exactly [].

THE UNIVERSE CATALOG (package_universe_rows, the 2026-10-08 transplant):
  the same resolver seam and result contract, sourced from the
  transplanted kali_packages.json file - the removed kali_agent_v3
  602-tool database, extracted verbatim from git history (commit
  c965747) by the committed tools/build_kali_packages.py builder. The
  consumed field is `package` (file rows are plain JSON mappings); a
  missing, unparsable, or non-mapping catalog file is a tolerated-loud
  warning with an empty checkup, never a fatal state.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "ROW_KEYS",
    "SCRUB_LIMIT",
    "SUMMARY_KEYS",
    "UNIVERSE_FILE",
    "package_doctor_rows",
    "package_universe_rows",
]

ROW_KEYS = ("tool", "binary", "present", "path")
SUMMARY_KEYS = ("present", "missing", "total")

# Echoed strings are capped at this length (house cap).
SCRUB_LIMIT = 128

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WS_RE = re.compile(r"\s+")


def _scrub_text(value: Any) -> str:
    """Module-level input scrub: control characters removed, whitespace
    runs collapsed to single spaces, outer whitespace stripped, length
    capped at SCRUB_LIMIT. Non-string input scrubs to "". Every echoed
    string passes through here."""
    if not isinstance(value, str):
        return ""
    text = _CTRL_RE.sub("", value)
    text = _WS_RE.sub(" ", text).strip()
    return text[:SCRUB_LIMIT]


def _row_field(row: Any, field: str) -> Any:
    """Read one catalog field off a row: mapping rows use .get,
    attribute rows (the dataclass shape) use getattr; anything else
    carries no field."""
    if isinstance(row, dict):
        return row.get(field)
    return getattr(row, field, None)


def package_doctor_rows(
    resolver: Optional[Callable[[str], Any]] = None,
    generated_at: Any = None,
) -> Dict[str, Any]:
    """Every KALI_TOOLS_DB binary verified present on the host: per-tool
    presence rows, a present/missing/total summary, the injected
    generated_at echoed verbatim (None by default), and one warning per
    tolerated malformation."""
    if resolver is None:
        resolver = shutil.which
    if not callable(resolver):
        raise ValueError(
            "resolver must be callable or None: %r" % (resolver,))

    # Lazy, read-only catalog import (the house anti-cycle rule).
    from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB

    warnings: List[str] = []
    rows: List[Dict[str, Any]] = []
    db = KALI_TOOLS_DB
    if not isinstance(db, dict):
        warnings.append(
            "KALI_TOOLS_DB is not a mapping (%s): nothing to check"
            % type(db).__name__)
        db = {}

    for index, (key, entry) in enumerate(db.items(), start=1):
        tool = _scrub_text(key)
        if not tool:
            warnings.append(
                "db row %d skipped: key is not a non-blank string" % index)
            continue
        command = _row_field(entry, "command")
        binary = _scrub_text(command)
        if not binary:
            warnings.append(
                "db row '%s' skipped: command is not a clean non-blank "
                "string" % tool)
            continue

        path: Optional[str] = None
        present = False
        try:
            found = resolver(binary)
        except Exception as exc:
            warnings.append(
                "db row '%s' marked missing: resolver raised %s"
                % (tool, type(exc).__name__))
        else:
            if isinstance(found, str) and found.strip():
                present = True
                path = _scrub_text(found)
            elif not isinstance(found, str) and found is not None:
                warnings.append(
                    "db row '%s' marked missing: resolver returned a %s "
                    "instead of a path-or-None" % (tool, type(found).__name__))
        rows.append({
            "tool": tool,
            "binary": binary,
            "present": present,
            "path": path,
        })

    rows.sort(key=lambda row: (row["tool"], row["binary"]))
    present_count = sum(1 for row in rows if row["present"])
    summary = {
        "present": present_count,
        "missing": len(rows) - present_count,
        "total": len(rows),
    }
    return {
        "rows": rows,
        "summary": summary,
        "generated_at": generated_at,
        "warnings": warnings,
    }


# --- the transplanted universe catalog (KA merge, 2026-10-08) -------------
# Source: kali_agent_v3/core/tools_db_600_plus.json @ c965747 via the
# committed tools/build_kali_packages.py builder; 602 rows, exactly the
# fields (package, category, desc, mb, priority, tags). The op below is
# the package_doctor seam over that FILE: identical row/summary/warning
# semantics, `package` consumed as the binary, a missing/unparsable
# catalog tolerated loud (warning + empty checkup), never fatal.

UNIVERSE_FILE = Path(__file__).resolve().parent / "data" / "kali_packages.json"


def _universe_presence(
    binary: str, tool: str, resolver, warnings: List[str],
) -> Dict[str, Any]:
    """One resolver grading in the universe seam: raises tolerated loud,
    hostile returns graded missing with a warning."""
    try:
        found = resolver(binary)
    except Exception as exc:
        warnings.append(
            "universe row '%s' marked missing: resolver raised %s"
            % (tool, type(exc).__name__))
        return {"present": False, "path": None}
    if isinstance(found, str) and found.strip():
        return {"present": True, "path": _scrub_text(found)}
    if not isinstance(found, str) and found is not None:
        warnings.append(
            "universe row '%s' marked missing: resolver returned a %s "
            "instead of a path-or-None" % (tool, type(found).__name__))
    return {"present": False, "path": None}


def package_universe_rows(
    universe_path: Optional[Any] = None,
    resolver: Optional[Callable[[str], Any]] = None,
    generated_at: Any = None,
) -> Dict[str, Any]:
    """Universe package presence: every transplanted kali_packages.json
    package verified through the injected resolver - the identical result
    contract to package_doctor_rows, sourced from the universe file."""
    if resolver is None:
        resolver = shutil.which
    if not callable(resolver):
        raise ValueError(
            "resolver must be callable or None: %r" % (resolver,))

    path = UNIVERSE_FILE if universe_path is None else Path(universe_path)

    warnings: List[str] = []
    db: Dict[str, Any] = {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        warnings.append("universe catalog missing: %s" % path.name)
    except (OSError, ValueError) as exc:
        detail = _scrub_text("%s" % (exc,))
        warnings.append(
            "universe catalog unreadable: %s%s"
            % (type(exc).__name__, (": %s" % detail) if detail else ""))
    else:
        if isinstance(loaded, dict):
            db = loaded
        else:
            warnings.append(
                "universe catalog is not a mapping (%s): nothing to check"
                % type(loaded).__name__)

    rows: List[Dict[str, Any]] = []
    for index, (key, entry) in enumerate(db.items(), start=1):
        tool = _scrub_text(key)
        if not tool:
            warnings.append(
                "universe row %d skipped: key is not a non-blank string"
                % index)
            continue
        if not isinstance(entry, dict):
            warnings.append(
                "universe row '%s' skipped: not a mapping row" % tool)
            continue
        binary = _scrub_text(entry.get("package"))
        if not binary:
            warnings.append(
                "universe row '%s' skipped: package is not a clean "
                "non-blank string" % tool)
            continue
        graded = _universe_presence(binary, tool, resolver, warnings)
        rows.append({
            "tool": tool,
            "binary": binary,
            "present": graded["present"],
            "path": graded["path"],
        })

    rows.sort(key=lambda row: (row["tool"], row["binary"]))
    present_count = sum(1 for row in rows if row["present"])
    summary = {
        "present": present_count,
        "missing": len(rows) - present_count,
        "total": len(rows),
    }
    return {
        "rows": rows,
        "summary": summary,
        "generated_at": generated_at,
        "warnings": warnings,
    }
