#!/usr/bin/env python3
r"""KA-093 (OPT-93) - cards/matrix sync gate for the agent registry.

The GATE for task [93] "Cards/matrix sync": when the registry changes, the
agent cards (/team/ card data) and docs/AGENT_MATRIX.md must be regenerated
from it, and this checker is what detects every drift kind between the two
surfaces. Read-only: it verifies and edits NOTHING - the integrator applies
regenerated rows/sections/summary by hand or by generated output, never via
this tool.

Surfaces compared:

- LIVE REGISTRY - `agentic_ai/agents/registry.py` read by LIBRARY IMPORT
  (module-level `AGENT_REGISTRY` tuples + `resolve_agent_class`), the same
  source `agent list` renders. Never via child-process invocation or
  network I/O. Importing a registered agent's module may fail gracefully
  (resolver returns None -> drift findings, not a crash).
- AGENT CARD - the registered agent CLASS, read WITHOUT instantiation
  (mirroring the `agent card` fallback and the `agent ops` surface):
  - id and category from the registry entry,
  - purpose derived from the class docstring's first non-empty line
    (docs/KA-BUILDING-CONVENTIONS.md section 2: the class docstring IS the
    public /team/ card purpose),
  - op count = class-level public callables with the `agent ops` filter
    (names starting with "_" excluded, plus the chassis names "agent_id"
    and "inference", `callable` only).
- docs/AGENT_MATRIX.md - read as plain text: Quick Reference rows
  (`| \`id\` | Name | Category | Caps | Tests |`), the per-agent sections
  (`### Name (\`file.py\`)` with **Purpose** and **Capabilities** tables),
  and the Test Coverage Summary counters (per-category agents + **Total**).

Diff kinds (diff["kind"], all advisory: the integrator fixes them):

- missing_row - registry id with no Quick Reference row
- extra_row - Quick Reference row not in the registry
- category_mismatch - quick-ref category differs from the registry category
- count_mismatch - quick-ref Caps differ from the live op count; summary
  **Total** differs from the quick-ref row count; a summary category's
  agents differ from the quick-ref rows in that category (counts must
  mirror the registry: rows -> summary, registry -> rows)
- docstring_drift - section **Purpose** differs from the docstring-derived
  card purpose (or the purpose is absent/unshown and the card has one)
- capability_line_drift - section capability rows differ from the live op
  count (rows are the capability mirror; names stay descriptive, COUNTS
  are the gate)

Report shape (the design contract, plus house tool/spec/verdict fields):

    {"registry": {"agents": N, "cards": {...}},
     "matrix": {"rows": N, "summary": N},
     "diffs": [{"kind": ..., "agent": ..., "detail": ...}, ...]}

Exit status: 0 when clean, 1 when drift findings exist - the future gate
hooks on it. Purity: no child-process invocation, no string-exec, no
network I/O; the checker only parses text and reads the registry via
import.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "AGENT_MATRIX.md"

# Chassis names the `agent ops` CLI surface excludes from op listing.
_EXCLUDED_OP_NAMES = ("agent_id", "inference")

_QUICK_REF_ROW = re.compile(
    r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*"
    r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$")
_SECTION_HEAD = re.compile(r"^###\s+(.+?)\s+\(`([^`]+)`\)\s*$")
_FILE_LINE = re.compile(r"^\*\*File\*\*:\s*`([^`]+)`")
_PURPOSE_LINE = re.compile(r"^\*\*Purpose\*\*:\s*(.*)$")
_OPS_ROW = re.compile(r"^\|\s*`([A-Za-z_][A-Za-z0-9_]*)`\s*\|")
_HEADING = re.compile(r"^#{2,3}\s")
_SUMMARY_ROW = re.compile(r"^\|\s*(\*\*Total\*\*|Category|[A-Za-z][A-Za-z ]*?)"
                          r"\s*\|\s*\*{0,2}(\d+)\*{0,2}\s*\|")

DIFF_KINDS = ("missing_row", "extra_row", "count_mismatch",
              "category_mismatch", "docstring_drift",
              "capability_line_drift")


def _norm(text: str) -> str:
    """Collapse all whitespace runs to single spaces and strip."""
    return re.sub(r"\s+", " ", text or "").strip()


def _validate_registry(registry) -> None:
    """Reject malformed registry shapes loudly instead of misreporting."""
    if not registry:
        raise ValueError("registry is empty; nothing to check")
    for agent_id, entry in sorted(registry.items()):
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("registry id is not a non-empty string: %r"
                             % (agent_id,))
        missing = {"class", "module", "category", "description"} - set(
            entry if isinstance(entry, dict) else {})
        if missing:
            raise ValueError("registry entry %r is missing keys: %s"
                             % (agent_id, ", ".join(sorted(missing))))


# ------------------------------------------------------------- live import

def card_purpose(cls) -> Optional[str]:
    """The docstring-derived card purpose: first non-empty doc line.

    Mirrors docs/KA-BUILDING-CONVENTIONS.md section 2: the class docstring
    is the public /team/ card purpose and `agent card` prints its first
    non-empty line. Returns None when the docstring is blank.
    """
    doc = getattr(cls, "__doc__", None)
    for line in (doc or "").splitlines():
        normalized = line.strip()
        if normalized:
            return _norm(normalized)
    return None


def class_op_count(cls) -> int:
    """Live op count: class-level public callables (`agent ops` filter).

    Same surface the `agent ops` CLI renders, read at class level so the
    checker never instantiates agents. Class-level attribute access means
    properties resolve to their accessor (not callable -> not an op),
    matching the planner-pure reading of the card.
    """
    count = 0
    for name in sorted(dir(cls)):
        if name.startswith("_") or name in _EXCLUDED_OP_NAMES:
            continue
        if callable(getattr(cls, name, None)):
            count += 1
    return count


def live_resolver(agent_id: str) -> Optional[type]:
    """Import the registered agent class by id (library import path).

    Returns the class, or None when the module/attribute import fails -
    the failure becomes drift findings instead of a crash.
    """
    _ensure_import_path()
    from agentic_ai.agents.registry import resolve_agent_class
    try:
        return resolve_agent_class(agent_id)
    except Exception:  # noqa: BLE001 - unresolvable classes are findings
        return None


def _ensure_import_path() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def live_registry() -> Dict[str, Dict[str, str]]:
    """The live registry as the display dict (`agent list` surface)."""
    _ensure_import_path()
    from agentic_ai.agents.registry import list_agents
    return list_agents()


# ------------------------------------------------------------ matrix parse

def quick_ref_region(matrix_text: str) -> str:
    """The document region under the `## Quick Reference` heading."""
    match = re.search(r"^##\s+Quick Reference\s*$", matrix_text,
                      flags=re.MULTILINE)
    if not match:
        raise ValueError("AGENT_MATRIX.md has no '## Quick Reference' heading")
    rest = matrix_text[match.end():]
    stop = re.search(r"^##\s", rest, flags=re.MULTILINE)
    return rest[:stop.start()] if stop else rest


def summary_region(matrix_text: str) -> str:
    """The document region under `## Test Coverage Summary`."""
    match = re.search(r"^##\s+Test Coverage Summary\s*$", matrix_text,
                      flags=re.MULTILINE)
    if not match:
        raise ValueError(
            "AGENT_MATRIX.md has no '## Test Coverage Summary' heading")
    rest = matrix_text[match.end():]
    stop = re.search(r"^##\s", rest, flags=re.MULTILINE)
    return rest[:stop.start()] if stop else rest


def parse_rows(matrix_text: str) -> Dict[str, Dict[str, object]]:
    """Quick Reference rows as {id: {agent, category, caps, tests}}."""
    rows: Dict[str, Dict[str, object]] = {}
    for line in quick_ref_region(matrix_text).splitlines():
        row = _QUICK_REF_ROW.match(line.strip())
        if row:
            rows[row.group(1)] = {
                "agent": row.group(2).strip(),
                "category": row.group(3).strip(),
                "caps": int(row.group(4)),
                "tests": int(row.group(5)),
            }
    if not rows:
        raise ValueError("AGENT_MATRIX.md Quick Reference parses to 0 rows")
    return rows


def parse_sections(matrix_text: str) -> List[Dict[str, object]]:
    """Agent sections as a list of dicts: {title, header_file, file_path,
    purpose (normalized or ""), cap_rows (quoted-identifier row count)}."""
    sections: List[Dict[str, object]] = []
    lines = matrix_text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if _SECTION_HEAD.match(line)), None)
    if start is None:
        raise ValueError("AGENT_MATRIX.md has no agent sections")
    for index in range(start, len(lines)):
        head = _SECTION_HEAD.match(lines[index])
        if not head:
            continue
        span_end = next((j for j in range(index + 1, len(lines))
                         if _HEADING.match(lines[j])), len(lines))
        span = lines[index + 1:span_end]
        purpose_parts: List[str] = []
        in_purpose = False
        for line in span:
            purpose_start = _PURPOSE_LINE.match(line)
            if purpose_start:
                in_purpose = True
                purpose_parts.append(purpose_start.group(1))
                continue
            if in_purpose:
                if (line.strip() == "" or line.startswith(("**", "|", "#"))):
                    in_purpose = False
                else:
                    purpose_parts.append(line)
        file_path = next(
            (m.group(1) for m in (_FILE_LINE.match(l) for l in span)
             if m), None)
        sections.append({
            "title": head.group(1).strip(),
            "header_file": head.group(2).strip(),
            "file_path": _norm(file_path) if file_path else None,
            "purpose": _norm(" ".join(purpose_parts)),
            "cap_rows": sum(1 for l in span if _OPS_ROW.match(l.strip())),
        })
    return sections


def parse_summary(matrix_text: str) -> Dict[str, object]:
    """Test Coverage Summary rows as {categories: {name: agents}, total}."""
    categories: Dict[str, int] = {}
    total: Optional[int] = None
    for line in summary_region(matrix_text).splitlines():
        row = _SUMMARY_ROW.match(line.strip())
        if not row:
            continue
        label, agents = row.group(1), int(row.group(2))
        if label == "Category":
            continue
        if label == "**Total**":
            total = agents
        else:
            categories[label] = agents
    return {"categories": categories, "total": total}


# ------------------------------------------------------------- the gate

def build_report(
    registry: Dict[str, Dict[str, str]],
    matrix_text: str,
    *,
    resolver: Optional[Callable[[str], Optional[type]]] = None,
) -> Dict[str, object]:
    """Cross-check the live registry cards against the matrix text.

    `resolver` (id -> class or None) supplies the card surface; when None
    the live loader resolves classes through the registry import path.
    Returns the report dict; NEVER mutates inputs or files. Raises
    ValueError for empty/structurally broken inputs.
    """
    _validate_registry(registry)
    if not matrix_text.strip():
        raise ValueError("matrix text is empty; nothing to check")

    rows = parse_rows(matrix_text)
    sections = parse_sections(matrix_text)
    summary = parse_summary(matrix_text)

    # --- cards (live registry surface) -----------------------------------
    cards: Dict[str, Dict[str, object]] = {}
    card_resolved: Dict[str, bool] = {}
    for agent_id in sorted(registry):
        entry = registry[agent_id]
        card: Dict[str, object] = {"category": str(entry["category"]),
                                   "purpose": None, "ops": None}
        klass = None
        try:
            klass = resolver(agent_id) if resolver else live_resolver(
                agent_id)
        except Exception:  # noqa: BLE001 - a raising resolver is drift
            klass = None
        card_resolved[agent_id] = klass is not None
        if klass is not None:
            card["purpose"] = card_purpose(klass)
            card["ops"] = class_op_count(klass)
        cards[agent_id] = card

    # --- matrix-section mapping (module path, header-name fallback) -------
    modules = {agent_id: str(entry["module"]).replace(".", "/") + ".py"
               for agent_id, entry in registry.items()}
    section_for_agent: Dict[str, Dict[str, object]] = {}
    for section in sections:
        path = str(section["file_path"]) if section["file_path"] else None
        matched = [agent_id for agent_id, module_path in modules.items()
                   if path == module_path]
        if len(matched) == 1 and matched[0] not in section_for_agent:
            section_for_agent[matched[0]] = section
            continue
        if path is None:
            # No **File** line: fall back to the header basename.
            by_name = [agent_id for agent_id, module_path in modules.items()
                       if Path(module_path).name == section["header_file"]]
            if len(by_name) == 1 and by_name[0] not in section_for_agent:
                section_for_agent[by_name[0]] = section

    diffs: List[Dict[str, object]] = []

    def add(kind: str, agent: Optional[str], detail: str) -> None:
        diffs.append({"kind": kind, "agent": agent, "detail": detail})

    # --- id coverage (both directions) ------------------------------------
    for agent_id in registry:
        if agent_id not in rows:
            add("missing_row", agent_id,
                "registry id has no Quick Reference row")
    for agent_id in sorted(rows):
        if agent_id not in registry:
            add("extra_row", agent_id,
                "Quick Reference row is not in the registry")

    # --- categories ---------------------------------------------------------
    for agent_id, row in sorted(rows.items()):
        entry = registry.get(agent_id)
        if entry and _norm(str(row["category"])).lower() != _norm(
                str(entry["category"])).lower():
            add("category_mismatch", agent_id,
                "quick-ref category %r != registry %r"
                % (row["category"], entry["category"]))

    # --- rows, summary counters vs the live cards / the row mirror -------
    by_rows_category: Dict[str, int] = {}
    for row in rows.values():
        by_rows_category[_norm(str(row["category"])).lower()] = \
            by_rows_category.get(_norm(str(row["category"])).lower(), 0) + 1

    for agent_id in sorted(cards):
        card = cards[agent_id]
        klass_ok = card_resolved[agent_id]
        if not klass_ok:
            add("docstring_drift", agent_id,
                "class %r does not import; card purpose unknown"
                % registry[agent_id]["class"])
            add("capability_line_drift", agent_id,
                "class %r does not import; op count unknown"
                % registry[agent_id]["class"])
            continue
        section = section_for_agent.get(agent_id)
        purpose = card["purpose"]
        if purpose is None:
            add("docstring_drift", agent_id,
                "class docstring (the /team/ card) is empty")
        elif section is None:
            module_path = str(registry[agent_id]["module"])
            add("docstring_drift", agent_id,
                "no AGENT_MATRIX section matched module %r; purpose not "
                "shown" % module_path)
        elif not section["purpose"]:
            add("docstring_drift", agent_id,
                "section has no **Purpose** paragraph")
        elif _norm(str(section["purpose"])) != _norm(str(purpose)):
            add("docstring_drift", agent_id,
                "card purpose %r != section purpose %r"
                % (purpose, section["purpose"]))
        op_count = card["ops"]
        row = rows.get(agent_id)
        if section is None:
            add("capability_line_drift", agent_id,
                "no AGENT_MATRIX section matched module %r; capability "
                "lines not shown" % str(registry[agent_id]["module"]))
        elif not section["cap_rows"]:
            add("capability_line_drift", agent_id,
                "section has no capability rows")
        elif int(section["cap_rows"]) != int(op_count):
            add("capability_line_drift", agent_id,
                "section capability rows %d != live op count %d"
                % (int(section["cap_rows"]), int(op_count)))
        if row is not None and op_count is not None:
            if int(row["caps"]) != int(op_count):
                add("count_mismatch", agent_id,
                    "quick-ref caps %d != live op count %d"
                    % (int(row["caps"]), int(op_count)))

    total = summary["total"]
    if total is None:
        add("count_mismatch", None, "summary has no **Total** row")
    elif total != len(rows):
        add("count_mismatch", None,
            "summary Total %d agents != %d quick-ref rows"
            % (total, len(rows)))
    for name, agents in sorted(summary["categories"].items()):  # type: ignore
        mirrored = by_rows_category.pop(_norm(name).lower(), 0)
        if mirrored != agents:
            add("count_mismatch", None,
                "summary category %r claims %d agents; quick-ref has %d"
                % (name, agents, mirrored))
    for category, count in sorted(by_rows_category.items()):
        add("count_mismatch", None,
            "quick-ref category %r has %d rows; the summary names it "
            "not" % (category, count))

    diffs.sort(key=lambda d: (d["kind"], d["agent"] or "", d["detail"]))
    verdict = "clean" if not diffs else "drift"
    return {
        "tool": "ka-cards-matrix",
        "spec": "OPT-93 / KA-093",
        "registry": {"agents": len(registry), "cards": cards},
        "matrix": {"rows": len(rows),
                   "summary": summary["total"]},
        "diffs": diffs,
        "diffs_total": len(diffs),
        "verdict": verdict,
    }


# ------------------------------------------------------------------ CLI

def _printed_report(report: Dict[str, object]) -> List[str]:
    unresolved = sum(
        1 for card in report["registry"]["cards"].values()  # type: ignore
        if card["ops"] is None)  # type: ignore
    lines = ["KA-093 cards/matrix sync: %s" % report["verdict"],
             "registry agents=%d (cards unresolved=%d) matrix rows=%d "
             "summary=%s"
             % (report["registry"]["agents"], unresolved,  # type: ignore
                report["matrix"]["rows"],  # type: ignore
                report["matrix"]["summary"]),  # type: ignore
             "diffs=%d" % report["diffs_total"]]  # type: ignore
    if not report["diffs"]:  # type: ignore
        lines.append("(no drift)")
    for diff in report["diffs"]:  # type: ignore
        lines.append("- [%s] %s: %s"
                     % (diff["kind"], diff["agent"] or "-", diff["detail"]))
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry: build the live report, print it, and exit 0/1."""
    parser = argparse.ArgumentParser(
        description="KA-093 cards/matrix sync gate (read-only)")
    parser.add_argument("--matrix", default=str(MATRIX_PATH),
                        help="AGENT_MATRIX.md path (default: the repo doc)")
    parser.add_argument("--json", action="store_true",
                        help="print the full report as JSON")
    args = parser.parse_args(argv)

    registry = live_registry()
    report = build_report(registry, Path(args.matrix).read_text(
        encoding="utf-8"), resolver=None)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("\n".join(_printed_report(report)))
    return 0 if report["verdict"] == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())