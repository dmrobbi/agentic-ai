#!/usr/bin/env python3
"""KA-079 (OPT-79) - registry/doc sync consistency checker.

Read-only tool: it verifies that the three documented agent surfaces agree
and edits NOTHING (future [INTEGRATION] tasks run it after doc lands).

Surfaces compared:

- LIVE REGISTRY - `agentic_ai/agents/registry.py::AGENT_REGISTRY` read by
  LIBRARY IMPORT (`agentic_ai.agents.registry.list_agents()`, the same
  surface the `agent list` CLI renders). Never via child-process
  invocation: the module
  must stay execution-pure. Importing registered agent modules is allowed
  to fail gracefully (resolver returns None -> reported, not crashed);
  the repo's dependency set is importable offline.
- AGENT CARD - the registered agent CLASS docstring. Per
  docs/KA-BUILDING-CONVENTIONS.md section 2, a registered agent's class
  docstring IS the public /team/ card purpose and must stay complete
  under 260 characters; `agent card` prints its first non-empty line.
- docs/AGENT_MATRIX.md - read as plain text: the Quick Reference table,
  the per-agent sections (`### Name (`file.py`)` + Purpose/File/Tests +
  capability rows), and the Test Coverage Summary table.

Checks (finding check names, all advisory: fix in the owning task):

- matrix_row_missing / matrix_row_unknown - id coverage both directions
- category_mismatch - quick-ref category vs registry category
- section_missing / section_unknown - section coverage by module path
- section_file_missing - section without a **File** line
- file_header_mismatch - header basename vs **File** basename
- section_purpose_missing - section without a **Purpose** paragraph
- registry_class_unresolved - class does not import/resolve (needs cards)
- card_missing - resolved class has no docstring (needs cards)
- card_overlength - normalized docstring over the conventions cap
- description_missing - empty registry description
- description_duplicate - identical registry description on 2+ ids
- section_op_count_mismatch - section capability rows vs quick-ref Caps
- section_tests_count_mismatch - section "(N tests" vs quick-ref Tests
- section_tests_file_missing - named test file absent on disk (repo root)
- summary_count_mismatch - Test Coverage Summary per-category Agents vs
  quick-ref rows in that category
- summary_total_mismatch - Total row vs quick-ref row count

Purity: no child-process invocation, no string-exec, no network; the
checker only
parses text and reads the registry/tests paths it is given.

Exit status: 0 when the report is consistent, 1 when drift findings
exist (mirrors scripts/ka/catalog_check.py so future integrations can
gate on it). Findings are advisory - the integrator fixes them.
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "docs" / "AGENT_MATRIX.md"

# docs/KA-BUILDING-CONVENTIONS.md section 2: the registered agent's class
# docstring is the public /team/ card purpose, complete and under 260 chars.
CARD_DOC_LIMIT = 260

_QUICK_REF_ROW = re.compile(
    r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*"
    r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$")
_SECTION_HEAD = re.compile(r"^###\s+(.+?)\s+\(`([^`]+)`\)\s*$")
_FILE_LINE = re.compile(r"^\*\*File\*\*:\s*`([^`]+)`")
_PURPOSE_LINE = re.compile(r"^\*\*Purpose\*\*:\s*(.*)$")
_OPS_ROW = re.compile(r"^\|\s*`([A-Za-z_][A-Za-z0-9_]*)`\s*\|")
_TESTS_LINE = re.compile(r"^\*\*Tests\*\*:\s*`([^`]+)`\s*(?:\((\d+)\s+tests)?")
_HEADING = re.compile(r"^#{2,3}\s")
_SUMMARY_ROW = re.compile(r"^\|\s*(\*\*Total\*\*|Category|[A-Za-z][A-Za-z ]*?)"
                          r"\s*\|\s*\*{0,2}(\d+)\*{0,2}\s*\|")

_CARD_CHECKS = ("card_missing", "card_overlength", "registry_class_unresolved")
_FILE_CHECKS = ("section_tests_file_missing",)


def _norm(text: str) -> str:
    """Collapse all whitespace runs to single spaces and strip."""
    return re.sub(r"\s+", " ", text or "").strip()


def _validate_registry(registry: Dict[str, Dict[str, str]]) -> None:
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


def parse_quick_ref(matrix_text: str) -> Dict[str, Dict[str, object]]:
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
    """Agent sections as a list of {title, header_file, file_path,
    purpose, op_count, tests_file, tests_count} dicts."""
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
        tests_file, tests_count = None, None
        for m in (_TESTS_LINE.match(l) for l in span):
            if m:
                tests_file, tests_count = m.group(1), m.group(2)
                break
        sections.append({
            "title": head.group(1).strip(),
            "header_file": head.group(2).strip(),
            "file_path": _norm(file_path) if file_path else None,
            "purpose": _norm(" ".join(purpose_parts)),
            "op_count": sum(1 for l in span if _OPS_ROW.match(l.strip())),
            "tests_file": _norm(tests_file) if tests_file else None,
            "tests_count": int(tests_count) if tests_count else None,
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


def build_report(
    registry: Dict[str, Dict[str, str]],
    matrix_text: str,
    *,
    repo_root: Optional[Path] = None,
    resolver: Optional[Callable[[str], Optional[type]]] = None,
    card_doc_limit: int = CARD_DOC_LIMIT,
) -> Dict[str, object]:
    """Cross-check the registry, the matrix text, and the agent cards.

    `resolver` (id -> class or None) enables the card checks; when given
    a None resolver (or omitted) the card checks are listed as skipped.
    `repo_root` enables the section-tests-file existence check.
    Returns the report dict; NEVER mutates inputs or files.
    """
    _validate_registry(registry)
    if not matrix_text.strip():
        raise ValueError("matrix text is empty; nothing to check")

    quick_ref = parse_quick_ref(matrix_text)
    sections = parse_sections(matrix_text)
    summary = parse_summary(matrix_text)
    findings: List[Dict[str, str]] = []

    def add(check: str, agent: Optional[str], detail: str) -> None:
        findings.append({"check": check, "agent": agent, "detail": detail})

    # --- row coverage, registry -> matrix and matrix -> registry ---------
    for agent_id in registry:
        if agent_id not in quick_ref:
            add("matrix_row_missing", agent_id,
                "registry id has no Quick Reference row")
    for agent_id in quick_ref:
        if agent_id not in registry:
            add("matrix_row_unknown", agent_id,
                "Quick Reference row is not in the registry")

    # --- categories ------------------------------------------------------
    for agent_id, row in sorted(quick_ref.items()):
        entry = registry.get(agent_id)
        if entry and _norm(str(row["category"])).lower() != _norm(
                str(entry["category"])).lower():
            add("category_mismatch", agent_id,
                "quick-ref category %r != registry %r"
                % (row["category"], entry["category"]))

    # --- sections vs registry (by module path, header-name fallback) ------
    modules = {agent_id: str(entry["module"]).replace(".", "/") + ".py"
               for agent_id, entry in registry.items()}
    module_basenames: Dict[str, List[str]] = {}
    for agent_id, module_path in modules.items():
        module_basenames.setdefault(Path(module_path).name, []).append(agent_id)
    mapped: Dict[str, str] = {}
    unmatched_sections: List[Dict[str, object]] = []
    for section in sections:
        path = str(section["file_path"]) if section["file_path"] else None
        by_path = [agent_id for agent_id, module_path in modules.items()
                  if path == module_path]
        if len(by_path) == 1:
            mapped[by_path[0]] = True
            continue
        by_name = module_basenames.get(str(section["header_file"]), [])
        if path is None and len(by_name) == 1:
            mapped[by_name[0]] = True
            add("section_file_missing", by_name[0],
                "section has no **File** line; matched by header name")
            continue
        if len(by_path) > 1:
            add("section_unknown", None,
                "section for %r matches %d registry modules (%s)"
                % (path if path else section["title"], len(by_path),
                   ", ".join(sorted(by_path))))
        unmatched_sections.append(section)
    if unmatched_sections:
        for section in unmatched_sections:
            path = section["file_path"]
            add("section_unknown", None,
                "section %r (%s) has no registry module match"
                % (section["title"], path if path else "no **File** line"))
    for agent_id, module_path in sorted(modules.items()):
        if agent_id not in mapped:
            add("section_missing", agent_id,
                "registry id has no agent-matrix section for %s" % module_path)

    # --- section internals -------------------------------------------------
    for agent_id, section in _sections_by_id(sections, modules,
                                             module_basenames):
        head_file = str(section["header_file"])
        path = section["file_path"]
        if not section["purpose"]:
            add("section_purpose_missing", agent_id,
                "section has no empty-free **Purpose** paragraph")
        if path and Path(str(path)).name != head_file:
            add("file_header_mismatch", agent_id,
                "header %r != **File** %r" % (head_file, path))
        row = quick_ref.get(agent_id)
        if row:
            if int(section["op_count"]) != int(row["caps"]):
                add("section_op_count_mismatch", agent_id,
                    "section capability rows %d != quick-ref caps %d"
                    % (int(section["op_count"]), int(row["caps"])))
            if section["tests_count"] is not None and \
                    int(section["tests_count"]) != int(row["tests"]):
                add("section_tests_count_mismatch", agent_id,
                    "section tests %s != quick-ref tests %s"
                    % (section["tests_count"], row["tests"]))
        if section["tests_file"] and repo_root is not None:
            if not (Path(repo_root) / str(section["tests_file"])).is_file():
                add("section_tests_file_missing", agent_id,
                    "%s does not exist" % section["tests_file"])

    # --- cards -------------------------------------------------------------
    checks_run = ["matrix_row_missing", "matrix_row_unknown",
                  "category_mismatch", "section_missing", "section_unknown",
                  "section_file_missing", "file_header_mismatch",
                  "section_purpose_missing", "section_op_count_mismatch",
                  "section_tests_count_mismatch", "description_missing",
                  "description_duplicate", "summary_count_mismatch",
                  "summary_total_mismatch"]
    checks_skipped: List[str] = list(_FILE_CHECKS if repo_root is None else [])
    if resolver is None:
        checks_skipped += list(_CARD_CHECKS)
    else:
        checks_run += list(_CARD_CHECKS)
        for agent_id in sorted(registry):
            try:
                klass = resolver(agent_id)
            except Exception:  # noqa: BLE001 - resolver errors are findings
                klass = None
            if klass is None:
                add("registry_class_unresolved", agent_id,
                    "class %r does not import/resolve from the module"
                    % registry[agent_id]["class"])
                continue
            doc = getattr(klass, "__doc__", None) or ""
            if not _norm(doc):
                add("card_missing", agent_id,
                    "class docstring (the /team/ card) is empty")
            elif len(_norm(doc)) > card_doc_limit:
                add("card_overlength", agent_id,
                    "docstring is %d chars > cap %d"
                    % (len(_norm(doc)), card_doc_limit))
    if repo_root is not None:
        checks_run += list(_FILE_CHECKS)

    # --- registry descriptions ----------------------------------------------
    seen: Dict[str, List[str]] = {}
    for agent_id in sorted(registry):
        description = _norm(str(registry[agent_id]["description"]))
        if not description:
            add("description_missing", agent_id,
                "registry description is empty")
        else:
            seen.setdefault(description.lower(), []).append(agent_id)
    for description, agent_ids in sorted(seen.items()):
        if len(agent_ids) > 1:
            add("description_duplicate", ", ".join(agent_ids),
                "%d agents share the description %r" % (len(agent_ids),
                                                        description))

    # --- Test Coverage Summary vs quick-ref rows ----------------------------
    by_category: Dict[str, int] = {}
    for row in quick_ref.values():
        category = _norm(str(row["category"])).lower()
        by_category[category] = by_category.get(category, 0) + 1
    for name, agents in sorted(summary["categories"].items()):  # type: ignore
        count = by_category.pop(_norm(name).lower(), 0)
        if count != agents:
            add("summary_count_mismatch", None,
                "summary category %r claims %d agents; quick-ref has %d"
                % (name, agents, count))
    for category, count in by_category.items():
        add("summary_count_mismatch", None,
            "quick-ref category %r has %d rows; the summary names it "
            "not" % (category, count))
    total = summary["total"]  # type: ignore
    if total is not None and total != len(quick_ref):
        add("summary_total_mismatch", None,
            "summary total %d agents != %d quick-ref rows"
            % (total, len(quick_ref)))

    findings.sort(key=lambda f: (f["check"], f["agent"] or "", f["detail"]))
    return {
        "tool": "ka-doc-sync",
        "spec": "OPT-79 / KA-079",
        "registry_agents": len(registry),
        "matrix_rows": len(quick_ref),
        "matrix_sections": len(sections),
        "summary_categories": len(summary["categories"]),  # type: ignore
        "checks_run": sorted(set(checks_run)),
        "checks_skipped": sorted(set(checks_skipped)),
        "findings": findings,
        "inconsistencies": len(findings),
        "verdict": "consistent" if not findings else "drift",
    }


def _sections_by_id(sections, modules, module_basenames):
    """Yield (agent_id, section) pairs for id-matched sections."""
    for section in sections:
        path = section["file_path"]
        by_path = [agent_id for agent_id, module_path in modules.items()
                   if path == module_path]
        if len(by_path) == 1:
            yield by_path[0], section
            continue
        by_name = module_basenames.get(str(section["header_file"]), [])
        if path is None and len(by_name) == 1:
            yield by_name[0], section


def live_resolver(agent_id: str) -> Optional[type]:
    """Import the registered agent class by id (library import path).

    Returns the class, or None when the module/attribute import fails -
    the failure becomes a finding instead of a crash. No child-process
    invocation.
    """
    sys.path.insert(0, str(ROOT))
    from agentic_ai.agents.registry import AGENT_REGISTRY
    try:
        module_path, class_name, _, _ = AGENT_REGISTRY[agent_id]
        return getattr(importlib.import_module(module_path), class_name)
    except Exception:  # noqa: BLE001 - unresolvable classes are findings
        return None


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry: build the live report, print it, and exit 0/1."""
    parser = argparse.ArgumentParser(
        description="KA-079 registry/doc sync checker (read-only)")
    parser.add_argument("--matrix", default=str(MATRIX_PATH),
                        help="AGENT_MATRIX.md path (default: the repo doc)")
    parser.add_argument("--json", action="store_true",
                        help="print the full report as JSON")
    parser.add_argument("--no-cards", action="store_true",
                        help="skip importing agent modules for card checks")
    parser.add_argument("--repo", default=str(ROOT),
                        help="repo root for section-tests-file checks")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT))
    from agentic_ai.agents.registry import list_agents

    resolver = None if args.no_cards else live_resolver
    report = build_report(list_agents(), Path(args.matrix).read_text(
        encoding="utf-8"), repo_root=Path(args.repo), resolver=resolver)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("KA-079 registry/doc sync: %s"
              % report["verdict"])
        print("registry=%d matrix_rows=%d sections=%d summary_categories=%d"
              % (report["registry_agents"], report["matrix_rows"],
                 report["matrix_sections"], report["summary_categories"]))
        print("findings=%d (skipped checks: %s)"
              % (report["inconsistencies"],
                 ",".join(report["checks_skipped"]) or "none"))
        for finding in report["findings"]:  # type: ignore
            print("- [%s] %s: %s" % (finding["check"],
                                     finding["agent"] or "-",
                                     finding["detail"]))
    return 0 if report["verdict"] == "consistent" else 1


if __name__ == "__main__":
    raise SystemExit(main())
