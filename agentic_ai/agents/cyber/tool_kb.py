"""Tool KB one-pagers (KA-087): in-house planning knowledge for the
kali tool registry.

Reads the generated catalog at data/tool_kb.json - emitted by the
committed tools/build_tool_kb.py, never hand-edited - and exposes
read-only one-pager lookups over the registry tool keys:

  tool_kb_get(tool)            one entry dict, or None when unknown
  tool_kb_search(q, cap=25)    ranked, bounded entry dicts
  tool_kb_stats() {"tools": n, "with_patterns": n, "with_notes": n}

Pure planner surface: no execution, no network, no writes; results are
copies so callers cannot mutate the shared catalog.
"""
from __future__ import annotations

import copy
import json
import pathlib

# cyber/ -> agents/ -> agentic_ai/ -> repo root
KB_PATH = (pathlib.Path(__file__).resolve().parents[3]
           / "data" / "tool_kb.json")

SEARCH_DEFAULT_CAP = 25

_ENTRIES: list | None = None


def _entries() -> list:
    """Load the committed catalog once, lazily; the file order is the
    builder's deterministic tool order."""
    global _ENTRIES
    if _ENTRIES is None:
        data = json.loads(KB_PATH.read_text(encoding="utf-8"))
        _ENTRIES = list(data["entries"])
    return _ENTRIES


def _normalized_tool(tool):
    if not isinstance(tool, str):
        return None
    return tool.strip().lower() or None


def tool_kb_get(tool):
    """One-pager for a registry tool key, case-insensitive; None when
    the tool is not in the catalog. Returns a copy."""
    key = _normalized_tool(tool)
    if key is None:
        return None
    for entry in _entries():
        if entry["tool"].lower() == key:
            return copy.deepcopy(entry)
    return None


def _entry_rank(entry, query):
    """Rank of the first field layer that matches: tool key first, then
    package, then purpose, then command patterns, then notes. Bigger
    numbers rank lower."""
    layers = (
        entry["tool"].lower(),
        (entry["package"] or "").lower(),
        entry["purpose"].lower(),
        " ".join(entry["command_patterns"]).lower(),
        entry["false_positive_notes"].lower(),
    )
    for rank, layer in enumerate(layers):
        if query in layer:
            return rank
    return None


def tool_kb_search(query, cap=SEARCH_DEFAULT_CAP):
    """Ranked one-pager search over tool key, package, purpose, command
    patterns and false-positive notes; case-insensitive. Results keep
    catalog order within a rank and are bounded by cap, itself clamped
    to the house cap of 25 (cap <= 0 returns no rows)."""
    if not isinstance(query, str):
        return []
    query = query.strip().lower()
    if not query:
        rows = []
        for entry in _entries():
            rows.append((0, entry))
    else:
        rows = []
        for entry in _entries():
            rank = _entry_rank(entry, query)
            if rank is not None:
                rows.append((rank, entry))
    try:
        cap_int = int(cap)
    except (TypeError, ValueError):
        cap_int = SEARCH_DEFAULT_CAP
    if cap_int <= 0:
        return []
    cap_int = min(cap_int, SEARCH_DEFAULT_CAP)
    rows.sort(key=lambda row: row[0])
    return [copy.deepcopy(entry) for _, entry in rows[:cap_int]]


def tool_kb_stats():
    """Catalog counters: registered one-pagers, how many carry command
    patterns, how many carry false-positive notes."""
    entries = _entries()
    return {
        "tools": len(entries),
        "with_patterns": sum(
            1 for entry in entries if entry["command_patterns"]),
        "with_notes": sum(
            1 for entry in entries
            if str(entry["false_positive_notes"]).strip()),
    }
