"""Laya-loop replay eval (KA-021): replay flagged-alert audit rows
through CVE-matching + planning, and emit a MEASURED precision report.
Pure planner: the audit rows come from committed fixtures/the caller;
the live SOC pull is a P5 wiring decision; nothing here executes.

CONTRACT:
- replay_flagged(rows, matcher=None): rows = the laya_gated_decision
  audit rows (dicts: ts/kind/alert_id/severity/model/outcome/duration_ms/
  detail). The cve cargo = the CVE tokens found in the row's detail text.
  Per row out: {"alert_id", "ts", "cves", "matches" (DB-known only:
  {cve, exploit_name, metasploit_module, port, rank}),
  "suggested_next_steps" (planner strings for matched rows only)}.
- precision(result): {"rows", "rows_with_cve_cargo", "rows_matched",
  "match_rate", "overall_flag_rate"} - the MEASURED numbers.
- render_report(result): fills REPORT_TEMPLATE (documented; the gap
  rows = a straight pointer to KA-029's expansion queue).
- The matcher default imports LAZILY (module-level chassis imports
  would cycle the way they did for the bridges)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

CVE_RE = r"CVE-\d{4}-\d+"


def _extract_cves(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    found = re.findall(CVE_RE, text)
    seen, out = set(), []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def replay_flagged(rows: Iterable[Dict[str, Any]], matcher=None) -> Dict[str, Any]:
    """Replay flagged audit rows: extract the cve cargo per row, match
    via the (lazily-defaulted) engine, plan planner-only next steps."""
    if matcher is None:
        # lazy default: a module-level import would cycle with the v2
        # chassis once its ops land (the bridge lesson, applied)
        from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine
        matcher = CVEMatchingEngine()

    out_rows: List[Dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        detail = row.get("detail") if isinstance(row.get("detail"), str) else ""
        cves = _extract_cves(detail)
        matches = []
        steps: List[str] = []
        for cve in cves:
            match = matcher.match_cve(cve)
            if match:
                matches.append({
                    "cve": cve,
                    "exploit_name": match.exploit_name,
                    "metasploit_module": match.metasploit_module,
                    "port": match.port,
                    "rank": match.rank,
                })
                steps.append("searchsploit %s" % match.exploit_name)
                steps.append(
                    "verify %s against the flagged asset's patch level "
                    "(laya flagged; human confirms)" % cve)
            else:
                steps.append(
                    "no internal exploit for %s - file into the KA-029 "
                    "expansion queue" % cve)
        out_rows.append({
            "alert_id": row.get("alert_id", ""),
            "ts": row.get("ts", ""),
            "cves": cves,
            "matches": matches,
            "suggested_next_steps": steps,
        })
    return {"rows": out_rows}


def precision(result: Dict[str, Any]) -> Dict[str, Any]:
    rows = result.get("rows", [])
    with_cargo = [r for r in rows if r["cves"]]
    matched = [r for r in rows if r["matches"]]
    return {
        "rows": len(rows),
        "rows_with_cve_cargo": len(with_cargo),
        "rows_matched": len(matched),
        "match_rate": (len(matched) / len(with_cargo)) if with_cargo else 0.0,
        "overall_flag_rate": (len(matched) / len(rows)) if rows else 0.0,
    }


REPORT_TEMPLATE = """# laya-loop replay precision report

rows replayed: {rows}
rows with CVE cargo: {with_cves}
rows with a DB-known match: {matched}
match rate (of cve-cargo rows): {match_rate:.2f}
overall flagged-to-matched rate: {flagged_rate:.2f}

| alert_id | cve | exploit | module | next steps |
|---|---|---|---|---|
{table_rows}

(cves with null exploits = gap rows: file them into the KA-029 expansion queue)
"""


def render_report(result: Dict[str, Any]) -> str:
    numbers = precision(result)
    table_rows = []
    for row in result.get("rows", []):
        if not row["matches"]:
            continue
        for match in row["matches"]:
            table_rows.append("| %s | %s | %s | %s | %d |" % (
                row["alert_id"], match["cve"], match["exploit_name"],
                match["metasploit_module"] or "(none)",
                len(row["suggested_next_steps"])))
    return REPORT_TEMPLATE.format(
        rows=numbers["rows"], with_cves=numbers["rows_with_cve_cargo"],
        matched=numbers["rows_matched"],
        match_rate=numbers["match_rate"],
        flagged_rate=numbers["overall_flag_rate"],
        table_rows="\n".join(table_rows))
