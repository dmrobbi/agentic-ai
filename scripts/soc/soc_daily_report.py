#!/usr/bin/env python3
"""SOC daily report — summarize Wazuh alerts from the last 24h.

Queries the OpenSearch indexer (`wazuh-alerts-*`) for the last 24 hours,
groups by:
  - severity (critical / high / medium / low / informational)
  - top 10 agents by alert count
  - top 10 rules by alert count
  - any level >= 10 (high/critical) that should have triggered an incident

Writes:
  - `memory/soc-daily-YYYY-MM-DD.md` (long form, human-readable)
  - stdout: short webchat summary (also returns the markdown for piping)

Configuration via env:
  WAZUH_INDEXER_URL       default https://127.0.0.1:9200
  WAZUH_INDEXER_USERNAME   default admin
  WAZUH_INDEXER_PASSWORD   default SecretPassword (thing1 single-node)
  REPORT_DIR               default /home/wez/.openclaw/workspace/memory

Usage:
  python3 scripts/soc/soc_daily_report.py                # last 24h
  python3 scripts/soc/soc_daily_report.py --hours 6      # last 6h
  python3 scripts/soc/soc_daily_report.py --stdout-only  # don't write file
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add repo root to sys.path so we can import agentic_ai without install
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from agentic_ai.infrastructure.utils import utcnow
from agentic_ai.infrastructure.wazuh_client import (
    WazuhIndexerClient,
    map_level_to_severity,
)


REPORT_DIR = Path(os.environ.get(
    "REPORT_DIR",
    "/home/wez/.openclaw/workspace/memory",
))


def _query_range(since_iso: str) -> Dict[str, Any]:
    return {"range": {"@timestamp": {"gte": since_iso}}}


def fetch_recent_alerts(idx: WazuhIndexerClient, since_iso: str, size: int = 10000) -> List[Dict[str, Any]]:
    """Pull up to `size` alerts since `since_iso` from the indexer.

    Uses a single big sort by @timestamp asc so the per-day counter works.
    For very large days we may need to paginate; for now 10k is plenty.
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": _query_range(since_iso),
    }
    resp = idx._request("POST", "/wazuh-alerts*/_search", json_body=body)
    hits = (resp.get("hits") or {}).get("hits") or []
    return [h.get("_source", {}) for h in hits]


def summarize(alerts: List[Dict[str, Any]], hours: int) -> Dict[str, Any]:
    by_sev: Counter = Counter()
    by_agent: Counter = Counter()
    by_rule: Counter = Counter()
    high_critical: List[Dict[str, Any]] = []
    earliest = None
    latest = None

    for a in alerts:
        rule = a.get("rule") or {}
        agent = a.get("agent") or {}
        ts = a.get("@timestamp") or a.get("timestamp")
        if ts:
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0
        sev = map_level_to_severity(level)
        by_sev[sev] += 1
        by_agent[agent.get("name") or agent.get("id", "unknown")] += 1
        rule_key = f"{rule.get('id', '?')}: {rule.get('description', '?')[:80]}"
        by_rule[rule_key] += 1
        if level >= 10:
            high_critical.append({
                "timestamp": ts,
                "level": level,
                "rule_id": rule.get("id", "?"),
                "rule_desc": rule.get("description", "?"),
                "agent": agent.get("name", "?"),
                "srcip": (a.get("data") or {}).get("srcip"),
            })

    return {
        "total": len(alerts),
        "by_severity": dict(by_sev),
        "top_agents": by_agent.most_common(10),
        "top_rules": by_rule.most_common(10),
        "high_critical": sorted(high_critical, key=lambda x: x.get("timestamp") or "")[-20:],
        "earliest": earliest,
        "latest": latest,
        "hours": hours,
    }


def run_pipeline_selftest(
    target: str = "192.168.1.151",
    attempts: int = 10,
    timeout_sec: int = 90,
) -> Dict[str, Any]:
    """Invoke the SOC pipeline self-test as a smoke check.

    Delegates to `soc_pipeline_selftest.py` (the synthetic-injection
    harness installed 2026-08-09 by Ciceron). That harness uses the
    *real* integration daemon in the Wazuh manager container, which
    is the only thing the SOC actually depends on — it doesn't need
    password auth on any host.

    Returns a dict with:
      - ok (bool): did it end-to-end succeed?
      - rc (int): subprocess exit code
      - soc_severity (str|None): severity the SOC agent assigned
      - soc_alert_created (bool): was a SecurityAlert created?
      - soc_incident_created (bool): was an IncidentReport created?
      - soc_narrative_present (bool): did soc-narrator fill the narrative?
      - soc_decision_present (bool): did soc-triage fill the decision?
      - tag (str|None): run identifier
      - stderr_excerpt (str): last 600 chars of stderr for debugging
      - stdout_excerpt (str): last 600 chars of stdout
      - duration_sec (float)
      - note (str): human summary line for the report

    We DON'T fail the daily report if the selftest fails — we just
    attach the result so an operator can see "the alert pipeline is
    broken" alongside the alerts that supposedly flowed through it.
    """
    import subprocess as _sp
    script = Path(__file__).parent / "soc_pipeline_selftest.py"
    started = time.time()
    try:
        proc = _sp.run(
            [sys.executable, str(script),
             "--mode", "synthetic",
             "--timeout", str(timeout_sec)],
            capture_output=True, text=True,
            timeout=timeout_sec + 90,  # integration daemon + JSONL wait
        )
        duration = time.time() - started
        out = proc.stdout or ""
        err = proc.stderr or ""

        def _grep(pattern: str, text: str = out) -> str | None:
            import re as _re
            m = _re.search(pattern, text)
            return m.group(1) if m else None

        tag = _grep(r"tag\s+=\s+(\S+)")
        alert_id = _grep(r"alert_id\s+=\s+(\S+)")
        incident_id = _grep(r"incident_id\s+=\s+(\S+)")
        severity = _grep(r"severity\s+=\s+(\S+)")
        all_good = "[ALL GOOD]" in out

        ok = proc.returncode == 0 and all_good
        # NOTE: don't include the emoji in the note text — the rendered
        # section adds one before the bold so we don't get "✅ **✅ ...**".
        note = (
            f"pipeline self-test PASSED "
            f"(alert={alert_id} incident={incident_id} sev={severity})"
            if ok else
            f"pipeline self-test FAILED (rc={proc.returncode}, "
            f"alert={alert_id}, see stderr)"
        )
        return {
            "ok": ok,
            "rc": proc.returncode,
            "attempts": attempts,
            "wazuh_rule_id": str(SYNTHETIC_RULE_ID),  # 40112
            "wazuh_level": SYNTHETIC_RULE_LEVEL,
            "soc_severity": severity,
            "soc_alert_created": alert_id is not None,
            "soc_incident_created": incident_id is not None,
            "soc_narrative_present": "agentic_narrative" in out,
            "soc_decision_present": "agentic_decision" in out,
            "tag": tag,
            "stderr_excerpt": err[-600:] if err else "",
            "stdout_excerpt": out[-600:] if out else "",
            "duration_sec": round(duration, 1),
            "note": note,
        }
    except _sp.TimeoutExpired:
        return {
            "ok": False,
            "rc": -1,
            "note": f"pipeline self-test TIMED OUT after {timeout_sec+90}s",
            "duration_sec": round(time.time() - started, 1),
        }
    except Exception as e:
        return {
            "ok": False,
            "rc": -1,
            "note": f"pipeline self-test crashed: {type(e).__name__}: {e}",
            "duration_sec": round(time.time() - started, 1),
        }

# Synthetic-alert constants used by the new self-test harness
# (also referenced by the rendered note so the report stays readable).
SYNTHETIC_RULE_ID = 40112
SYNTHETIC_RULE_LEVEL = 12


def render_markdown(s: Dict[str, Any], when: datetime, selftest: Optional[Dict[str, Any]] = None) -> str:
    sev_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🔵",
        "informational": "⚪",
    }
    lines = []
    lines.append(f"# SOC Daily Report — {when.strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append(f"_Window: last **{s['hours']}h** "
                 f"({s['earliest']} → {s['latest']})_")
    lines.append("")
    lines.append(f"**Total alerts: {s['total']}**")
    lines.append("")
    lines.append("## By severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = s["by_severity"].get(sev, 0)
        if n:
            lines.append(f"| {sev_emoji.get(sev,'')} {sev} | {n} |")
    lines.append("")
    lines.append("## Top 10 agents")
    lines.append("")
    lines.append("| Agent | Alerts |")
    lines.append("|---|---:|")
    for name, n in s["top_agents"]:
        lines.append(f"| `{name}` | {n} |")
    lines.append("")
    lines.append("## Top 10 rules")
    lines.append("")
    lines.append("| Rule | Count |")
    lines.append("|---|---:|")
    for rule, n in s["top_rules"]:
        # Escape pipe characters in the rule description
        rule_safe = rule.replace("|", "\\|")
        lines.append(f"| {rule_safe} | {n} |")
    lines.append("")
    if s["high_critical"]:
        lines.append(f"## High/Critical (level ≥ 10): {len(s['high_critical'])} alerts")
        lines.append("")
        lines.append("| Time | Lvl | Agent | Rule | Source IP |")
        lines.append("|---|---:|---|---|---|")
        for h in s["high_critical"][-20:]:
            ts = h.get("timestamp", "?")
            lvl = h.get("level", "?")
            ag = h.get("agent", "?")
            rid = h.get("rule_id", "?")
            rdesc = (h.get("rule_desc", "?") or "?")[:60].replace("|", "\\|")
            ip = h.get("srcip") or "-"
            lines.append(f"| {ts} | {lvl} | `{ag}` | {rid} {rdesc} | `{ip}` |")
        lines.append("")
    else:
        lines.append("## High/Critical (level ≥ 10): none")
        lines.append("")
    if selftest:
        lines.append("## Pipeline self-test (synthetic Wazuh alert → integration daemon → SOC)")
        lines.append("")
        emoji = "✅" if selftest.get("ok") else "⚠️"
        lines.append(f"{emoji} **{selftest.get('note', 'no result')}**")
        lines.append("")
        lines.append(f"- duration: {selftest.get('duration_sec', '?')}s")
        lines.append(f"- tag: `{selftest.get('tag', '?')}`")
        if selftest.get("wazuh_rule_id"):
            lines.append(f"- Wazuh alert: rule={selftest.get('wazuh_rule_id')} "
                         f"level={selftest.get('wazuh_level')} (synthetic, via "
                         f"agentic-soc-send.py in {os.environ.get('WAZUH_MANAGER_CONTAINER', 'wazuh-stack-wazuh.manager-1')})")
        lines.append(f"- SOC ingested: alert={selftest.get('soc_alert_created')}, "
                     f"incident={selftest.get('soc_incident_created')}, "
                     f"severity={selftest.get('soc_severity')}")
        lines.append(f"- SOC enrichment: narrative={selftest.get('soc_narrative_present')}, "
                     f"decision={selftest.get('soc_decision_present')}")
        if not selftest.get("ok") and selftest.get("stderr_excerpt"):
            lines.append("")
            lines.append("<details><summary>stderr excerpt</summary>")
            lines.append("")
            lines.append("```")
            lines.append(selftest["stderr_excerpt"].strip())
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        lines.append("")
    return "\n".join(lines)


def render_short_summary(s: Dict[str, Any], when: datetime, selftest: Optional[Dict[str, Any]] = None) -> str:
    """One-screen summary suitable for webchat / Signal / Telegram."""
    parts = []
    parts.append(f"📊 **SOC Daily Report — {when.strftime('%Y-%m-%d')}** (last {s['hours']}h)")
    parts.append(f"  total: **{s['total']}** alerts")
    sev_bits = []
    for sev in ("critical", "high", "medium", "low"):
        n = s["by_severity"].get(sev, 0)
        if n:
            sev_bits.append(f"{n} {sev}")
    if sev_bits:
        parts.append(f"  by severity: {', '.join(sev_bits)}")
    if s["top_agents"]:
        top3 = ", ".join(f"`{n}`={c}" for n, c in s["top_agents"][:3])
        parts.append(f"  top agents: {top3}")
    if s["high_critical"]:
        parts.append(f"  🚨 {len(s['high_critical'])} high/critical alert(s) (level ≥ 10)")
    else:
        parts.append(f"  ✅ no high/critical alerts")
    if selftest:
        emoji = "✅" if selftest.get("ok") else "⚠️"
        # short note for webchat — strip leading emoji if present (the
        # emoji we add here is the only one we want).
        short_note = (selftest.get("note") or "?").lstrip("✅⚠️ ").strip()
        parts.append(f"  {emoji} pipeline self-test: {short_note}")
    return "\n".join(parts)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hours", type=int, default=24, help="lookback window (default 24)")
    p.add_argument("--stdout-only", action="store_true",
                   help="print summary but don't write the markdown report file")
    p.add_argument("--selftest", action="store_true",
                   help="run the benign SSH brute-force end-to-end pipeline test "
                        "BEFORE generating the report, and include its result")
    p.add_argument("--selftest-target", default="192.168.1.151",
                   help="target host for the selftest (default: 192.168.1.151 = rpi42)")
    p.add_argument("--selftest-attempts", type=int, default=10,
                   help="bad-password attempts for the selftest (default: 10)")
    p.add_argument("--selftest-timeout", type=int, default=90,
                   help="seconds to wait for the Wazuh alert (default: 90)")
    args = p.parse_args()

    selftest_result: Optional[Dict[str, Any]] = None
    if args.selftest:
        print(f"[*] running pipeline self-test against {args.selftest_target}...",
              file=sys.stderr)
        selftest_result = run_pipeline_selftest(
            target=args.selftest_target,
            attempts=args.selftest_attempts,
            timeout_sec=args.selftest_timeout,
        )
        print(f"[*] selftest result: {selftest_result['note']}", file=sys.stderr)

    idx = WazuhIndexerClient(
        base_url=os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200"),
        username=os.environ.get("WAZUH_INDEXER_USERNAME", "admin"),
        password=os.environ.get("WAZUH_INDEXER_PASSWORD", "SecretPassword"),
        verify_ssl=False,
    )
    now = utcnow()
    since = now - timedelta(hours=args.hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"[*] querying wazuh-alerts-* since {since_iso}", file=sys.stderr)
    alerts = fetch_recent_alerts(idx, since_iso)
    print(f"[*] got {len(alerts)} alerts", file=sys.stderr)

    s = summarize(alerts, args.hours)
    md = render_markdown(s, now, selftest=selftest_result)
    short = render_short_summary(s, now, selftest=selftest_result)

    if not args.stdout_only:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        out = REPORT_DIR / f"soc-daily-{now.strftime('%Y-%m-%d')}.md"
        out.write_text(md)
        # also print the path
        print(f"[*] wrote {out}", file=sys.stderr)

    # The short summary on stdout is what the cron job pipes into the chat.
    print(short)

    # Exit non-zero if the selftest ran and failed — so cron can alert.
    if args.selftest and selftest_result and not selftest_result.get("ok"):
        print("[!] pipeline self-test FAILED — exiting 2 so cron can alert",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
