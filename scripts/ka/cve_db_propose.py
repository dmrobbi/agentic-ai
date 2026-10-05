#!/usr/bin/env python3
"""KA-029 - CVE-DB expansion pipeline: the KEV feed's newest-30d entries
become PROPOSAL rows for human review. The CVE_EXPLOIT_DB is NEVER
touched here - the separation is the whole point; the generated review
queue (markdown) is the deliverable.

Usage:
  cve_db_propose.py --feed PATH [--queue PATH] [--as-of YYYY-MM-DD]
    feed   a JSON carrying {"entries": [...]} (the kevstig snapshot
           shape) or {"vulnerabilities": [...]} (the raw CISA KEV feed
           shape); both accepted.
    queue  default docs/KA-CVE-DB-REVIEW-QUEUE.md - CWD-relative: run
           from the repo root for the default location.
    as-of  default = today (UTC); the window = the last 30 days.

Prints CVE-DB-PROPOSE-OK proposals=N skipped=M (an automation marker).
A duplicate cve, a malformed cve/date, and outside-window rows all land
in the skipped tally with reasons. Exit 0 on any clean run (0 proposals
is still green); 1 on a feed you cannot read/pars"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_ai.infrastructure.utils import utcnow  # noqa: E402

CVE_RE = r"CVE-\d{4}-\d+"


def note_urls(note: str) -> list:
    return re.findall(r"https?://\S+", note or "")


def build_proposals(entries: list, as_of: date,
                    source_label: str = "kev-30d") -> tuple:
    cutoff = as_of - timedelta(days=30)
    proposals, skipped, seen = [], [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            skipped.append({"cve": "?", "reason": "row not a dict"})
            continue
        cve = entry.get("cve")
        if not isinstance(cve, str) or not re.fullmatch(CVE_RE, cve):
            skipped.append({"cve": str(cve), "reason": "cve malformed"})
            continue
        try:
            added = date.fromisoformat(str(entry.get("dateAdded", "")))
        except ValueError:
            skipped.append({"cve": cve, "reason": "dateAdded malformed"})
            continue
        if added < cutoff:
            skipped.append({"cve": cve, "reason": "outside 30d window"})
            continue
        if cve in seen:
            skipped.append({"cve": cve, "reason": "duplicate"})
            continue
        seen.add(cve)
        proposals.append({
            "cve": cve,
            "dateAdded": entry.get("dateAdded"),
            "vendor": entry.get("vendor") or "",
            "product": entry.get("product") or "",
            "name": entry.get("name") or "",
            "references": note_urls(entry.get("note") or ""),
            "proposed_at": utcnow().isoformat(),
            "status": "pending-review",
            "review_decision": None,
            "source": source_label,
        })
    return proposals, skipped


def render_queue(proposals: list, as_of: date) -> str:
    lines = [
        "# KA-CVE-DB review queue (KA-029 generated)",
        "",
        "as_of: %s   window: %s..%s   human review required before any"
        % (as_of.isoformat(), (as_of - timedelta(days=30)).isoformat(),
           as_of.isoformat()),
        " CVE_EXPLOIT_DB row lands; decisions: approve / reject / park.",
        "",
        "| cve | dateAdded | vendor | product | references | status |",
        "|---|---|---|---|---|---|",
    ]
    if not proposals:
        lines.append("| (empty queue) | | | | | |")
    for p in proposals:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            p["cve"], p["dateAdded"], p["vendor"],
            (p["vendor"] + " " + p["product"]).strip() or p["product"],
            " <br>".join(p["references"]) or "(none)",
            p["status"]))
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--feed", required=True, help="KEV feed JSON path")
    parser.add_argument("--queue", default="docs/KA-CVE-DB-REVIEW-QUEUE.md")
    parser.add_argument("--as-of", default=None, help="YYYY-MM-DD; default today")
    args = parser.parse_args()

    try:
        feed = json.loads(Path(args.feed).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print("CVE-DB-PROPOSE-BAD feed unparsable: %s" % exc)
        return 1

    entries = feed.get("entries") or feed.get("vulnerabilities") or []
    as_of = date.fromisoformat(args.as_of) if args.as_of else utcnow().date()
    proposals, skipped = build_proposals(entries, as_of)
    queue = render_queue(proposals, as_of)
    queue_path = Path(args.queue)
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    queue_path.write_text(queue, encoding="utf-8")

    print("CVE-DB-PROPOSE-OK proposals=%d skipped=%d queue=%s"
          % (len(proposals), len(skipped), queue_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
