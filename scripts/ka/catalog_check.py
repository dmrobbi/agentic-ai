#!/usr/bin/env python3
"""KA-023 - catalog link-rotation check.

OFFLINE (default; CI-safe; no network): both generated tool catalogs
load, every row keeps name/purpose/url with well-formed http(s) URLs,
and the counted phase/tool totals match the catalogs' own meta.

LIVE (--live; opt-in; never in CI): fetch every catalog URL; dead links
are flagged into a report file (--report, default ka_catalog_links_report.txt).
Exit 0 when green (offline green, or live with zero dead links); 1 when
live finds dead links."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
CATALOGS = {
    "redteam": ROOT / "agentic_ai/agents/cyber/data/redteam_tools.json",
    "xss": ROOT / "agentic_ai/agents/cyber/data/xss_tools.json",
}
UA = "Mozilla/5.0 (compatible; ka-catalog-check/1.0)"


def catalog_facts(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    total_tools = sum(
        len(e["tools"]) for e in data["phases"].values() if e.get("tools"))
    return {
        "path": path, "data": data, "phases": len(data["phases"]),
        "tools": total_tools,
        "meta_phases": data["meta"]["totals"]["phases"],
        "meta_tools": data["meta"]["totals"]["tools"],
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def check_catalog(facts: dict) -> list:
    problems = []
    facts_data = facts
    if facts_data["phases"] != facts_data["meta_phases"]:
        problems.append("%s: phases %d != meta %d"
                        % (facts_data["path"].name, facts_data["phases"],
                           facts_data["meta_phases"]))
    if facts_data["tools"] != facts_data["meta_tools"]:
        problems.append("%s: tools %d != meta %d"
                        % (facts_data["path"].name, facts_data["tools"],
                           facts_data["meta_tools"]))
    for phase, entry in sorted(facts_data["data"]["phases"].items()):
        for row in entry["tools"]:
            if not (row["name"] or "").strip():
                problems.append("%s/%s: empty name"
                                % (phase, row.get("url", "?")))
            if not (row["url"] or "").startswith(("http://", "https://")):
                problems.append("%s/%s: url not http(s): %r"
                                % (phase, row["name"], row["url"]))
                continue
            if urlsplit(row["url"]).netloc == "":
                problems.append("%s/%s: url has no netloc: %r"
                                % (phase, row["name"], row["url"]))
    return problems


def write_report(dead_rows: list, path: Path) -> None:
    lines = [
        "# KA-023 catalog link report",
        "",
        "generated_utc: (filled by the caller)",
        "dead_links: %d" % len(dead_rows),
        "",
        "| catalog | phase | tool | url | problem |",
        "|---|---|---|---|---|",
    ]
    for row in dead_rows:
        lines.append("| %s | %s | %s | %s | %s |" % (
            row.get("catalog", "?"), row.get("phase", "?"),
            row.get("name", "?"), row.get("url", "?"),
            row.get("problem", "?")))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true",
                        help="opt-in: fetch every catalog URL; never in CI")
    parser.add_argument("--report", default="ka_catalog_links_report.txt",
                        help="path for the live-mode dead-link report")
    args = parser.parse_args()

    facts = {name: catalog_facts(path) for name, path in CATALOGS.items()}
    problems = []
    for name, fx in sorted(facts.items()):
        problems.extend(check_catalog(fx))

    if args.live and not problems:
        import requests  # lazy: the offline path never imports it

        dead_rows = []
        for name, fx in sorted(facts.items()):
            for phase, entry in sorted(fx["data"]["phases"].items()):
                for row in entry["tools"]:
                    try:
                        response = requests.get(
                            row["url"], timeout=20, headers={"User-Agent": UA})
                        problem = None if response.status_code == 200 else (
                            "HTTP %d" % response.status_code)
                    except Exception as exc:
                        problem = type(exc).__name__ + ": " + str(exc)[:120]
                    if problem:
                        dead_rows.append({
                            "catalog": name, "phase": phase,
                            "name": row["name"], "url": row["url"],
                            "problem": problem})
        write_report(dead_rows, Path(args.report))
        print("CATALOG-CHECK-LIVE dead=%d report=%s"
              % (len(dead_rows), args.report))
        return 1 if dead_rows else 0

    if problems:
        for problem in problems:
            print("PROBLEM:", problem)
        print("CATALOG-CHECK-BAD problems=%d" % len(problems))
        return 1
    total = sum(fx["tools"] for fx in facts.values())
    print("CATALOG-CHECK-OK catalogs=%d tools=%d"
          % (len(CATALOGS), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
