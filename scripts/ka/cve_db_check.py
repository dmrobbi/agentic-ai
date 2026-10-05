#!/usr/bin/env python3
"""KA-012 - CVE_EXPLOIT_DB staleness gate.

OFFLINE (default; CI-safe; no network): every DB entry's references
resolve structurally - EDB ids are well-formed positive integers with
derivably-correct URLs, metasploit module paths are plausible
(exploit/<os>/<vector>/<name>), reliability stays in the known bands,
ranks stay 1-5, disclosure dates parse, ports are int-or-None. The DB
itself is the committed mirror; nothing external is touched.

LIVE (--live; opt-in; NEVER in CI; a nightly schedule is a P5
decision): additionally fetch every EDB URL and require HTTP 200.

Prints CVE-DB-CHECK-OK rows=<n> on green (an automation-gate marker).
Exit 0 green, 1 stale/broken."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_ai.agents.cyber.kali_v2 import CVE_EXPLOIT_DB  # noqa: E402

RELIABILITY_BANDS = {"excellent", "great", "good", "normal", "low", "manual"}


def edb_url(exploit_db_id: str) -> str:
    return "https://www.exploit-db.com/exploits/" + str(exploit_db_id)


def check_entry(cve_id: str, row) -> list:
    problems = []
    if row.cve_id != cve_id:
        problems.append("row key/cve_id mismatch: %r" % cve_id)
    if not (row.description or "").strip():
        problems.append("empty description")
    if (row.exploit_db_id or "") and not str(row.exploit_db_id).isdigit():
        problems.append("exploit_db_id not numeric: %r" % row.exploit_db_id)
    module = row.metasploit_module or ""
    if module:
        parts = module.split("/")
        if len(parts) < 3 or parts[0] != "exploit":
            problems.append("malformed metasploit_module: %r" % module)
    if row.reliability not in RELIABILITY_BANDS:
        problems.append("unknown reliability: %r" % row.reliability)
    if not (1 <= row.rank <= 5):
        problems.append("rank out of range: %r" % row.rank)
    try:
        date.fromisoformat(row.disclosure_date)
    except (ValueError, TypeError):
        problems.append("unparsable disclosure_date: %r" % row.disclosure_date)
    if row.port is not None and not isinstance(row.port, int):
        problems.append("port not int-or-None: %r" % row.port)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true",
                        help="opt-in: fetch every EDB URL (never in CI)")
    args = parser.parse_args()

    problems = []
    for cve_id, row in sorted(CVE_EXPLOIT_DB.items()):
        entry_problems = check_entry(cve_id, row)
        problems.extend("%s: %s" % (cve_id, p) for p in entry_problems)

    if args.live and not problems:
        import requests  # lazy: the offline path never imports it

        for cve_id, row in sorted(CVE_EXPLOIT_DB.items()):
            if not row.exploit_db_id:
                continue
            url = edb_url(row.exploit_db_id)
            try:
                response = requests.get(url, timeout=20)
            except Exception as exc:
                problems.append("%s: live fetch failed: %s" % (cve_id, exc))
                continue
            if response.status_code != 200:
                problems.append("%s: EDB %r -> HTTP %d"
                                % (cve_id, row.exploit_db_id,
                                   response.status_code))

    if problems:
        for problem in problems:
            print("STALE:", problem)
        print("CVE-DB-CHECK-STALE rows=%d problems=%d"
              % (len(CVE_EXPLOIT_DB), len(problems)))
        return 1
    print("CVE-DB-CHECK-OK rows=%d" % len(CVE_EXPLOIT_DB))
    return 0


if __name__ == "__main__":
    sys.exit(main())
