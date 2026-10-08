#!/usr/bin/env python3
"""Build agentic_ai/agents/cyber/data/kali_packages.json - the tool
universe transplanted from the removed kali_agent_v3 generation (the
owner's 2026-10-08 merge order: salvage the transplantable work, then
the dead code goes).

The source is pinned in git HISTORY so the builder stays runnable after
the removal: `git show <commit>:<path>` - commit c965747,
kali_agent_v3/core/tools_db_600_plus.json, the 602-tool database
(fields: package, category, desc, mb, priority, tags).

The build is a validating verbatim round-trip: every row must carry the
exact 6-field schema (strings for package/category/desc, string-list
tags, non-negative number mb, priority 1-10) and the content passes
through UNMUTED - the doctor op (package_doctor.package_universe_rows)
does the hygiene, the transplant stays byte-faithful to the source era.
Output = canonical json round-trip (indent 2, ensure_ascii False,
sorted nothing, trailing newline).

Usage:
  python tools/build_kali_packages.py            (rebuild)
  python tools/build_kali_packages.py --verify   (rebuild + byte-compare
      against the committed file; prints KALI-UNIVERSE-VERIFY-OK and
      exits 0 on match, non-zero otherwise)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = (REPO_ROOT / "agentic_ai" / "agents" / "cyber" / "data"
       / "kali_packages.json")

COMMIT = "c965747"
SOURCE_PATH = "kali_agent_v3/core/tools_db_600_plus.json"
FIELDS = {"category", "desc", "mb", "package", "priority", "tags"}
EXPECTED_ROWS = 602


def load_source() -> dict:
    """Pinned-history extract + full schema validation (loud, fatal)."""
    raw = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", "%s:%s" % (COMMIT, SOURCE_PATH)],
        capture_output=True, check=True,
    ).stdout
    db = json.loads(raw.decode("utf-8"))
    if not isinstance(db, dict) or len(db) != EXPECTED_ROWS:
        raise SystemExit(
            "source is not the expected %d-tool mapping" % EXPECTED_ROWS)
    for key, row in db.items():
        if not isinstance(key, str) or not key.strip():
            raise SystemExit("bad key: %r" % (key,))
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise SystemExit(
                "row %r does not carry exactly %s" % (key, sorted(FIELDS)))
        for field in ("category", "desc", "package"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise SystemExit(
                    "row %r field %r is not a non-blank string"
                    % (key, field))
        if not isinstance(row["tags"], list) or not all(
                isinstance(tag, str) for tag in row["tags"]):
            raise SystemExit("row %r tags is not a string list" % key)
        if isinstance(row["mb"], bool) or not isinstance(row["mb"], (int, float)) \
                or row["mb"] < 0:
            raise SystemExit(
                "row %r mb is not a non-negative number" % key)
        if not isinstance(row["priority"], int) \
                or not 1 <= row["priority"] <= 10:
            raise SystemExit("row %r priority is not an int 1-10" % key)
    return db


def render(db: dict) -> str:
    return json.dumps(db, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    argv = sys.argv[1:]
    db = load_source()
    text = render(db)
    if argv == ["--verify"]:
        current = (OUT.read_text(encoding="utf-8")
                   if OUT.exists() else None)
        if current == text:
            print("KALI-UNIVERSE-VERIFY-OK")
            return 0
        print("KALI-UNIVERSE-VERIFY-DIFF", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print("KALI-UNIVERSE-BUILT %d rows -> %s" % (len(db), OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())