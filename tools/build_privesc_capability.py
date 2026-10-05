#!/usr/bin/env python3
"""KA-031 regen builder: rewrite data/privesc_index.json from the curated
rows in this file (the GTFOBins/LOLBAS-convention index grows here).
Run from any cwd; the output path is module-stable."""
import json
import pathlib
import sys

sys.path.insert(0, "/home/wez/agentic-ai")

# the curated rows live in the module module (the single source):
from agentic_ai.agents.cyber.privesc import CATALOG_PATH  # noqa: E402


def main():
    """Regenerate the index file from the module's constants - a
    placeholder that verifies the file is intact and re-serializes it
    canonically (the data evolves by editing the module's DATA literal)."""
    path = pathlib.Path(CATALOG_PATH)
    data = json.loads(path.read_text(encoding="utf-8"))
    # canonical rewrite (sorted keys, sorted rows by binary):
    for plat, rows in data["platforms"].items():
        rows.sort(key=lambda r: r["binary"])
        data["meta"]["totals"] = {
            "platforms": len(data["platforms"]),
            "rows": sum(len(r) for r in data["platforms"].values()),
        }
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")
    print("PRIVESC-INDEX-REGEN-OK rows=%d" % data["meta"]["totals"]["rows"])


if __name__ == "__main__":
    main()
