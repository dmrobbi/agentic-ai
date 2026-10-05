"""KA-029 - the proposal pipeline: the KEV feed's newest-30d rows
become pending-review proposals; the DB is NEVER touched; both feed
shapes accepted; the window/malformed/duplicate lanes count into
skipped with reasons; the queue renders. The full-run test uses the
committed KA-002 snapshot's 156 routed rows (as-of pinned 2026-10-05:
exactly 2 proposals, 154 skipped). No network anywhere."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agentic_ai.agents.cyber.kali_v2 import CVE_EXPLOIT_DB

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ka" / "cve_db_propose.py"
SNAPSHOT = (REPO / "tests" / "fixtures" / "scans"
            / "kevstig_coverage_snapshot.json")
AS_OF = "2026-10-05"
CUTOFF = "2026-09-05"
EXPECTED_PROPOSALS = ["CVE-2026-81963", "CVE-2026-85880"]


def _run(tmp_path, feed):
    feed_path = tmp_path / "feed.json"
    queue_path = tmp_path / "queue" / "KA-CVE-DB-REVIEW-QUEUE.md"
    feed_path.write_text(json.dumps(feed), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--feed", str(feed_path),
         "--queue", str(queue_path), "--as-of", AS_OF],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    return proc, queue_path


def test_full_run_counts_marker_and_queue(tmp_path):
    feed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    entries = feed["coverage"]["entries"]
    proc, queue = _run(tmp_path, {"entries": entries})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CVE-DB-PROPOSE-OK proposals=2 skipped=154" in proc.stdout
    text = queue.read_text(encoding="utf-8")
    for cve in EXPECTED_PROPOSALS:
        assert cve in text
    assert text.count("pending-review") == 2
    assert "as_of: 2026-10-05" in text
    assert "window: %s..%s" % (CUTOFF, AS_OF) in text


def test_proposal_rows_carry_reference_urls(tmp_path):
    feed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    proc, queue = _run(tmp_path, {"entries": feed["coverage"]["entries"]})
    assert proc.returncode == 0
    text = queue.read_text(encoding="utf-8")
    import re
    urls = re.findall(r"https?://[^\s|<]+", text)
    assert len(urls) >= 6  # the measured reference count for the window


def test_window_boundary_malformed_and_duplicate(tmp_path):
    crafted = {"entries": [
        {"cve": "CVE-2026-0001", "dateAdded": CUTOFF, "vendor": "V",
         "product": "P", "name": "boundary-day included", "note": ""},
        {"cve": "CVE-2026-0002", "dateAdded": "2026-09-04",
         "vendor": "V", "product": "P", "name": "day before cutoff", "note": ""},
        {"cve": "CVE-2026-0003", "dateAdded": "not-a-date", "name": "bad date"},
        {"cve": "NOT-A-CVE", "dateAdded": "2026-10-01", "name": "bad cve"},
        {"cve": "CVE-2026-0001", "dateAdded": "2026-10-01", "name": "dup row"},
    ]}
    proc, queue = _run(tmp_path, crafted)
    assert proc.returncode == 0
    assert "CVE-DB-PROPOSE-OK proposals=1 skipped=4" in proc.stdout
    text = queue.read_text(encoding="utf-8")
    assert "CVE-2026-0001" in text          # the boundary-day proposal
    assert "CVE-2026-0002" not in text      # filtered by the window
    assert "NOT-A-CVE" not in text          # never a row


def test_raw_kev_vulnerabilities_shape_accepted(tmp_path):
    crafted = {"vulnerabilities": [
        {"cve": "CVE-2026-5555", "dateAdded": "2026-10-01", "name": "raw kev"}]}
    proc, queue = _run(tmp_path, crafted)
    assert proc.returncode == 0
    assert "CVE-DB-PROPOSE-OK proposals=1 skipped=0" in proc.stdout
    assert "CVE-2026-5555" in queue.read_text(encoding="utf-8")


def test_empty_feed_zero_proposals(tmp_path):
    proc, queue = _run(tmp_path, {"entries": []})
    assert proc.returncode == 0
    assert "CVE-DB-PROPOSE-OK proposals=0 skipped=0" in proc.stdout
    assert "(empty queue)" in queue.read_text(encoding="utf-8")


def test_db_never_touched_after_runs(tmp_path):
    feed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    entries = feed["coverage"]["entries"]
    before = len(CVE_EXPLOIT_DB)
    proc, _queue = _run(tmp_path, {"entries": entries})
    assert proc.returncode == 0
    assert len(CVE_EXPLOIT_DB) == before == 6


def test_script_is_offline_only():
    source = SCRIPT.read_text(encoding="utf-8")
    for banned in ("import requests", "urllib", "socket", "subprocess"):
        assert banned not in source, banned
