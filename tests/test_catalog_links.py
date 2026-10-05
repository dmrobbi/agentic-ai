"""KA-023 - catalog integrity: the measured sha256 snapshot (the drift
alarm if a catalog file is edited), well-formed URLs across all 740
tool rows, the counted totals matching the catalogs' own meta, the
offline script green via subprocess, the live mode structurally
opt-in, and the report writer as a pure tested function. No network."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ka" / "catalog_check.py"
RT_PATH = REPO / "agentic_ai" / "agents" / "cyber" / "data" / "redteam_tools.json"
XS_PATH = REPO / "agentic_ai" / "agents" / "cyber" / "data" / "xss_tools.json"

RT_SHA = "02b99135d76dec5c9600dade43b491ff770133bd20b65b382d31b17d5384f25e"
XS_SHA = "f3ad2fdd6d291ed36b08727b683c7211b7568cdf1ee9ff87263482db7bc7f0ce"


def test_catalog_hashes_unchanged():
    assert hashlib.sha256(RT_PATH.read_bytes()).hexdigest() == RT_SHA
    assert hashlib.sha256(XS_PATH.read_bytes()).hexdigest() == XS_SHA


def test_all_urls_wellformed():
    for path in (RT_PATH, XS_PATH):
        data = json.loads(path.read_text(encoding="utf-8"))
        for phase, entry in sorted(data["phases"].items()):
            for row in entry["tools"]:
                url = row["url"]
                assert url.startswith(("http://", "https://")), (phase, url)
                assert "://" in url and not any(c.isspace() for c in url)
                assert urlsplit_free_of_hostile(url)


def urlsplit_free_of_hostile(url):
    from urllib.parse import urlsplit
    return bool(urlsplit(url).netloc)


def test_counts_match_meta_totals():
    for path, expected in ((RT_PATH, {"phases": 13, "tools": 725}),
                           (XS_PATH, {"phases": 5, "tools": 15})):
        data = json.loads(path.read_text(encoding="utf-8"))
        counted = sum(len(e["tools"]) for e in data["phases"].values())
        assert counted == expected["tools"], path.name
        assert len(data["phases"]) == expected["phases"], path.name
        # subset semantics: the redteam totals carry EXTRA keys at
        # curation ("links_seen": 1071 + the doc/index note) - kept visible
        totals = data["meta"]["totals"]
        for key, value in expected.items():
            assert totals.get(key) == value, (path.name, key, totals)


def test_offline_script_runs_green():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CATALOG-CHECK-OK catalogs=2 tools=740" in proc.stdout


def test_live_mode_is_optin_only():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--live" in source and "write_report" in source
    assert source.count("import requests") == 1
    offline_part = source.split("import requests", 1)[0]
    assert "import requests" not in offline_part


def test_write_report_renders_rows(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("ka023_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dead = [{"catalog": "xss", "phase": "fuzzing", "name": "a-tool",
             "url": "https://example.com/a", "problem": "HTTP 404"}]
    report = tmp_path / "report.txt"
    module.write_report(dead, report)
    text = report.read_text(encoding="utf-8")
    assert "dead_links: 1" in text
    assert "| xss | fuzzing | a-tool | https://example.com/a | HTTP 404 |" in text
    assert text.startswith("# KA-023 catalog link report")
