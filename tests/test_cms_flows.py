"""KA-049 - per-CMS catalog integrity: the measured sha256 snapshot (the
drift alarm if data/cms_flows.json is hand-edited), the WP/Drupal/Joomla/
typo3 shape and counted totals matching the catalog's own meta, well-formed
unique URLs, the planner-purity/policy scans (no payloads, no execution
markers, no dead-link markers), the offline builder re-running green and
byte-identical, and the live URL-verification mode staying opt-in.
No network (the builder's default mode and the test both run offline)."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data" / "cms_flows.json"
SCRIPT = REPO / "tools" / "build_cms_catalog.py"

DATA_SHA = "e9aec8e7f6d010ac497ae5a45439ca7e6ff9c4f9c7837c229bad683c93d4d592"

EXPECTED_CMS = ("drupal", "joomla", "typo3", "wordpress")
EXPECTED_ARCS = ("enumeration", "extension-audit", "version-trail",
                 "hardening-assessment")
EXPECTED_CMS_FLOWS = {"wordpress": 7, "drupal": 6, "joomla": 5, "typo3": 6}
EXPECTED_TOTALS = {"cms": 4, "flows": 24}

# payload/hostile/exploit strings that must never leak into the catalog
# (methodology only: names + official doc links + re-authored purposes)
FORBIDDEN_STRINGS = (
    "<script", "javascript:", "onerror=", "onload=", "union select",
    "drop table", "select *", "base64", "/etc/passwd", "whoami",
    "bash -c", "nc -e", "import subprocess", "os.system", "eval(",
    "exec(", "system(", "curl", "wget", "hydra", "sqlmap", "metasploit",
    "wp-admin", "password", "secret_",
)

# dead-link markers: dropped candidates are documented in the builder's
# docstring only - the committed data carries none of these
DEAD_LINK_MARKERS = (
    "dead", "404", "403", "unavailable", "no longer", "removed",
    "dropped", "unreachable",
)


def _load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def test_catalog_sha_unchanged():
    assert hashlib.sha256(DATA.read_bytes()).hexdigest() == DATA_SHA


def test_data_shape_top_keys_and_cms_set():
    data = _load()
    assert sorted(data) == ["cms", "meta"]
    assert tuple(sorted(data["cms"])) == EXPECTED_CMS
    assert sorted(data["meta"]) == ["policy", "source", "totals",
                                    "urls_verified"]


def test_arcs_constant_per_cms():
    data = _load()
    for name, entry in data["cms"].items():
        assert tuple(entry["arcs"]) == EXPECTED_ARCS, name


def test_flow_row_schema_and_stage_membership():
    data = _load()
    for name, entry in data["cms"].items():
        assert name in EXPECTED_CMS_FLOWS, name
        for row in entry["flows"]:
            assert sorted(row) == ["name", "purpose", "stage", "url"], row
            assert row["stage"] in entry["arcs"], (name, row)
            assert all(str(row[k]).strip() for k in row), (name, row)


def test_stage_grouping_order():
    """flows are grouped stage-arc by stage-arc in curated arc order."""
    data = _load()
    for name, entry in data["cms"].items():
        seen = []
        for row in entry["flows"]:
            if not seen or seen[-1] != row["stage"]:
                seen.append(row["stage"])
        assert seen == [a for a in entry["arcs"]
                        if any(r["stage"] == a for r in entry["flows"])], name


def test_counts_match_meta_totals():
    data = _load()
    for name, entry in data["cms"].items():
        assert len(entry["flows"]) == EXPECTED_CMS_FLOWS[name], name
    totals = data["meta"]["totals"]
    counted = sum(len(e["flows"]) for e in data["cms"].values())
    assert totals == EXPECTED_TOTALS, totals
    assert len(data["cms"]) == EXPECTED_TOTALS["cms"]
    assert counted == EXPECTED_TOTALS["flows"]


def test_urls_wellformed_and_unique():
    data = _load()
    urls = [row["url"] for entry in data["cms"].values()
            for row in entry["flows"]]
    assert len(urls) == len(set(urls)) == EXPECTED_TOTALS["flows"]
    for url in urls:
        assert url.startswith("https://"), url
        assert not any(c.isspace() for c in url), url
        assert urlsplit(url).netloc, url


def test_no_payload_strings():
    text = DATA.read_text(encoding="utf-8").lower()
    for needle in FORBIDDEN_STRINGS:
        assert needle not in text, needle


def test_no_dead_link_markers():
    text = DATA.read_text(encoding="utf-8").lower()
    for marker in DEAD_LINK_MARKERS:
        assert marker not in text, marker


def test_meta_claims_present():
    data = _load()
    meta = data["meta"]
    for prose in (meta["source"], meta["policy"]):
        assert isinstance(prose, str) and prose.strip(), prose
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["urls_verified"]), \
        meta["urls_verified"]


def test_builder_offline_deterministic():
    before = DATA.read_bytes()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(SCRIPT)], cwd=str(REPO),
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CMS-CATALOG-OK cms=4 flows=24" in proc.stdout, proc.stdout
    assert DATA.read_bytes() == before, "builder rewrite is not byte-stable"


def test_live_mode_is_optin_only():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--live" in source
    # planner/catalog purity: no execution markers anywhere in the builder
    for marker in ("subprocess", "os.system", "eval("):
        assert marker not in source, marker
    # the offline module part (before the check function) never imports a
    # network client; urllib.request stays lazy inside check_url_once
    offline_part = source.split("def check_url_once", 1)[0]
    assert offline_part.strip(), "check_url_once not found in builder"
    for needle in ("urllib", "requests", "http.client"):
        assert needle not in offline_part, needle
    assert source.count("import urllib.request") == 1