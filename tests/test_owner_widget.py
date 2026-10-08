"""KA-100 - owner dashboard widget: pin the pure payload builder's shapes,
degradation, determinism and string coercion over INJECTED inputs only.

Pinned here: the session:report block order (metrics, table, links?),
the exact three headline metric labels, the {label, value, detail} item
shape with STRING values/details, per-metric degradation to
{"value": "unknown", ...} (suite / coverage / battery), the
grep-equivalent verdict + collect-total parsing (last match wins, never
tail), battery transcript parsing (documented [battery]-line convention,
consent-gate refusals), http(s)-only
link validation (file:// and every other scheme dropped), determinism
(identical injections -> identical payload and identical JSON text), the
committed sample data/owner_widget.json matching the offline builder
byte-for-byte and its structural contract, and module purity (no
subprocess/pytest/network/disk imports; and no Mixin class, so the
module stays out of the tool-versions scan set).

History: the fourth headline (the evidence count under the removed
kali_agent_v4 facade's evidence package) was retired 2026-10-08 with
dead-generation cleanup; its degradation tests left with it.

No pytest runs, no /tmp reads, no network in these tests: every test
feeds injected structures; the only path reads are the committed repo
files this task owns or depends on."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

import pytest

from agentic_ai.agents.cyber import owner_widget as OW

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "build_owner_widget.py"
DATA = REPO / "data" / "owner_widget.json"

_builder_spec = importlib.util.spec_from_file_location(
    "build_owner_widget", str(TOOL))
BUILD = importlib.util.module_from_spec(_builder_spec)
_builder_spec.loader.exec_module(BUILD)

# Synthetic injected corpus - same SHAPE as the committed eval corpus
# (known entries pin a match, edge entries pin found/null, out_of_db
# pins an absent id): expected = 2 known + 1 edge-found = 3.
CORPUS = {
    "meta": {"name": "test corpus"},
    "known": [
        {"cve": "CVE-2026-0001", "metasploit_module": "exploit/test/one"},
        {"cve": "CVE-2026-0002", "metasploit_module": "exploit/test/two"},
    ],
    "edge": [
        {"raw": "cve-2026-0001", "outcome": "found", "class": "lowercase",
         "expect_cve": "CVE-2026-0001"},
        {"raw": " cve-2026-0002 ", "outcome": "null", "class": "padded"},
    ],
    "out_of_db": [{"cve": "CVE-2026-0009", "class": "real-world-absent"}],
}


class _Row:
    def __init__(self, cve_id):
        self.cve_id = cve_id


class StubMatcher:
    """Engine-like stub: match_cve -> a row exposing .cve_id, or None."""

    def __init__(self, mapping):
        self._mapping = mapping

    def match_cve(self, cve_id):
        want = self._mapping.get(cve_id)
        return _Row(want) if want is not None else None


class RaisingMatcher:
    """Hostile 'matcher': match_cve raises."""

    def match_cve(self, cve_id):
        raise RuntimeError("boom")


FULL = StubMatcher({
    "CVE-2026-0001": "CVE-2026-0001",
    "CVE-2026-0002": "CVE-2026-0002",
    "cve-2026-0001": "CVE-2026-0001",
})
PARTIAL = StubMatcher({
    "CVE-2026-0001": "CVE-2026-0001",
    "cve-2026-0001": "CVE-2026-0001",
})
OVERREACH = StubMatcher({
    "CVE-2026-0001": "CVE-2026-0001",
    "cve-2026-0001": "CVE-2026-0001",
    " cve-2026-0002 ": "CVE-2026-0002",
    "CVE-2026-0009": "CVE-2026-0009",
})

GOOD_LINKS = [
    {"label": "repo mirror", "url": "https://github.com/example/repo",
     "detail": "verified"},
    {"label": "corpus source",
     "url": "https://example.test/corpus.json"},
]

PASS_LOG = ("run: 2026-10-05T21:04Z\n"
            "[battery] OK host tier\n"
            "[battery] OK target tier (rocky-scan reachable on port 2226)\n")
STAMPLESS_PASS = ("[battery] OK host tier\n"
                  "[battery] OK target tier (rocky-scan reachable on"
                  " port 2226)\n")
FAIL_LOG = "[battery] OK host tier\n[battery] FATAL: target disk missing\n"
REFUSED_LOG = ("[battery] REFUSED: executing modes need"
               " KA_BATTERY_CONSENT=1\n")


# --------------------------------------------------------- payload shape

def test_payload_shape_and_block_order():
    payload = OW.build_payload(
        collected_total=5121, verdict="5120 passed, 1 failed",
        corpus=CORPUS, matcher=FULL,
        battery={"verdict": "pass", "when": "2026-10-05T21:04Z"},
        links=GOOD_LINKS)
    assert set(payload) == {"schema", "generated", "blocks"}
    assert payload["schema"] == OW.SCHEMA
    assert payload["generated"] == OW.GENERATED
    assert OW.UNKNOWN == "unknown"
    assert OW.METRIC_LABELS == ("suite state", "CVE-DB coverage %",
                                "last battery run")
    assert [block["type"] for block in payload["blocks"]] == \
        ["metrics", "table", "links"]
    items = payload["blocks"][0]["items"]
    assert all(set(item) == {"label", "value", "detail"} for item in items)
    assert tuple(item["label"] for item in items) == OW.METRIC_LABELS
    assert all(isinstance(item["value"], str)
               and isinstance(item["detail"], str) for item in items)
    table = payload["blocks"][1]
    assert set(table) == {"type", "title", "columns", "rows"}
    assert table["columns"] == ["metric", "state", "source"]
    rows = table["rows"]
    assert len(rows) == 3
    for row, label, item in zip(rows, OW.METRIC_LABELS, items):
        assert row[0] == label
        assert (row[1] == "ok") == (item["value"] != OW.UNKNOWN)
        assert row[2] == ("injected" if item["value"] != OW.UNKNOWN
                          else "absent")
        assert all(isinstance(cell, str) for cell in row)


def test_payload_determinism_full_build():
    one = OW.build_payload(
        collected_total=5121, verdict="5120 passed, 1 failed",
        corpus=CORPUS, matcher=FULL,
        battery={"verdict": "pass", "when": "2026-10-05T21:04Z"},
        links=GOOD_LINKS)
    two = OW.build_payload(
        collected_total=5121, verdict="5120 passed, 1 failed",
        corpus=CORPUS, matcher=FULL,
        battery={"verdict": "pass", "when": "2026-10-05T21:04Z"},
        links=GOOD_LINKS)
    assert one == two
    text = OW.payload_json_text(two)
    assert text.endswith("\n")
    assert json.loads(text) == two


def test_payload_never_raises_on_hostile_inputs():
    payload = OW.build_payload(corpus=42, matcher="nope", battery=[1, 2],
                               verdict=7.5,
                               collected_total=True)
    items = payload["blocks"][0]["items"]
    assert len(items) == 3
    assert all(isinstance(item["value"], str) for item in items)


# --------------------------------------------------------- suite state

@pytest.mark.parametrize(("collected", "verdict", "note", "value",
                          "detail_fragment"), [
    (5121, "5120 passed, 1 failed", None,
     "collected 5121 - 5120 passed, 1 failed", "injected"),
    (42, None, None, "collected 42", "no verdict text available"),
    (None, None, "mystery", OW.UNKNOWN, "no suite state injected"),
])
def test_suite_metric_states(collected, verdict, note, value,
                             detail_fragment):
    metric = OW.suite_metric(collected, verdict, note)
    assert metric["value"] == value
    assert detail_fragment in metric["detail"]
    if note:
        assert note in metric["detail"]


@pytest.mark.parametrize("output,expected", [
    ("noise\n5119 passed, 0 failed, 3 warnings in 7.02s =====\n"
     "ValueError: cosmetic shutdown noise",
     "5119 passed, 0 failed, 3 warnings in 7.02s ====="),
    ("1 passed\n5 errors\n3 passed\n", "3 passed"),
])
def test_parse_verdict_last_grep_match_wins(output, expected):
    assert OW.parse_verdict(output) == expected


@pytest.mark.parametrize("output,expected", [
    ("5104 tests collected in 1.25s", 5104),
])
def test_parse_collect_total(output, expected):
    assert OW.parse_collect_total(output) == expected


# ------------------------------------------------------- CVE-DB coverage

def test_coverage_full_and_partial_and_overreach():
    full = OW.coverage_metric(CORPUS, FULL)
    assert full["value"] == "100.0%"
    assert full["detail"] == ("matched 3/3 expected entries over 5 corpus"
                              " entries (known 2, edge 2, out_of_db 1);"
                              " over-reach 0")
    partial = OW.coverage_metric(CORPUS, PARTIAL)
    assert partial["value"] == "66.7%"  # exact + lowercase raw both known
    assert "matched 2/3 expected entries" in partial["detail"]
    overreach = OW.coverage_metric(CORPUS, OVERREACH)
    assert overreach["value"] == "66.7%"  # over-reach never inflates the score
    assert "over-reach 2" in overreach["detail"]


@pytest.mark.parametrize(("corpus", "matcher", "detail_fragment"), [
    (None, None, "no matcher injected"),
    (None, FULL, "no corpus injected"),
    (42, FULL, "corpus must be the parsed eval-corpus dict"),
    ({"known": [], "edge": [], "out_of_db": []}, FULL,
     "no expected-match entries"),
    (CORPUS, RaisingMatcher(), "matcher raised: boom"),
])
def test_coverage_degrades_without_crashing(corpus, matcher,
                                            detail_fragment):
    metric = OW.coverage_metric(corpus, matcher)
    assert metric["value"] == OW.UNKNOWN
    assert detail_fragment in metric["detail"]


# ------------------------------------------------------- battery run

@pytest.mark.parametrize("text,expected", [
    (PASS_LOG, ("pass", "2026-10-05T21:04Z")),
    (FAIL_LOG, ("fail", None)),
    (REFUSED_LOG, ("refused", None)),
    ("make: *** No rule to make target\nsudo reboot\n", None),
])
def test_parse_battery_log_cases(text, expected):
    state = OW.parse_battery_log(text)
    if expected is None:
        assert state is None
        return
    assert state["verdict"] == expected[0]
    assert state.get("when") == expected[1]
    assert state["mode"] == OW.BATTERY_MODE
    if expected[0] in ("fail", "refused"):
        assert "FATAL" in state["detail"] or "REFUSED" in state["detail"]


@pytest.mark.parametrize(("state", "note", "value_fragment",
                          "detail_fragment"), [
    ({"verdict": "pass", "when": "2026-10-05T21:04Z",
      "detail": "2 battery lines"}, None, "pass - run:", "2 battery lines"),
    (PASS_LOG, None, "pass - run:", "2 battery lines"),
    (STAMPLESS_PASS, None, "pass - run time not recorded", None),
    (None, "check the log dir", OW.UNKNOWN, "skipped when absent"),
])
def test_battery_metric_states(state, note, value_fragment,
                               detail_fragment):
    metric = OW.battery_metric(state, note)
    assert value_fragment in metric["value"]
    if detail_fragment:
        assert detail_fragment in metric["detail"]


# -------------------------------------------------------------- links

def test_valid_links_keeps_https_in_order_and_dedupes():
    kept = OW.valid_links(GOOD_LINKS + [dict(GOOD_LINKS[0])])
    assert kept[0]["url"] == GOOD_LINKS[0]["url"]
    assert kept[0]["detail"] == "verified"
    assert set(kept[0]) == {"label", "url", "detail"}
    assert len(kept) == 2  # duplicate (label, url) collapsed


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "javascript:alert(1)",
    "//no-scheme.example.org/x",
])
def test_valid_links_drop_hostile_schemes(url):
    assert OW.valid_links([{"label": "bad", "url": url}]) == []


def test_valid_links_drop_malformed_entries():
    garbage = [42, "https://plain-string.example", {},
               {"label": "missing-url"}, {"url": "https://x/y"},
               {"label": "  ", "url": "https://x/y"}]
    assert OW.valid_links(garbage) == []


def test_payload_omits_links_block_when_nothing_survives():
    payload = OW.build_payload(corpus=CORPUS, matcher=FULL,
                               links=[{"label": "bad",
                                       "url": "file:///x"}])
    assert [block["type"] for block in payload["blocks"]] == \
        ["metrics", "table"]


# ------------------------------------------------------------ builder

def test_builder_offline_matches_committed_bytes():
    text = BUILD.offline_payload_text()
    assert json.loads(text)["schema"] == OW.SCHEMA
    assert text == DATA.read_text(encoding="utf-8")
    assert BUILD.OUT.name == "owner_widget.json"
    assert callable(BUILD.main) and callable(BUILD.probe_suite)
    assert callable(BUILD.lazy_coverage)
    links = BUILD.CURATED_LINKS
    assert links and all(
        entry["url"].startswith("https://") for entry in links)


def test_committed_sample_structure():
    text = DATA.read_text(encoding="utf-8")
    sample = json.loads(text)
    assert sample["generated"] == OW.GENERATED
    blocks = sample["blocks"]
    assert [block["type"] for block in blocks] == \
        ["metrics", "table", "links"]
    items = blocks[0]["items"]
    assert tuple(item["label"] for item in items) == OW.METRIC_LABELS
    assert all(isinstance(item["value"], str)
               and isinstance(item["detail"], str) for item in items)
    coverage = items[1]
    assert re.fullmatch(r"\d+\.\d%", coverage["value"])
    assert "expected entries" in coverage["detail"]
    assert "corpus entries" in coverage["detail"]
    links = blocks[2]["items"]
    assert all(link["url"].startswith("https://") for link in links)
    assert "file://" not in text


def test_module_purity_scans():
    src = (REPO / "agentic_ai" / "agents" / "cyber"
           / "owner_widget.py").read_text(encoding="utf-8")
    for banned in ("import subprocess", "import pytest", "import requests",
                   "import socket", "import urllib.request", "http.client",
                   "os.system(", "popen(", "eval(", "exec(", "open(",
                   "import pathlib"):
        assert banned not in src, banned
    # no Mixin class: the module stays a plain payload builder and stays
    # outside the tool-versions scan-set pin.
    assert re.search(r"^class \w+Mixin", src, flags=re.M) is None


@pytest.mark.parametrize("args", [
    ["--bogus"],
    ["--json"],
])
def test_builder_rejects_bad_flags(args):
    with pytest.raises(SystemExit):
        BUILD.main(args)