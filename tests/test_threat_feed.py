"""KA-073 tests - newsroom threat feed: the newsroom state shape pinned
field-by-field against the committed snapshot (a synthetic-but-realistic
mirror of the live bedimsecurity newsroom JSON; provenance recorded in
its meta), the daily-brief contract (newest-first ordering with id
tiebreaks, newest-wins duplicate collapse on id AND url, the lenient
unusable ledger, archive-counted-never-briefed), deterministic threat
tags, strict CVE extraction with lookalike negatives, priority and
watchlist pinning, the URL-capped link roll with the house cap 25, the
host-gate boundary on watch_target, and the purity scan. Fixture rows
are synthetic; the live newsroom state is never touched. No network."""
from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.threat_feed import (
    ARTICLE_ROW_KEYS,
    HIGH_SIGNAL_TAGS,
    TAG_RULES,
    ThreatBriefPlanner,
    tf_scrub_text,
    validate_feed,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "scans" / "newsroom_feed.json"
)
SNAP = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
FEED = SNAP["feed"]
ARTICLES = FEED["articles"]
ARCHIVE = FEED["archive"]
ROW_KEYS = set(ARTICLE_ROW_KEYS)

TOP_LEVEL_KEYS = {"brief_date", "counts", "headlines", "unusable",
                  "watchlist", "notes"}
COUNT_KEYS = {"total", "unusable", "duplicates", "usable", "briefed",
              "archived", "shown", "cves_seen", "by_category"}
HEADLINE_KEYS = {"id", "added_at", "source", "title", "url", "category",
                 "summary", "tags", "cves", "priority"}
LINK_KEYS = {"id", "title", "url", "source", "category"}
BRIEFING = ThreatBriefPlanner()

EXPECTED_ORDER = [
    "synthetic-backup-restore",                  # 2026-10-06 22:00
    "synthetic-agentic-sandbox-escape",          # 21:10 tie -> id asc
    "synthetic-zero-day-router-exploit",         # 21:10 tie -> id asc
    "synthetic-mcp-protocol-pivot",              # 18:41
    "synthetic-0day-disclosure-slate",           # 14:00
    "synthetic-ot-coalition-guidance",           # 12:30
    "synthetic-contractor-breach",               # 08:25
    "synthetic-backup-appliance-path-traversal", # 10-05 18:08
    "synthetic-gov-registry-dwell",              # 10-05 16:00
    "synthetic-netscaler-cve",                   # 10-05 12:01
]
EXPECTED_TAGS = {
    "synthetic-zero-day-router-exploit":
        ["zero-day", "rce", "active-exploitation"],
    "synthetic-mcp-protocol-pivot": ["agentic-ai"],
    "synthetic-netscaler-cve": ["rce", "active-exploitation"],
    "synthetic-gov-registry-dwell": ["data-breach", "credentials"],
    "synthetic-ot-coalition-guidance": [],
    "synthetic-contractor-breach": ["data-breach", "supply-chain"],
    "synthetic-backup-appliance-path-traversal": ["path-traversal"],
    "synthetic-0day-disclosure-slate": ["zero-day"],
    "synthetic-backup-restore": [],
    "synthetic-agentic-sandbox-escape": ["agentic-ai"],
}


def test_fixture_carries_the_newsroom_shape():
    assert set(SNAP) == {"meta", "feed"}
    assert set(FEED) == {"articles", "archive"}
    for row in ARTICLES + ARCHIVE:
        assert set(row) == ROW_KEYS
    meta = SNAP["meta"]
    assert meta["trimmed"]["articles_in_fixture"] == len(ARTICLES) == 10
    assert meta["trimmed"]["archive_in_fixture"] == len(ARCHIVE) == 2
    assert FEED["articles"][0]["added_at"].endswith("Z")  # live format


def test_build_brief_output_schema():
    result = BRIEFING.build_brief(FEED)
    assert set(result) == TOP_LEVEL_KEYS
    assert set(result["counts"]) == COUNT_KEYS
    for row in result["headlines"]:
        assert set(row) == HEADLINE_KEYS
    assert result["unusable"] == []
    assert result["brief_date"] == "2026-10-06"
    assert all(row["priority"] in ("high", "normal")
               for row in result["headlines"])


def test_headline_ordering_pin():
    result = BRIEFING.build_brief(FEED)
    assert [row["id"] for row in result["headlines"]] == EXPECTED_ORDER


def test_counts_equations_and_by_category():
    result = BRIEFING.build_brief(FEED)
    assert result["counts"] == {
        "total": 10, "unusable": 0, "duplicates": 0, "usable": 10,
        "briefed": 10, "archived": 2, "shown": 10, "cves_seen": 2,
        "by_category": {"Agentic AI": 2, "Cyber Controls": 4,
                        "Compliance": 2, "Policy": 2},
    }
    by_category = result["counts"]["by_category"]
    assert list(by_category) == sorted(by_category)  # deterministic order
    notes = " ".join(result["notes"])
    assert "total=10 = usable=10 + duplicates=0 + unusable=0" in notes
    assert "sum=10 = briefed=10)" in notes
    assert (any("planning-only lens" in note for note in result["notes"]))
    assert result["counts"]["briefed"] == sum(by_category.values())


def test_day_filter_and_archive_never_briefed():
    six = BRIEFING.build_brief(FEED, day="2026-10-06")
    assert six["brief_date"] == "2026-10-06"
    assert six["counts"]["briefed"] == 7 and six["counts"]["shown"] == 7
    assert six["counts"]["by_category"] == {
        "Agentic AI": 2, "Cyber Controls": 2, "Compliance": 1, "Policy": 2}
    four = BRIEFING.build_brief(FEED, day="2026-10-04")
    assert four["headlines"] == [] and four["counts"]["briefed"] == 0
    assert four["counts"]["archived"] == 2  # counted, never briefed
    assert four["brief_date"] == "2026-10-04"


def test_duplicate_semantics_latest_wins_ties_keep_stored():
    articles = copy.deepcopy(ARTICLES)
    idx = next(i for i, row in enumerate(articles)
               if row["id"] == "synthetic-backup-restore")
    newer = dict(articles[idx], added_at="2026-10-06T23:00:00Z")
    tie = dict(articles[idx], id="synthetic-backup-restore-tie-dupe",
               added_at="2026-10-06T23:00:00Z")
    url_dupe = dict(articles[idx], id="synthetic-backup-restore-url-dupe",
                    added_at="2026-10-05T01:00:00Z")
    result = BRIEFING.build_brief(
        {"articles": [*articles, newer, tie, url_dupe]})
    assert result["counts"]["duplicates"] == 3
    assert result["counts"]["usable"] == 10
    ids = [row["id"] for row in result["headlines"]]
    assert ids == EXPECTED_ORDER
    first = result["headlines"][0]
    assert first["id"] == "synthetic-backup-restore"
    assert first["added_at"] == "2026-10-06T23:00:00Z"  # newest wins
    assert "synthetic-backup-restore-url-dupe" not in ids  # url collapse
    assert "synthetic-backup-restore-tie-dupe" not in ids


def _brief_with_appended(row):
    articles = copy.deepcopy(ARTICLES)
    articles.append(copy.deepcopy(row))
    return BRIEFING.build_brief({"articles": articles})


CASES = [
    {"row": None, "reason": "row is not an object",
     "ledger": "<missing-id>"},
    {"row": "junk", "reason": "row is not an object",
     "ledger": "<missing-id>"},
    {"row": {"added_at": "2026-10-06T10:00:00Z", "source": "s",
             "title": "t", "url": "https://example.com/n/x",
             "category": "c"},
     "reason": "id missing or blank", "ledger": "<missing-id>"},
    {"row": {}, "reason": "id missing or blank", "ledger": "<missing-id>",
     "min_reasons": True},
    {"row": {"id": "x!bad", "added_at": "2026-10-06T10:00:00Z",
             "source": "s", "title": "t", "url": "https://example.com/n/x",
             "category": "c"},
     "reason": "id malformed", "ledger": "<missing-id>"},
    {"row": {"id": "synthetic-bad-at", "added_at": "2026-06-10T10:00",
             "source": "s", "title": "t", "url": "https://example.com/n/x",
             "category": "c"},
     "reason": "added_at malformed", "ledger": "synthetic-bad-at"},
    {"row": {"id": "synthetic-bad-url", "added_at": "2026-10-06T10:00:00Z",
             "source": "s", "title": "t", "url": "ftp://example.com/news/x",
             "category": "c"},
     "reason": "url malformed", "ledger": "synthetic-bad-url"},
    {"row": {"id": "synthetic-bad-url-2", "added_at": "2026-10-06T10:00:00Z",
             "source": "s", "title": "t",
             "url": "https://exa mple.com/news/x", "category": "c"},
     "reason": "url malformed", "ledger": "synthetic-bad-url-2"},
    {"row": {"id": "synthetic-ctrl-title",
             "added_at": "2026-10-06T10:00:00Z", "source": "s",
             "title": "zero\x01day", "url": "https://example.com/news/x",
             "category": "c"},
     "reason": "title rejected", "ledger": "synthetic-ctrl-title"},
    {"row": {"id": "synthetic-int-summary",
             "added_at": "2026-10-06T10:00:00Z", "source": "s",
             "title": "t", "url": "https://example.com/news/x",
             "category": "c", "summary": 12},
     "reason": "summary present but not a string",
     "ledger": "synthetic-int-summary"},
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["reason"][:30])
def test_unparseable_rows_never_crash(case):
    result = _brief_with_appended(case["row"])
    counts = result["counts"]
    assert counts["total"] == 11 and counts["unusable"] == 1
    assert counts["usable"] == 10 and counts["shown"] == 10
    (entry,) = result["unusable"]
    assert entry["id"] == case["ledger"]
    assert entry["id"] not in [row["id"] for row in result["headlines"]]
    assert any(case["reason"] in reason
               for reason in entry["reasons"]), entry["reasons"]
    if case.get("min_reasons"):
        assert len(entry["reasons"]) >= 5  # every field miss at once


def test_empty_row_reports_every_field_miss():
    result = _brief_with_appended({})
    (entry,) = result["unusable"]
    joined = " ".join(entry["reasons"])
    for fragment in ("id missing", "added_at missing", "source missing",
                     "title missing", "url missing", "category missing"):
        assert fragment in joined


def test_tags_are_deterministic_and_scoped():
    assert len(TAG_RULES) == 8
    result = BRIEFING.build_brief(FEED)
    tags_by_id = {row["id"]: row["tags"] for row in result["headlines"]}
    assert tags_by_id == EXPECTED_TAGS
    again = {row["id"]: row["tags"]
             for row in BRIEFING.build_brief(FEED)["headlines"]}
    assert again == tags_by_id  # two passes, same answer


def test_cves_extracted_deduped_sorted():
    result = BRIEFING.build_brief(FEED)
    rows = {row["id"]: row for row in result["headlines"]}
    assert rows["synthetic-netscaler-cve"]["cves"] == [
        "CVE-2026-1001", "CVE-2026-31337"]
    for row_id, row in rows.items():
        if row_id != "synthetic-netscaler-cve":
            assert row["cves"] == []
    assert result["counts"]["cves_seen"] == 2
    notes = " ".join(result["notes"])
    assert ("cves: 2 distinct strings extracted; live validity NOT "
            "checked here") in notes


def test_cve_extraction_lookalikes_excluded():
    row = copy.deepcopy(ARTICLES[0])
    row["id"] = "synthetic-cve-lookalikes"
    row["url"] = "https://example.com/news/cve-lookalike-sweep"
    row["title"] = "Lookalike sweep"
    row["summary"] = (
        "None of these match: CVE-20263-4 (5-digit year), CVE-2026- (no "
        "digits), CVE-2026- 12345 (gap), cve-2026-9 (too short). Only "
        "cve-2026-778899 counts.")
    result = _brief_with_appended(row)
    assert result["counts"]["unusable"] == 0
    rows = {r["id"]: r for r in result["headlines"]}
    assert rows["synthetic-cve-lookalikes"]["cves"] == ["CVE-2026-778899"]


def test_priority_and_watchlist_pin():
    assert HIGH_SIGNAL_TAGS == {"zero-day", "rce", "active-exploitation"}
    result = BRIEFING.build_brief(FEED)
    assert result["watchlist"] == [
        "synthetic-zero-day-router-exploit",
        "synthetic-0day-disclosure-slate",
        "synthetic-netscaler-cve",
    ]
    ids = [row["id"] for row in result["headlines"]]
    assert set(result["watchlist"]) <= set(ids)
    priorities = {row["priority"] for row in result["headlines"]}
    assert priorities == {"high", "normal"}


def test_story_links_shape_filter_and_truncation():
    result = BRIEFING.story_links(FEED)
    assert set(result) == {"category", "links", "counts", "truncated"}
    assert set(result["counts"]) == {
        "total", "unusable", "duplicates", "shown"}
    assert result["counts"] == {"total": 10, "unusable": 0,
                                "duplicates": 0, "shown": 10}
    assert result["truncated"] is False
    for link in result["links"]:
        assert set(link) == LINK_KEYS          # names + links only,
        assert "summary" not in link           # never the long free text
    assert [link["id"] for link in result["links"]] == EXPECTED_ORDER
    cc = BRIEFING.story_links(FEED, category="cyber controls")
    assert cc["category"] == "cyber controls"  # the scrubbed caller string
    assert [link["id"] for link in cc["links"]] == [
        "synthetic-backup-restore", "synthetic-zero-day-router-exploit",
        "synthetic-backup-appliance-path-traversal",
        "synthetic-netscaler-cve"]
    assert all(link["category"] == "Cyber Controls"
               for link in cc["links"])
    two = BRIEFING.story_links(FEED, limit=2)
    assert two["counts"]["shown"] == 2 and two["truncated"] is True
    assert [link["id"] for link in two["links"]] == EXPECTED_ORDER[:2]
    empty = BRIEFING.story_links(FEED, category="no-such-category")
    assert empty["links"] == [] and empty["truncated"] is False


def test_story_links_and_brief_house_cap_25():
    articles = []
    for i in range(30):
        articles.append({
            "id": "synthetic-cap-%02d" % i,
            "added_at": "2026-10-06T%02d:%02d:00Z" % (i // 12, i % 60),
            "source": "SyntheticLoad", "title": "Cap filler row %d" % i,
            "url": "https://example.com/news/cap-%02d" % i,
            "category": "Cyber Controls", "summary": "",
        })
    rolled = BRIEFING.story_links({"articles": articles}, limit=999)
    assert rolled["counts"]["shown"] == 25      # clamped to the house cap
    assert rolled["truncated"] is True
    brief = BRIEFING.build_brief({"articles": articles}, brief_size=5)
    assert brief["counts"]["briefed"] == 30     # rows counted un-clipped
    assert brief["counts"]["shown"] == 5        # headlines capped


class _GatedHost(ThreatBriefPlanner):
    def __init__(self, verdict=(True, "ok")):
        self.calls = []
        self._verdict = verdict

    def validate_target(self, target):
        self.calls.append(target)
        return self._verdict


def test_watch_target_matches_and_gate_contract():
    host = _GatedHost()
    result = host.watch_target(FEED, "  NetScaler  ")
    assert host.calls == ["NetScaler"]   # scrubbed BEFORE the gate consult
    assert result["target"] == "NetScaler"
    assert [row["id"] for row in result["matches"]] == ["synthetic-netscaler-cve"]
    assert set(result["counts"]) == {
        "total", "unusable", "duplicates", "usable", "shown"}
    assert result["counts"]["usable"] == 10
    url_hit = host.watch_target(FEED, "example.com/news/backup-restore")
    assert [row["id"] for row in url_hit["matches"]] == [
        "synthetic-backup-restore"]


def test_watch_target_rejecting_gate():
    host = _GatedHost(verdict=(False, "outside scope"))
    with pytest.raises(ValueError) as err:
        host.watch_target(FEED, "NetScaler")
    assert ("target rejected by host agent gate: outside scope"
            in str(err.value))
    assert host.calls == ["NetScaler"]


def test_watch_target_silent_fallback_and_scrub_first():
    bare = ThreatBriefPlanner()  # no validate_target attribute at all
    result = bare.watch_target(FEED, "NetScaler")  # silent fallback works
    assert [row["id"] for row in result["matches"]] == [
        "synthetic-netscaler-cve"]
    host = _GatedHost(verdict=(False, "must-not-be-reached"))
    with pytest.raises(ValueError) as scrub_err:
        host.watch_target(FEED, "bad\x01target")
    assert "with control characters" in str(scrub_err.value)
    assert host.calls == []              # scrubbed first, gate untouched


def test_scrub_helper_contract():
    assert BRIEFING._tf_scrub("  spaced  ") == "spaced"  # thin wrapper
    assert tf_scrub_text("x" * 200) == "x" * 200         # default cap
    for bad in (None, 7, "", "   ", "a\x00b", "x" * 201):
        with pytest.raises(ValueError):
            tf_scrub_text(bad)
    with pytest.raises(ValueError) as exc:
        tf_scrub_text("a\x00b")
    assert "\\x00" in str(exc.value)     # reasons are repr-safe


@pytest.mark.parametrize("bad_day", ["2026-1-06", "2026/10/06",
                                     "not-a-day", 7])
def test_day_parameter_guard(bad_day):
    with pytest.raises(ValueError):
        BRIEFING.build_brief(FEED, day=bad_day)


def test_validate_feed_actionable_errors():
    with pytest.raises(ValueError) as err:
        validate_feed("nope")
    assert "feed must be a dict" in str(err.value)
    with pytest.raises(ValueError) as err:
        validate_feed({})
    assert "missing required keys" in str(err.value)
    with pytest.raises(ValueError) as err:
        validate_feed({"articles": "no"})
    assert "articles must be a list" in str(err.value)
    with pytest.raises(ValueError) as err:
        validate_feed({"articles": [], "archive": "x"})
    assert "archive must be a list" in str(err.value)
    validate_feed({"articles": []})  # the minimal task-context shape
    validate_feed(FEED)              # the fixture validates clean


def test_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.threat_feed")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
