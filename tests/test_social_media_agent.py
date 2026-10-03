"""Tests for SocialMediaAgent (channel ops: calendar, drafts, engagement,
listening, metrics, brand safety).

Rules under test:
- Draft-only: every artifact requires_owner_send; the toolset contains no
  posting path; publish bookkeeping (mark_published) is data entry.
- Verified links only: dead links are dropped or the story is skipped.
- Measured numbers only: brand_check flags unsourced percent/multiplier
  claims; measured stats pass.
- Persistence mirrors the sales agent (round trip, monotonic ids, corrupt
  and mock stores tolerated).

No test touches the network: every link check is monkeypatched.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentic_ai.agents.base import Permission  # noqa: E402
from agentic_ai.agents.social_media import (  # noqa: E402
    LIMITS,
    Channel,
    PostStatus,
    SocialMediaAgent,
)
from agentic_ai.infrastructure.state import StateStore  # noqa: E402

EXPECTED_TOOLS = sorted([
    "content_calendar", "repurpose", "draft_post", "post_queue",
    "mark_status", "mark_published", "engagement_draft", "listen_report",
    "metrics_report", "brand_check", "crisis_note", "week_summary",
])

ARTICLE = {
    "id": "test-eo-story",
    "added_at": "2026-10-03T01:00:00Z",
    "source": "White House",
    "title": "Federal order renames the AI vocabulary in government",
    "url": "https://example.gov/order/",
    "category": "Policy",
    "summary": ("Executive Order 14434 orders the executive branch to use a "
                "new term in place of Artificial Intelligence. The order "
                "defines the new term as the technologies already covered by "
                "the existing statutory definition."),
}


def make_agent(agent_id: str = "social-test-1", state_store=None,
               news_state: str = "/tmp/nonexistent-news.json") -> SocialMediaAgent:
    return SocialMediaAgent(agent_id=agent_id, name="SocialAgent-test",
                            state_store=state_store, news_state=news_state)


def write_news_state(tmp_path, article, pool="articles"):
    state = {pool: [article] if pool == "articles" else [],
             "archive": [article] if pool == "archive" else []}
    path = tmp_path / "news.json"
    path.write_text(json.dumps(state))
    return str(path)


class TestBasics:
    def test_init_and_tools(self):
        agent = make_agent()
        assert agent.agent_type == "social_media"
        assert agent.permission == Permission.STANDARD
        assert sorted(agent._tools.keys()) == EXPECTED_TOOLS

    def test_no_posting_path(self):
        """Draft-only invariant: no tool that posts/sends exists at all."""
        agent = make_agent()
        tools = set(agent._tools.keys())
        assert "send_message" not in tools  # base defaults were replaced
        assert not any(name.startswith("post_to") or name in
                       ("publish", "send_tweet", "send_post") for name in tools)

    def test_measured_stats_shared_with_sales(self):
        from agentic_ai.agents.sales import PROOF_POINTS
        import agentic_ai.agents.social_media as sm
        assert sm.MEASURED_STATS is PROOF_POINTS


class TestCalendar:
    def test_seven_day_linkedin_only(self):
        agent = make_agent("sm-cal-1")
        result = agent.content_calendar(days=7, channels=["linkedin"])
        assert result["status"] == "ok"
        assert len(result["entries"]) == 3  # weekly cadence 3
        assert all(e["channel"] == "linkedin" for e in result["entries"])
        weekday_ok = all(
            datetime.fromisoformat(e["date"]).weekday() < 5
            for e in result["entries"])
        assert weekday_ok

    def test_seed_binding(self):
        agent = make_agent("sm-cal-2")
        result = agent.content_calendar(days=7, channels=["linkedin",
                                                         "x"],
                                        seed_articles=["eo-14434"])
        repurpose_slots = [e for e in result["entries"]
                           if e["slot_kind"] == "story-repurpose"]
        assert len(repurpose_slots) == 1
        assert repurpose_slots[0]["proposed_post_id"] == "eo-14434"

    def test_unknown_channel_error(self):
        agent = make_agent("sm-cal-3")
        result = agent.content_calendar(days=7, channels=["tiktok"])
        assert "error" in result
        assert "valid_channels" in result

    def test_days_clamped(self):
        agent = make_agent("sm-cal-4")
        result = agent.content_calendar(days=100, channels=["linkedin"])
        assert result["days"] == 28


class TestRepurpose:
    def test_all_variants_generated(self, tmp_path, monkeypatch):
        agent = make_agent("sm-rep-1",
                           news_state=write_news_state(tmp_path, ARTICLE))
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.repurpose("test-eo-story")
        assert result["status"] == "repurposed"
        drafts = result["drafts"]
        assert len(drafts) == 4
        channels = {d["channel"] for d in drafts}
        assert channels == {"linkedin", "x", "mastodon", "bluesky"}
        for draft in drafts:
            assert len(draft["body"]) <= LIMITS[draft["channel"]]
            assert draft["requires_owner_send"] is True
            assert draft["status"] == PostStatus.DRAFTED
        assert ARTICLE["url"] in [d["body"] for d in drafts if d["channel"] == "x"][0]

    def test_hashtags_limited(self, tmp_path, monkeypatch):
        agent = make_agent("sm-rep-2",
                           news_state=write_news_state(tmp_path, ARTICLE))
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.repurpose("test-eo-story")
        li = [d for d in result["drafts"] if d["channel"] == "linkedin"][0]
        assert len(li["hashtags"]) <= 3
        assert "#compliance" in li["hashtags"]  # Policy mapping

    def test_dead_link_skips(self, tmp_path, monkeypatch):
        agent = make_agent("sm-rep-3",
                           news_state=write_news_state(tmp_path, ARTICLE))
        monkeypatch.setattr(agent, "_link_ok", lambda url: False)
        result = agent.repurpose("test-eo-story")
        assert result["status"] == "skipped"
        assert "not live" in result["reason"]
        assert agent.post_queue()["total"] == 0  # nothing queued

    def test_article_not_found(self, tmp_path):
        agent = make_agent("sm-rep-4",
                           news_state=write_news_state(tmp_path, ARTICLE))
        result = agent.repurpose("missing-id")
        assert "error" in result

    def test_unreadable_state(self):
        agent = make_agent("sm-rep-5")
        result = agent.repurpose("anything")
        assert "error" in result
        assert "unreadable" in result["error"]

    def test_archive_pool_also_works(self, tmp_path, monkeypatch):
        agent = make_agent("sm-rep-6",
                           news_state=write_news_state(tmp_path, ARTICLE,
                                                       pool="archive"))
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.repurpose("test-eo-story")
        assert result["status"] == "repurposed"


class TestDraftPost:
    def test_drafted_with_verified_link(self, monkeypatch):
        agent = make_agent("sm-draft-1")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.draft_post(channel="linkedin",
                                  hook="Measured SOC numbers",
                                  angle="-74% GPU energy per decision",
                                  link="https://bedimsecurity.com/capabilities")
        assert result["status"] == "drafted"
        assert "https://bedimsecurity.com/capabilities" in result["post"]["body"]
        assert result["requires_owner_send"] is True

    def test_dead_link_dropped(self, monkeypatch):
        agent = make_agent("sm-draft-2")
        monkeypatch.setattr(agent, "_link_ok", lambda url: False)
        result = agent.draft_post(channel="linkedin", hook="Some news",
                                  link="https://example.gov/dead/")
        assert "https://example.gov/dead/" not in result["post"]["body"]
        assert any("link dropped" in n for n in result["post"]["notes"])

    def test_char_limit_trims(self, monkeypatch):
        agent = make_agent("sm-draft-3")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        long_hook = "word " * 90  # 450 chars
        result = agent.draft_post(channel="x", hook=long_hook)
        assert len(result["post"]["body"]) <= LIMITS["x"]
        assert any("trimmed" in n for n in result["post"]["notes"])

    def test_hashtags_clamped_to_three(self, monkeypatch):
        agent = make_agent("sm-draft-4")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.draft_post(channel="linkedin", hook="Test",
                                  hashtags=["#a", "#b", "#c", "#d", "#e"])
        assert len(result["post"]["hashtags"]) == 3

    def test_unknown_channel_and_empty_draft(self):
        agent = make_agent("sm-draft-5")
        assert "error" in agent.draft_post(channel="tiktok", hook="hi")
        assert "error" in agent.draft_post(channel="linkedin", hook="")


class TestQueue:
    def test_queue_counts(self, monkeypatch):
        agent = make_agent("sm-q-1")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        agent.draft_post(channel="linkedin", hook="One")
        agent.draft_post(channel="x", hook="Two")
        queue = agent.post_queue()
        assert queue["total"] == 2
        assert queue["by_status"] == {PostStatus.DRAFTED: 2}

    def test_status_transitions(self, monkeypatch):
        agent = make_agent("sm-q-2")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        agent.draft_post(channel="linkedin", hook="One")
        assert agent.mark_status("POST-0001", "owner_approved")["status"] == "recorded"
        assert agent.mark_status("POST-0001", "handed_off")["post_status"] == "handed_off"
        assert "error" in agent.mark_status("POST-0001", "published")
        queue = agent.post_queue()
        assert queue["by_status"] == {PostStatus.HANDED_OFF: 1}

    def test_mark_published_records(self, monkeypatch):
        agent = make_agent("sm-q-3")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        agent.draft_post(channel="linkedin", hook="One")
        result = agent.mark_published(
            "POST-0001", url="https://www.linkedin.com/feed/x/",
            metrics={"impressions": 100, "likes": 3})
        assert result["status"] == "recorded"
        post = agent._find_post("POST-0001")
        assert post.status == PostStatus.PUBLISHED
        assert post.published_at is not None
        assert post.metrics["impressions"] == 100

    def test_unknown_post(self, monkeypatch):
        agent = make_agent("sm-q-4")
        assert "error" in agent.mark_status("POST-9999", "owner_approved")


class TestEngagement:
    def test_question_reply_cites_only_live_links(self, monkeypatch):
        agent = make_agent("sm-eng-1")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.engagement_draft(
            mention_text="How do you avoid model drift in alert decisions?")
        assert result["tone"] == "question"
        assert "https://bedimsecurity.com/capabilities" in result["reply"]

        agent2 = make_agent("sm-eng-1b")
        monkeypatch.setattr(agent2, "_link_ok", lambda url: False)
        result2 = agent2.engagement_draft(mention_text="Is it reliable?")
        assert "https://bedimsecurity.com/capabilities" not in result2["reply"]

    def test_praise_and_criticism(self, monkeypatch):
        agent = make_agent("sm-eng-2")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        praise = agent.engagement_draft(mention_text="great writeup, thanks")
        assert praise["tone"] == "praise"
        assert "Thanks" in praise["reply"]
        crit = agent.engagement_draft(
            mention_text="Interesting, however the numbers look unclear to me")
        assert crit["tone"] == "criticism"
        assert "pressure-tested" in crit["reply"]

    def test_hostile_escalates_without_reply(self, monkeypatch):
        agent = make_agent("sm-eng-3")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.engagement_draft(mention_text="pure garbage scam")
        assert result["tone"] == "hostile"
        assert result["status"] == "escalated"
        assert result["reply"] is None
        record = [m for m in agent.mentions][-1]
        assert record.responded is False
        assert result["requires_owner_send"] is True

    def test_reply_is_a_queued_draft(self, monkeypatch):
        agent = make_agent("sm-eng-4")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.engagement_draft(mention_text="does it work offline?")
        assert result["status"] == "drafted"
        queue = agent.post_queue()
        assert queue["total"] == 1


class TestListen:
    def test_tone_split_and_keywords(self):
        agent = make_agent("sm-listen-1")
        result = agent.listen_report(entries=[
            {"source": "x", "author": "a1", "text": "how do you handle detection"},
            {"source": "x", "author": "a2", "text": "great product thanks"},
            {"source": "x", "author": "a3", "text": "this is garbage scam"},
        ])
        assert result["total_mentions"] == 3
        assert result["tone_split"] == {"question": 1, "praise": 1, "hostile": 1}
        assert result["hostile_count"] == 1
        assert result["top_keywords"]

    def test_spike_detection(self):
        agent = make_agent("sm-listen-2")
        result = agent.listen_report(entries=[
            {"text": "one"}, {"text": "two"}, {"text": "three"}],
            baseline=1.0)
        assert result["spike"] is True

    def test_non_dict_entries_ignored(self):
        agent = make_agent("sm-listen-3")
        result = agent.listen_report(entries=["junk", 42, {"text": "hello there"}])
        assert result["total_mentions"] == 1


class TestMetrics:
    def test_entry_math(self):
        agent = make_agent("sm-metrics-1")
        result = agent.metrics_report(period_days=7, entries=[
            {"channel": "linkedin", "impressions": 200, "likes": 4,
             "comments": 2, "shares": 0, "clicks": 6}])
        row = result["per_channel"]["linkedin"]
        assert row["engagement_rate"] == pytest.approx(0.03)
        assert row["ctr"] == pytest.approx(0.03)
        assert row["posts"] == 1

    def test_unknown_channel_bucketed(self):
        agent = make_agent("sm-metrics-2")
        result = agent.metrics_report(entries=[
            {"channel": "wechat", "impressions": 10, "likes": 1}])
        assert "other" in result["per_channel"]

    def test_from_published_queue(self, monkeypatch):
        agent = make_agent("sm-metrics-3")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        agent.draft_post(channel="x", hook="Hi")
        agent.mark_published("POST-0001",
                             url="https://x.com/status/1",
                             metrics={"impressions": 50, "likes": 2,
                                      "comments": 0, "shares": 0, "clicks": 3})
        result = agent.metrics_report(entries=None)
        row = result["per_channel"]["x"]
        assert row["impressions"] == 50
        assert row["engagement_rate"] == pytest.approx(0.04)

    def test_benchmark_labeled_not_data(self):
        agent = make_agent("sm-metrics-4")
        result = agent.metrics_report(entries=[])
        ctx = result["benchmark_context"]
        assert ctx["labeled"] == "research anchor, not Bedim data"


class TestBrand:
    def test_banned_claims_flagged(self):
        agent = make_agent("sm-brand-1")
        monkeypatch_free = agent.brand_check(
            "Our platform is unhackable and 100% secure.")
        assert monkeypatch_free["status"] == "flagged"
        assert len(monkeypatch_free["banned_claims"]) >= 2

    def test_unsourced_number_flagged(self):
        agent = make_agent("sm-brand-2")
        result = agent.brand_check("We cut breaches 99% with this trick.")
        assert "99%" in result["unsourced_numbers"]
        assert result["status"] == "approved"  # soft flag; human decides

    def test_measured_number_passes(self):
        agent = make_agent("sm-brand-3")
        result = agent.brand_check("We measured 74% less GPU energy per decision.")
        assert result["unsourced_numbers"] == []

    def test_dead_link_flagged(self, monkeypatch):
        agent = make_agent("sm-brand-4")
        monkeypatch.setattr(agent, "_link_ok", lambda url: False)
        result = agent.brand_check("Read this: https://example.gov/dead/")
        assert result["status"] == "flagged"
        assert result["dead_links"] == ["https://example.gov/dead/"]

    def test_scrub_hits(self):
        agent = make_agent("sm-brand-5")
        result = agent.brand_check(
            "ping me at wez@stsgym.com or check /home/wez/notes")
        assert result["scrub_hits"]  # domain + email + /home path
        assert result["status"] == "flagged"

    def test_markdown_paren_urls_cleaned(self, monkeypatch):
        agent = make_agent("sm-brand-6")
        monkeypatch.setattr(agent, "_link_ok", lambda url: False)
        result = agent.brand_check("See [docs](https://example.gov/page).")
        assert result["dead_links"] == ["https://example.gov/page"]


class TestCrisis:
    def test_hold_rules_and_escalation(self):
        agent = make_agent("sm-crisis-1")
        result = agent.crisis_note(incident_summary="active incident on prod")
        assert result["hold"] and len(result["hold"]) >= 3
        assert "unhackable" in result["never_claim"]
        assert result["owner_decides"] is True
        assert result["requires_owner_send"] is True


class TestWeekSummary:
    def test_empty_state(self):
        agent = make_agent("sm-week-1")
        result = agent.week_summary()
        assert result["published_this_week"] == 0
        assert result["unanswered_mentions"] == 0

    def test_overdue_slot_counted(self):
        from agentic_ai.agents.social_media import CalendarEntry
        agent = make_agent("sm-week-2")
        agent.calendar.append(CalendarEntry(date="2026-01-01",
                                            channel="linkedin"))
        result = agent.week_summary()
        assert result["overdue_slots"] == 1


class TestPersistence:
    def test_round_trip(self, tmp_path):
        store_a = StateStore(db_path=str(tmp_path / "s.sqlite"))
        agent_a = make_agent("sm-persist-1", state_store=store_a)
        agent_a.draft_post(channel="linkedin", hook="Persist me")
        agent_a.listen_report(entries=[{"text": "hello there friend"}])

        store_b = StateStore(db_path=str(tmp_path / "s.sqlite"))
        agent_b = make_agent("sm-persist-1", state_store=store_b)
        assert agent_b.post_queue()["total"] == 1
        assert agent_b.mentions[0].text == "hello there friend"

    def test_monotonic_ids(self, tmp_path, monkeypatch):
        store = StateStore(db_path=str(tmp_path / "m.sqlite"))
        agent = make_agent("sm-id-1", state_store=store)
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        agent.draft_post(channel="x", hook="One")
        agent.draft_post(channel="x", hook="Two")
        agent_b = make_agent("sm-id-1", state_store=store)
        result = agent_b.draft_post(channel="x", hook="Three")
        assert result["post"]["post_id"] == "POST-0003"

    def test_corrupt_state_tolerated(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "c.sqlite"))
        store.save_agent_state("sm-corrupt-1", "social_media", "not-a-dict")
        agent = make_agent("sm-corrupt-1", state_store=store)
        result = agent.draft_post(channel="x", hook="After corrupt")
        assert result["status"] == "drafted"
        assert result["post"]["post_id"] == "POST-0001"

    def test_mock_store_tolerated(self, monkeypatch):
        agent = make_agent("sm-mock-1", state_store=MagicMock())
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = agent.draft_post(channel="linkedin", hook="Hi")
        assert result["status"] == "drafted"
        assert agent.state_store.save_agent_state.called


class TestDispatch:
    @pytest.mark.asyncio
    async def test_payload_positional(self, monkeypatch):
        agent = make_agent("sm-dispatch-1")
        monkeypatch.setattr(agent, "_link_ok", lambda url: True)
        result = await agent.perform_task(
            "draft_post", {"channel": "linkedin", "hook": "Payload test"})
        assert result["status"] == "drafted"

    @pytest.mark.asyncio
    async def test_unknown_type(self):
        agent = make_agent("sm-dispatch-2")
        assert "error" in await agent.perform_task("viral_mode")

    @pytest.mark.asyncio
    async def test_brand_check_via_dispatch(self):
        agent = make_agent("sm-dispatch-3")
        result = await agent.perform_task(
            "brand_check", {"text": "unhackable promise"})
        assert result["status"] == "flagged"