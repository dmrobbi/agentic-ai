"""Social Media Agent — channel operations for Bedim Security (draft-only).

The channel-operations layer beside MarketingAgent (which owns campaign
strategy, budgets, and A/B testing): this agent handles the daily social
work a professional covers — calendars, platform-native drafting, community
engagement, listening rollups, and metrics — under hard house rules:

- NO posting path exists. There is no platform API client, no SMTP, and no
  network write of any kind in v1. The only network activity is READ-ONLY
  link verification (curl GET with the house linkcheck UA). Every outbound-
  facing artifact is a draft with requires_owner_send=True; publish
  bookkeeping (mark_published) records what the OWNER posted, it posts
  nothing.
- Verified links only: any URL in any output is curl-verified first; a
  link that is not live is dropped with a note (never published unverified).
- Measured numbers only: stats come from MEASURED_STATS (imported from the
  sales agent's PROOF_POINTS — one measured source fleet-wide); numbers
  outside it are flagged by brand_check, never presented as Bedim data.
- No fake engagement: no follows, likes, or inflation; the agent drafts
  replies for the owner's account and voice.
- No PII out: drafts pass the house scrub patterns (internal hostnames,
  /home paths, emails).

Persistence mirrors the sales agent: lazy-load + eager-save through a real
state_store (save_agent_state), monotonic ids rebuilt from persisted
records, corrupt or mocked stores tolerated, in-memory without one.
"""

import datetime
import json
import logging
import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from agentic_ai.agents.base import BaseAgent, Permission
from agentic_ai.agents.sales import PROOF_POINTS as MEASURED_STATS

logger = logging.getLogger(__name__)


class Channel:
    """Social channels (string values kept stable for serialization)."""

    LINKEDIN = "linkedin"
    X = "x"
    MASTODON = "mastodon"
    BLUESKY = "bluesky"
    OTHER = "other"

    @classmethod
    def values(cls) -> List[str]:
        return [v for k, v in vars(cls).items() if k.isupper()]


class PostStatus:
    """Post draft lifecycle (recorded states; nothing auto-advances)."""

    DRAFTED = "drafted"
    OWNER_APPROVED = "owner_approved"
    HANDED_OFF = "handed_off"
    PUBLISHED = "published"
    ARCHIVED = "archived"

    @classmethod
    def values(cls) -> List[str]:
        return [v for k, v in vars(cls).items() if k.isupper()]


# Weekly slot cadence per channel (research anchors: consistency beats
# volume; LinkedIn-first for B2B security).
CADENCE: Dict[str, Dict[str, Any]] = {
    Channel.LINKEDIN: {"weekly": 3, "peak": "Tue-Thu mornings"},
    Channel.X: {"weekly": 4, "peak": "weekday mornings"},
    Channel.MASTODON: {"weekly": 2, "peak": "weekday afternoons"},
    Channel.BLUESKY: {"weekly": 2, "peak": "weekday mornings"},
}

# Hard character limits per channel (platform rules; linkedin gets a soft
# cap well under the platform's ~3000 to keep posts readable).
LIMITS: Dict[str, int] = {
    Channel.LINKEDIN: 2900,
    Channel.X: 280,
    Channel.MASTODON: 500,
    Channel.BLUESKY: 300,
    Channel.OTHER: 1000,
}

# Hashtag policy per newsroom category (<=3, no bait tags).
CATEGORY_HASHTAGS: Dict[str, List[str]] = {
    "Compliance": ["#compliance", "#grc", "#soc2"],
    "Agentic AI": ["#agenticai", "#soc", "#automation"],
    "Cyber Controls": ["#cybersecurity", "#soc", "#controls"],
    "Policy": ["#cyberpolicy", "#regulation", "#compliance"],
}

# Banned claim / bait patterns (brand_check flags these; the human decides).
BANNED_CLAIMS: List[str] = [
    r"super\s?-?intelligen", r"unhackable", r"unbreakable", r"bulletproof",
    r"\b100%\s+secure\b", r"cannot be (hacked|breached)", r"can'?t? be hack",
    r"impossible to breach", r"guaranteed? (security|protection|uptime)",
    r"follow (me|us) to", r"\blike if\b", r"comment (yes|below)", r"\brt if\b",
]

# Scrub patterns: internal identifiers never appear in draft text.
SCRUB_PATTERNS: List[str] = [
    r"stgym", r"stsgym", r"wezzel", r"mailcow", r"\.openclaw", r"/home/[a-z]+",
    r"\bidm\.", r"127\.0\.0\.1", r"192\.168\.",
]

TONE_RULES: Dict[str, str] = {
    "question": "answer concretely from published material; cite live links only",
    "praise": "thank specific and brief; offer the capabilities page when relevant",
    "criticism": "acknowledge the specific point; offer the published measure; never defensive",
    "hostile": "no reply; escalate to the owner",
    "other": "match the register; stay technical and calm",
}

CAPABILITIES_URL = "https://bedimsecurity.com/capabilities"

# Research source pointer for benchmark CONTEXT (no numbers are stated in
# code - they are compared in the owner-facing report only if entered).
BENCHMARK_SOURCE = {
    "name": "Oktopost B2B LinkedIn benchmark report Q1 2026",
    "url": "https://www.oktopost.com/blog/linkedin-benchmarks-by-industry-april-2026/",
    "labeled": "research anchor, not Bedim data",
}

LINKCHECK_UA = "Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)"
NEWS_STATE = "/home/wez/.openclaw/soc/news/bedim-news.json"


@dataclass
class PostDraft:
    """A social post draft. ALWAYS draft-only; the owner sends."""
    post_id: str
    channel: str
    body: str
    link: str = ""
    hashtags: List[str] = field(default_factory=list)
    status: str = PostStatus.DRAFTED
    requires_owner_send: bool = True
    created_at: datetime = field(default_factory=datetime.datetime.now)
    slot: Optional[str] = None  # ISO date binding a calendar slot
    notes: List[str] = field(default_factory=list)
    metrics: Optional[Dict[str, Any]] = None
    published_url: str = ""
    published_at: Optional[datetime] = None


@dataclass
class CalendarEntry:
    """One planned slot in the posting calendar (work plan, not a scheduler)."""
    date: str  # ISO date
    channel: str
    slot_kind: str = "post"  # post | proof-point | story-repurpose
    proposed_post_id: str = ""
    notes: str = ""


@dataclass
class MentionRecord:
    """A social mention seen by a human and fed to the listener."""
    mention_id: str
    source: str = ""
    author: str = ""
    text: str = ""
    tone: str = "other"
    seen_at: datetime = field(default_factory=datetime.datetime.now)
    responded: bool = False
    notes: str = ""


class SocialMediaAgent(BaseAgent):
    """Social media agent: calendars, drafts, engagement, listening, metrics.

    Draft-only by construction: see module docstring for the hard rules.
    """

    agent_type = "social_media"
    permission = Permission.STANDARD

    def __init__(self, agent_id: Optional[str] = None, name: Optional[str] = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 news_state: str = NEWS_STATE) -> None:
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.news_state = news_state
        self.posts: List[PostDraft] = []
        self.calendar: List[CalendarEntry] = []
        self.mentions: List[MentionRecord] = []
        self._seq: Dict[str, int] = {"post": 0, "mention": 0}
        self._loaded = False
        self._tools = {
            "content_calendar": self.content_calendar,
            "repurpose": self.repurpose,
            "draft_post": self.draft_post,
            "post_queue": self.post_queue,
            "mark_status": self.mark_status,
            "mark_published": self.mark_published,
            "engagement_draft": self.engagement_draft,
            "listen_report": self.listen_report,
            "metrics_report": self.metrics_report,
            "brand_check": self.brand_check,
            "crisis_note": self.crisis_note,
            "week_summary": self.week_summary,
        }

    # ============================================
    # Persistence (mirrors the sales agent)
    # ============================================

    def _ensure_loaded(self) -> None:
        if self._loaded or self.state_store is None:
            return
        self._loaded = True
        try:
            state = self.state_store.get_agent_state(self.agent_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SocialMediaAgent: load failed, starting empty: %s", exc)
            return
        if not isinstance(state, dict) or not any(
                k in state for k in ("posts", "mentions", "calendar")):
            return
        self._deserialize(state)

    def _persist(self) -> None:
        if self.state_store is None:
            return
        try:
            self.state_store.save_agent_state(self.agent_id, self.agent_type,
                                              self._serialize())
        except Exception as exc:  # noqa: BLE001
            logger.warning("SocialMediaAgent: save failed: %s", exc)

    def _serialize(self) -> Dict[str, Any]:
        return {
            "posts": [self._dump_post(p) for p in self.posts],
            "calendar": [asdict(c) for c in self.calendar],
            "mentions": [self._dump_mention(m) for m in self.mentions],
            "seq": self._seq,
        }

    @staticmethod
    def _dt(value: Any) -> Optional[datetime.datetime]:
        if value is None or isinstance(value, datetime.datetime):
            return value
        try:
            return datetime.datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            return None

    @classmethod
    def _dump_post(cls, post: PostDraft) -> Dict[str, Any]:
        data = asdict(post)
        data["created_at"] = post.created_at.isoformat()
        data["published_at"] = post.published_at.isoformat() if post.published_at else None
        return data

    @classmethod
    def _load_post(cls, data: Dict[str, Any]) -> PostDraft:
        return PostDraft(
            post_id=data.get("post_id", ""),
            channel=data.get("channel", Channel.OTHER),
            body=data.get("body", ""),
            link=data.get("link", ""),
            hashtags=list(data.get("hashtags", [])),
            status=data.get("status", PostStatus.DRAFTED),
            requires_owner_send=bool(data.get("requires_owner_send", True)),
            created_at=cls._dt(data.get("created_at")) or datetime.datetime.now(),
            slot=data.get("slot"),
            notes=list(data.get("notes", [])),
            metrics=data.get("metrics") if isinstance(data.get("metrics"), dict) else None,
            published_url=data.get("published_url", ""),
            published_at=cls._dt(data.get("published_at")),
        )

    @classmethod
    def _dump_mention(cls, mention: MentionRecord) -> Dict[str, Any]:
        data = asdict(mention)
        data["seen_at"] = mention.seen_at.isoformat()
        return data

    @classmethod
    def _load_mention(cls, data: Dict[str, Any]) -> MentionRecord:
        return MentionRecord(
            mention_id=data.get("mention_id", ""),
            source=data.get("source", ""),
            author=data.get("author", ""),
            text=data.get("text", ""),
            tone=data.get("tone", "other"),
            seen_at=cls._dt(data.get("seen_at")) or datetime.datetime.now(),
            responded=bool(data.get("responded", False)),
            notes=data.get("notes", ""),
        )

    def _deserialize(self, state: Dict[str, Any]) -> None:
        seq = state.get("seq")
        self._seq = seq if isinstance(seq, dict) else {"post": 0, "mention": 0}
        self.posts = [self._load_post(e) for e in state.get("posts", []) if isinstance(e, dict)]
        self.calendar = [CalendarEntry(**{k: v for k, v in e.items()
                                          if k in CalendarEntry.__dataclass_fields__})
                         for e in state.get("calendar", []) if isinstance(e, dict)]
        self.mentions = [self._load_mention(e) for e in state.get("mentions", []) if isinstance(e, dict)]
        counts = {
            "post": ("POST-", [p.post_id for p in self.posts]),
            "mention": ("MENT-", [m.mention_id for m in self.mentions]),
        }
        for kind, (prefix, ids) in counts.items():
            max_seen = int(self._seq.get(kind, 0))
            for value in ids:
                text = str(value)
                if text.startswith(prefix):
                    try:
                        max_seen = max(max_seen, int(text[len(prefix):]))
                    except ValueError:
                        continue
            self._seq[kind] = max_seen

    def _next_id(self, prefix: str, kind: str) -> str:
        self._seq[kind] = int(self._seq.get(kind, 0)) + 1
        return f"{prefix}{self._seq[kind]:04d}"

    # ============================================
    # Link verification (the only network activity: read-only GET)
    # ============================================

    def _link_ok(self, url: str) -> bool:
        if not url:
            return False
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-A", LINKCHECK_UA, "--max-time", "10", url],
                capture_output=True, text=True, timeout=15)
            code = int((result.stdout or "0").strip() or 0)
            return 200 <= code < 400
        except Exception:  # noqa: BLE001
            return False

    # ============================================
    # Text helpers
    # ============================================

    @staticmethod
    def _first_sentences(text: str, max_chars: int) -> str:
        text = re.sub(r"\s+", " ", (text or "").strip())
        if len(text) <= max_chars:
            return text
        cut = text[:max_chars]
        if "." in cut:
            cut = cut.rsplit(".", 1)[0]
            if len(cut) > max_chars // 4:
                return cut + "."
        return cut.rsplit(" ", 1)[0] + "..."

    @staticmethod
    def _classify_tone(text: str) -> str:
        text = (text or "").lower()
        if re.search(r"trash|garbage|idiot|scam|fake|liar|shut up|moron", text):
            return "hostile"
        if re.search(r"\?|\bhow do\b|\bcan you\b|\bdoes it\b|\bis it\b", text):
            return "question"
        if re.search(r"\b(great|thanks|thank you|nice|love|excellent|helpful|solid)\b", text):
            return "praise"
        if re.search(r"\b(wrong|incorrect|actually|however|concern|hmm)\b", text):
            return "criticism"
        return "other"

    @classmethod
    def _hashtags_for(cls, category: str) -> List[str]:
        return CATEGORY_HASHTAGS.get(category, CATEGORY_HASHTAGS["Cyber Controls"])[:3]

    def _unsourced_numbers(self, text: str) -> List[str]:
        """Percent/multiplier claims not backed by MEASURED_STATS."""
        stats_blob = " ".join(MEASURED_STATS).lower()
        flagged = []
        for match in re.finditer(r"\d+(?:\.\d+)?%|\d+(?:\.\d+)?x\b", text):
            token = match.group(0)
            window = text[max(0, match.start() - 60):match.end() + 60].lower()
            if token.lower() not in stats_blob and _core(token) not in stats_blob \
                    and not any(part in stats_blob for part in _tokens(token)):
                flagged.append(token)
        return flagged

    def _scrub_hits(self, text: str) -> List[str]:
        hits = []
        for pattern in SCRUB_PATTERNS:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                hits.append(match.group(0))
        hits += ["<email> " + m.group(0) for m in
                 re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)]
        return hits

    def _banned_hits(self, text: str) -> List[str]:
        hits = []
        for pattern in BANNED_CLAIMS:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                hits.append(match.group(0))
        return hits

    def _validate_length(self, channel: str, body: str) -> Dict[str, Any]:
        limit = LIMITS.get(channel, LIMITS[Channel.OTHER])
        notes: List[str] = []
        if len(body) > limit:
            body = self._first_sentences(body, limit - 20)
            if len(body) > limit:
                body = body[:limit - 20] + "..."
            notes.append(f"trimmed to fit {channel} ({limit} chars)")
        return {"body": body, "notes": notes}

    def _append(self, post: PostDraft) -> None:
        self.posts.append(post)
        self._persist()

    # ============================================
    # Calendar
    # ============================================

    def content_calendar(self, days: int = 7, channels: Optional[List[str]] = None,
                         seed_articles: Optional[List[str]] = None) -> Dict[str, Any]:
        """Plan calendar slots for the window: weekly cadence, weekdays only.

        The calendar is the owner's work plan - no slot posts anything.
        seed_articles optionally binds the newest newsroom story ids to
        the first slots (story-repurpose kind).
        """
        days = int(max(1, min(int(days), 28)))
        channels = channels or [Channel.LINKEDIN, Channel.X]
        unknown = [c for c in channels if c not in CADENCE and c != Channel.OTHER]
        if unknown:
            return {"error": f"Unknown channel(s): {unknown}",
                    "valid_channels": list(CADENCE.keys())}
        today = datetime.date.today()
        weekday_dates = [today + datetime.timedelta(days=i)
                         for i in range(days)
                         if (today + datetime.timedelta(days=i)).weekday() < 5]
        entries: List[CalendarEntry] = []
        seed_iter = list(seed_articles or [])
        for channel in channels:
            weekly = CADENCE.get(channel, {}).get("weekly", 1)
            n_slots = -(-days * weekly // 7)  # ceil
            n_slots = min(n_slots, len(weekday_dates))
            for i, date in enumerate(weekday_dates[:max(n_slots, 0)]):
                proposed = seed_iter.pop(0) if seed_iter else ""
                entries.append(CalendarEntry(
                    date=date.isoformat(), channel=channel,
                    slot_kind="story-repurpose" if proposed else "post",
                    proposed_post_id=proposed,
                    notes=CADENCE.get(channel, {}).get("peak", "")))
        self.calendar = entries
        self._persist()
        return {"status": "ok", "days": days,
                "entries": [asdict(e) for e in entries],
                "note": "Work plan only - no slot posts anything by itself."}

    # ============================================
    # Repurpose + drafting
    # ============================================

    def repurpose(self, article_id: str = "") -> Dict[str, Any]:
        """Turn a newsroom article into platform-native DRAFTS of one story.

        The article's URL is curl-verified first; a dead link skips the
        story entirely (never publish an unverified link). Only the
        article's own title/summary/source fields are used.
        """
        self._ensure_loaded()
        article = None
        try:
            with open(self.news_state) as f:
                state = json.load(f)
        except (OSError, ValueError):
            return {"error": f"newsroom state unreadable at {self.news_state}"}
        for pool in ("articles", "archive"):
            for candidate in state.get(pool, []):
                if candidate.get("id") == article_id:
                    article = candidate
                    break
            if article:
                break
        if article is None:
            return {"error": f"Article {article_id!r} not found in newsroom state"}
        url = article.get("url", "")
        if not self._link_ok(url):
            return {"status": "skipped", "article_id": article_id,
                    "reason": "link not live - nothing drafted",
                    "url": url}
        title = article.get("title", "")
        summary = article.get("summary", "")
        source = article.get("source", "")
        category = article.get("category", "")
        hashtags = self._hashtags_for(category)
        drafts: List[PostDraft] = []
        plans = [
            (Channel.LINKEDIN, lambda: "\n\n".join([
                self._first_sentences(title, 120),
                self._first_sentences(summary, 420),
                f"Source: {source}",
                url,
                " ".join(hashtags),
            ])),
            (Channel.X, lambda: " ".join(
                [self._first_sentences(title, LIMITS[Channel.X] - len(url) - 4),
                 url])),
            (Channel.MASTODON, lambda: "\n\n".join([
                self._first_sentences(title, 110),
                self._first_sentences(summary, 240),
                url,
                " ".join(hashtags),
            ])),
            (Channel.BLUESKY, lambda: "\n\n".join([
                self._first_sentences(title, 90),
                url,
                self._first_sentences(" ".join(hashtags), 80),
            ])),
        ]
        for channel, builder in plans:
            body = builder()
            checked = self._validate_length(channel, body)
            drafts.append(PostDraft(
                post_id=self._next_id("POST-", "post"),
                channel=channel, body=checked["body"], link=url,
                hashtags=hashtags if channel in (Channel.LINKEDIN,
                                                 Channel.MASTODON) else [],
                notes=checked["notes"],
            ))
        for post in drafts:
            self._append(post)
        return {"status": "repurposed", "article_id": article_id,
                "drafts": [self._post_summary(p) for p in drafts],
                "gates": {"links_verified": True, "requires_owner_send": True}}

    def draft_post(self, channel: str = "", hook: str = "", angle: str = "",
                   link: str = "", hashtags: Optional[List[str]] = None,
                   slot: Optional[str] = None) -> Dict[str, Any]:
        """Draft one generic post (draft-only; the owner sends it)."""
        channel = (channel or "").strip().lower()
        if channel not in Channel.values():
            return {"error": f"Unknown channel {channel!r}",
                    "valid_channels": Channel.values()}
        if not hook.strip() and not (link or "").strip():
            return {"error": "a draft needs at least a hook or a link"}
        self._ensure_loaded()
        notes: List[str] = []
        if link:
            if not self._link_ok(link):
                link = ""
                notes.append("link dropped (not live)")
        parts = [hook.strip(), angle.strip()] if angle.strip() else [hook.strip()]
        if link:
            parts.append(link)
        hashtags = [tag for tag in (hashtags or []) if tag][:3]
        if hashtags:
            parts.append(" ".join(hashtags))
        body = "\n".join(p for p in parts if p)
        checked = self._validate_length(channel, body)
        post = PostDraft(post_id=self._next_id("POST-", "post"),
                         channel=channel, body=checked["body"], link=link,
                         hashtags=hashtags, slot=slot,
                         notes=[*notes, *checked["notes"]])
        self._append(post)
        return {"status": "drafted", "post": self._post_summary(post),
                "requires_owner_send": True}

    @staticmethod
    def _post_summary(post: PostDraft) -> Dict[str, Any]:
        return asdict(post)

    # ============================================
    # Queue bookkeeping (records owner actions; performs none)
    # ============================================

    def post_queue(self) -> Dict[str, Any]:
        """The owner's work list: all drafts grouped by status."""
        self._ensure_loaded()
        by_status: Dict[str, int] = {}
        for post in self.posts:
            by_status[post.status] = by_status.get(post.status, 0) + 1
        return {"status": "ok", "total": len(self.posts),
                "by_status": by_status,
                "posts": [self._post_summary(p)
                          for p in sorted(self.posts, key=lambda p: p.post_id)],
                "note": "Every item requires_owner_send; this agent posts nothing."}

    def _find_post(self, post_id: str) -> Optional[PostDraft]:
        for post in self.posts:
            if post.post_id == post_id:
                return post
        return None

    def mark_status(self, post_id: str = "", status: str = "") -> Dict[str, Any]:
        """Record an owner decision on a draft (approve/hand-off/archive)."""
        status = (status or "").strip().lower()
        if status == PostStatus.PUBLISHED:
            return {"error": "use mark_published to record an actual publish"}
        if status not in (PostStatus.OWNER_APPROVED, PostStatus.HANDED_OFF,
                          PostStatus.ARCHIVED):
            return {"error": f"Unknown status {status!r}",
                    "valid": [PostStatus.OWNER_APPROVED, PostStatus.HANDED_OFF,
                              PostStatus.ARCHIVED]}
        self._ensure_loaded()
        post = self._find_post(post_id)
        if post is None:
            return {"error": f"Post {post_id} not found"}
        post.status = status
        self._persist()
        return {"status": "recorded", "post_id": post_id, "post_status": status}

    def mark_published(self, post_id: str = "", url: str = "",
                       metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Record that the OWNER posted this draft (data entry, not an action)."""
        self._ensure_loaded()
        post = self._find_post(post_id)
        if post is None:
            return {"error": f"Post {post_id} not found"}
        post.status = PostStatus.PUBLISHED
        post.published_url = url
        post.published_at = datetime.datetime.now()
        if metrics is not None:
            post.metrics = metrics if isinstance(metrics, dict) else None
        self._persist()
        return {"status": "recorded", "post_id": post_id,
                "post_status": PostStatus.PUBLISHED,
                "published_url": post.published_url}

    # ============================================
    # Engagement
    # ============================================

    def engagement_draft(self, mention_text: str = "", channel: str = Channel.X,
                         tone_hint: str = "") -> Dict[str, Any]:
        """Draft (never send) a reply to a social mention.

        Hostile mentions are NOT replied to - they escalate to the owner.
        Links cited in a reply are curl-verified; dead links are dropped.
        """
        tone = (tone_hint or self._classify_tone(mention_text) or "other").lower()
        self._ensure_loaded()
        record = MentionRecord(
            mention_id=self._next_id("MENT-", "mention"),
            source=channel, text=mention_text, tone=tone,
            responded=tone != "hostile")
        self.mentions.append(record)
        if tone == "hostile":
            record.notes = "escalated: no reply drafted"
            self._persist()
            return {"status": "escalated", "mention_id": record.mention_id,
                    "tone": tone, "reply": None,
                    "note": "Hostile mention - no reply drafted; the human decides.",
                    "requires_owner_send": True}
        link = CAPABILITIES_URL
        if not self._link_ok(link):
            link = ""
        if tone == "question":
            reply = ((f"Concrete answer: the capability overview with the "
                      f"measured numbers is here: {link}" if link else
                      "Concrete answer: published pages carry the measured "
                      "numbers (link dropped - not live).")
                     + " Happy to go deeper on the part that matters to you.")
        elif tone == "praise":
            reply = (f"Thanks - glad it reads well. The full measured build is "
                     f"here: {link}" if link else
                     "Thanks - glad it reads well.")
        elif tone == "criticism":
            reply = (f"Fair point. The published measure behind it is here: "
                     f"{link} - tell me which part you want pressure-tested "
                     f"and I will bring the raw numbers." if link else
                     "Fair point. Tell me which part you want pressure-tested "
                     "and the raw numbers will follow (published link dropped: "
                     "not live).")
        else:
            reply = "Good question - short and technical, no marketing fluff."
        checked = self._validate_length(channel, reply)
        draft = PostDraft(post_id=self._next_id("POST-", "post"),
                          channel=channel, body=checked["body"],
                          notes=["engagement-reply; tone=%s" % tone, *checked["notes"]])
        self._append(draft)
        self._persist()
        return {"status": "drafted", "mention_id": record.mention_id,
                "tone": tone, "reply": draft.body,
                "post_id": draft.post_id, "requires_owner_send": True,
                "note": "Draft only - nothing is sent by this agent."}

    # ============================================
    # Listening + metrics
    # ============================================

    def listen_report(self, entries: Optional[List[Dict[str, Any]]] = None,
                      baseline: float = 0.0) -> Dict[str, Any]:
        """Roll up owner-fed mentions: tone split, keywords, spike, unanswered.

        v1 takes entries the owner pasted; scraping/API listening is v2.
        """
        self._ensure_loaded()
        rows_in = [e for e in (entries or []) if isinstance(e, dict)]
        count = len(rows_in)
        for entry in rows_in:
            record = MentionRecord(
                mention_id=self._next_id("MENT-", "mention"),
                source=entry.get("source", ""),
                author=entry.get("author", ""),
                text=entry.get("text", ""),
                tone=(entry.get("tone") or self._classify_tone(entry.get("text", ""))).lower(),
            )
            self.mentions.append(record)
        self._persist()
        recent = self.mentions[-count:] if count else []
        tone_split: Dict[str, int] = {}
        for record in recent:
            tone_split[record.tone] = tone_split.get(record.tone, 0) + 1
        stop = {"the", "a", "and", "is", "to", "of", "in", "it", "for", "on",
                "this", "that", "with", "as", "at", "be", "are", "was"}
        keywords: Dict[str, int] = {}
        for record in recent:
            for word in re.findall(r"[a-z][a-z-]{3,}", record.text.lower()):
                if word not in stop:
                    keywords[word] = keywords.get(word, 0) + 1
        total = len(recent)
        spike = bool(baseline and total > baseline * 1.5)
        return {"status": "ok", "total_mentions": total,
                "tone_split": tone_split,
                "top_keywords": sorted(keywords.items(), key=lambda kv: -kv[1])[:10],
                "hostile_count": tone_split.get("hostile", 0),
                "spike": spike, "baseline": baseline,
                "note": "v1 listens from owner-fed entries; API listening is v2."}

    def metrics_report(self, period_days: int = 7,
                       entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """KPI rollup over owner-entered per-post outcomes.

        Engagement rate = (likes + comments + shares) / impressions; CTR =
        clicks / impressions. Benchmark context is labeled a RESEARCH anchor,
        never presented as Bedim's own data.
        """
        period_days = int(max(1, min(int(period_days), 90)))
        self._ensure_loaded()
        if entries is not None:
            rows = [e for e in entries if isinstance(e, dict)]
        else:
            cutoff = datetime.datetime.now() - datetime.timedelta(days=period_days)
            source = [p for p in self.posts
                      if p.status == PostStatus.PUBLISHED
                      and p.published_at and p.published_at >= cutoff]
            rows = [dict({"channel": p.channel, **(p.metrics or {})})
                    for p in source]
        agg: Dict[str, Dict[str, float]] = {}
        for row in rows:
            channel = (row.get("channel") or Channel.OTHER).strip().lower()
            if channel not in Channel.values():
                channel = Channel.OTHER
            bucket = agg.setdefault(channel, {"impressions": 0.0, "likes": 0.0,
                                              "comments": 0.0, "shares": 0.0,
                                              "clicks": 0.0, "posts": 0.0})
            bucket["posts"] += 1
            for key in ("impressions", "likes", "comments", "shares", "clicks"):
                bucket[key] += float(row.get(key, 0) or 0)
        per_channel = {}
        for channel, bucket in agg.items():
            impressions = bucket["impressions"]
            engagement = bucket["likes"] + bucket["comments"] + bucket["shares"]
            per_channel[channel] = {
                "posts": int(bucket["posts"]),
                "impressions": int(impressions),
                "engagements": int(engagement),
                "clicks": int(bucket["clicks"]),
                "engagement_rate": round(engagement / impressions, 4) if impressions else None,
                "ctr": round(bucket["clicks"] / impressions, 4) if impressions else None,
            }
        totals = {k: sum(v[k] for v in per_channel.values())
                  for k in ("posts", "impressions", "engagements", "clicks")}
        return {"status": "ok", "period_days": period_days,
                "per_channel": per_channel,
                "totals": totals,
                "benchmark_context": {**BENCHMARK_SOURCE},
                "note": "Rates are computed from owner-entered outcomes; "
                        "benchmark context is a research anchor, not Bedim data."}

    # ============================================
    # Brand safety
    # ============================================

    def brand_check(self, text: str = "") -> Dict[str, Any]:
        """Pre-flight any draft text: banned claims, unsourced numbers,
        live links, scrub patterns."""
        self._ensure_loaded()
        hits_banned = self._banned_hits(text)
        unsourced = self._unsourced_numbers(text)
        scrub = self._scrub_hits(text)
        links: List[Dict[str, Any]] = []
        for url in re.findall(r"https?://\S+", text):
            links.append({"url": url, "live": self._link_ok(url)})
        dead = [l["url"] for l in links if not l["live"]]
        approved = not (hits_banned or dead or scrub)
        return {"status": "approved" if approved else "flagged",
                "banned_claims": hits_banned,
                "unsourced_numbers": unsourced,
                "scrub_hits": scrub,
                "links": links,
                "dead_links": dead,
                "note": "unsourced numbers are suggestions - the human decides"}

    def crisis_note(self, incident_summary: str = "") -> Dict[str, Any]:
        """Hold-rules and template language during an active incident."""
        self._ensure_loaded()
        return {"status": "ok",
                "incident_summary": incident_summary,
                "hold": ["pause scheduled posts",
                         "pause queued drafts (do not approve while uncertain)",
                         "no speculation about cause, scope, or blame"],
                "template_first_line": ("We are aware of reports affecting "
                                        "our services and are actively "
                                        "investigating. The human supervisor "
                                        "owns this account - updates follow "
                                        "as facts land."),
                "never_claim": ["unhackable", "100% secure",
                                "super intelligence"],
                "owner_decides": True,
                "requires_owner_send": True}

    def week_summary(self) -> Dict[str, Any]:
        """Owner-facing snapshot: queue, published week, overdue slots, mentions."""
        self._ensure_loaded()
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(days=7)
        published_week = [p for p in self.posts
                          if p.status == PostStatus.PUBLISHED
                          and p.published_at and p.published_at >= cutoff]
        today_iso = datetime.date.today().isoformat()
        overdue = [asdict(e) for e in self.calendar
                   if e.date < today_iso and not e.proposed_post_id]
        unanswered = [m for m in self.mentions
                      if not m.responded and m.tone != "hostile"]
        hostile = [m for m in self.mentions if m.tone == "hostile"]
        by_status: Dict[str, int] = {}
        for post in self.posts:
            by_status[post.status] = by_status.get(post.status, 0) + 1
        return {"status": "ok",
                "queue": {"total": len(self.posts), "by_status": by_status},
                "published_this_week": len(published_week),
                "overdue_slots": len(overdue),
                "unanswered_mentions": len(unanswered),
                "hostile_mentions": len(hostile),
                "requires_owner_send": True}

    # ============================================
    # Dispatch
    # ============================================

    async def perform_task(self, task_type: str = "",
                           payload: Optional[Dict[str, Any]] = None,
                           *args, **kwargs) -> Dict[str, Any]:
        """Dispatch a task by type; payload is merged into kwargs."""
        merged: Dict[str, Any] = {**(payload or {}), **kwargs}
        handler = self._tools.get(task_type if task_type else "")
        if handler is None:
            return {"error": f"Unknown task type: {task_type}"}
        try:
            result = handler(**merged)
        except TypeError as exc:
            return {"error": f"Bad arguments for '{task_type}': {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}
        return dict(result) if isinstance(result, dict) else {"result": result}


def _core(token: str) -> str:
    """Strip %/x so '74%' can match a stats blob that says '74 percent-less'."""
    return token.rstrip("%").rstrip("x").strip()


def _tokens(token: str) -> List[str]:
    parts = [token, _core(token)]
    if token.endswith("%"):
        parts.append(token[:-1])
    return parts