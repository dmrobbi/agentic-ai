"""Newsroom threat feed (KA-073 / OPT-73): the planner-side lens over the
bedimsecurity.com newsroom state - curated security stories parsed into a
daily threat-brief input for planners (the OPT-73 one-liner, verbatim).
The live JSON state is owned by the newsroom worker; THIS module never
reads it: a feed dict arrives as the argument (the OPT-73 spec injected
neither a store nor a transport, so none is accepted - no local I/O, no
fetching; a pure planner, source-scanned).

INPUT SHAPE (pinned from the live snapshot 2026-10-06; the committed
fixture tests/fixtures/scans/newsroom_feed.json is a synthetic-but-
realistic mirror of it):
  top-level: articles (required list) + archive (optional list, same rows)
  article row: id, added_at, source, title, url, category, summary
    (all strings; added_at ISO-8601 Z like 2026-10-06T20:43:59Z; url https)

INVARIANTS (pinned by tests/test_threat_feed.py):
  - brief rows order newest-first by added_at; equal timestamps keep
    id-ascending order (a stable two-pass sort)
  - duplicates collapse on the same id (exact) or the same url under a
    different id: the NEWEST added_at wins, input order breaks exact
    ties; every collapse is counted in counts["duplicates"]
  - contract-violating rows never crash the flow: they land in the
    "unusable" ledger with repr-safe reasons, id "<missing-id>" when no
    usable id string exists
  - archive rows are counted, never briefed (the newsroom worker owns
    the article->archive rotation)
  - URL rolls cap at the house cap 25 (story_links, brief headlines);
    link rows carry names + links + sources only, never long free text

OUTPUT SCHEMAS (the contracts; pinned field-by-field):
  build_brief:
  {
    "brief_date": "YYYY-MM-DD",        # day param, else latest added_at day
    "counts": {"total", "unusable", "duplicates", "usable", "briefed",
               "archived", "shown", "cves_seen", "by_category"},
    "headlines": [                     # newest-first, capped (house cap)
      {"id", "added_at", "source", "title", "url", "category", "summary",
       "tags", "cves", "priority"}    # priority high|normal
    ],
    "unusable": [{"id", "reasons"}],   # ledger rules above
    "watchlist": [id...],              # high-priority ids, newest-first
    "notes": [str...]                  # equations + honesty lines
  }
  story_links:
  {"category": None|"<scrubbed caller string>",
   "links": [{"id", "title", "url", "source", "category"}...],
   "counts": {"total", "unusable", "duplicates", "shown"},
   "truncated": bool}
  watch_target:
  {"target": str, "matches": [headline-shaped rows...],
   "counts": {"total", "unusable", "duplicates", "usable", "shown"},
   "truncated": bool}

Tag strings come from TAG_RULES - deterministic keyword matching over the
scrubbed lowercased title+summary; they describe story TEXT, never a
verified capability. CVE strings are extracted with the strict
CVE-\\d{4}-\\d{4,7} scan, deduped/sorted/uppercased; live validity is NOT
checked here. Host boundary: caller-supplied target strings are scrubbed
through tf_scrub_text and the host agent's validate_target gate is
consulted via getattr with a silent fallback when absent (house
pattern). Pure planner: no exec, no network, no local I/O."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

ARTICLE_ROW_KEYS = (
    "id", "added_at", "source", "title", "url", "category", "summary",
)
HOUSE_URL_CAP = 25
AT_RE = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
DAY_RE = r"\d{4}-\d{2}-\d{2}"
ID_RE = r"[A-Za-z0-9_.\-]{1,80}"
URL_RE = r"https://\S+"
CVE_RE = r"CVE-\d{4}-\d{4,7}"
CONTROL_RE = r"[\x00-\x1f\x7f]"

# (tag, regex over the lowercased title+summary): deterministic, ordered
TAG_RULES = (
    ("zero-day", r"zero[-\s]day|0-?day"),
    ("rce", r"remote code execution|\brce\b"),
    ("path-traversal", r"path traversal|directory traversal"),
    ("active-exploitation", r"exploited|in the wild|honeypot"),
    ("data-breach", r"\bbreach|leak|leaked|exposed|exfiltrat"),
    ("supply-chain", r"supply[-\s]chain|contractor|\bvendor\b"),
    ("credentials", r"credential|password|api key"),
    ("agentic-ai", r"prompt injection|\bagentic\b|\bagent\b|\bmcp\b"),
)
HIGH_SIGNAL_TAGS = frozenset(("zero-day", "rce", "active-exploitation"))

# external-string gate, per-field caps in contract order
FIELD_CAPS = (
    ("id", 80), ("added_at", 32), ("source", 80),
    ("title", 200), ("url", 500), ("category", 60), ("summary", 4000),
)


def _short_repr(value: Any, cap: int = 120) -> str:
    """Bounded, escape-safe rendering for error and ledger text."""
    rendered = repr(value)
    if len(rendered) > cap:
        rendered = rendered[: cap - 3] + "..."
    return rendered


def tf_scrub_text(value: Any, max_len: int = 200) -> str:
    """The shared gate for every external newsroom string (the
    wp_scrub_target pattern): non-strings, blanks, control characters
    and lengths over the field cap are rejected; clean values strip."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("rejected external string (non-string or blank): %s"
                         % _short_repr(value))
    scrubbed = value.strip()
    if re.search(CONTROL_RE, scrubbed):
        raise ValueError("rejected external string with control characters: %s"
                         % _short_repr(value))
    if len(scrubbed) > max_len:
        raise ValueError("rejected external string over the %d-char cap: %s"
                         % (max_len, _short_repr(value)))
    return scrubbed


def _cap(value: Any, default: int = HOUSE_URL_CAP) -> int:
    """The house URL cap: ints in 1..25 pass; anything else (missing,
    non-int, bool, out of range) falls back to the safe default 25."""
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value if 1 <= value <= HOUSE_URL_CAP else default


def validate_feed(feed: Dict[str, Any]) -> None:
    """Actionable ValueError on any top-level contract miss (the error
    text carries the offending keys)."""
    if not isinstance(feed, dict):
        raise ValueError("feed must be a dict of newsroom state, got: %s"
                         % type(feed).__name__)
    missing = [key for key in ("articles",) if key not in feed]
    if missing:
        raise ValueError("feed missing required keys: %s" % missing)
    if not isinstance(feed["articles"], list):
        raise ValueError("feed articles must be a list, got: %s"
                         % type(feed["articles"]).__name__)
    if "archive" in feed and not isinstance(feed["archive"], list):
        raise ValueError("feed archive must be a list, got: %s"
                         % type(feed["archive"]).__name__)


def _parse_article(row: Any):
    """Lenient row parse: (values, []) for a contract-clean row, else
    (None, [reasons...]) with every field miss reported at once."""
    if not isinstance(row, dict):
        return None, ["row is not an object"]
    reasons: List[str] = []
    vals: Dict[str, str] = {}
    for field, cap in FIELD_CAPS:
        raw = row.get(field)
        required = field != "summary"
        if raw is None and not required:
            vals[field] = ""
            continue
        if (not required and isinstance(raw, str)
                and not raw.strip()):
            vals[field] = ""
            continue
        if not isinstance(raw, str) or not raw.strip():
            if not required:
                reasons.append("summary present but not a string: %s"
                               % _short_repr(raw))
            else:
                reasons.append("%s missing or blank: %s"
                               % (field, _short_repr(raw)))
            continue
        try:
            vals[field] = tf_scrub_text(raw, max_len=cap)
        except ValueError as exc:
            reasons.append("%s rejected: %s" % (field, exc))
            continue
        if field == "id" and not re.fullmatch(ID_RE, vals[field]):
            reasons.append("id malformed: %s" % _short_repr(raw))
        elif field == "added_at" and not re.fullmatch(AT_RE, vals[field]):
            reasons.append("added_at malformed (ISO-8601 Z expected): %s"
                           % _short_repr(raw))
        elif field == "url" and not re.fullmatch(URL_RE, vals[field]):
            reasons.append("url malformed (https://... expected): %s"
                           % _short_repr(raw))
    if reasons:
        return None, reasons
    return vals, []


def _enrich(vals: Dict[str, str]) -> Dict[str, Any]:
    """Deterministic planner enrichment: TAG_RULES keywords over the
    scrubbed lowercased title+summary, strict CVE extraction, and the
    high/normal priority derived from HIGH_SIGNAL_TAGS."""
    text = "%s\n%s" % (vals["title"], vals["summary"])
    lowered = text.lower()
    tags = [tag for tag, pattern in TAG_RULES if re.search(pattern, lowered)]
    cves = sorted({hit.group(0).upper()
                   for hit in re.finditer(CVE_RE, lowered, re.I)})
    priority = "high" if set(tags) & HIGH_SIGNAL_TAGS else "normal"
    return {"tags": tags, "cves": cves, "priority": priority}


class ThreatBriefPlanner:
    """Planning-only lens over the newsroom article state: build_brief,
    story_links and watch_target turn the curated stories into threat-
    brief inputs for planners; never executes, never fetches, never
    archives (KA-073 / OPT-73)."""

    @staticmethod
    def _tf_scrub(value: Any, max_len: int = 200) -> str:
        """The thin class-side wrapper over the module tf_scrub_text
        gate (house pattern)."""
        return tf_scrub_text(value, max_len=max_len)

    def _tf_target_guard(self, target: Any) -> str:
        """Scrub the caller-supplied target string, then consult the
        host agent's validate_target via getattr (silent fallback when
        the gate is absent)."""
        label = tf_scrub_text(target, max_len=200)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(label)
            if not ok:
                raise ValueError(
                    "target rejected by host agent gate: %s" % (msg,))
        return label

    def _tf_digest(self, feed: Dict[str, Any]):
        """Shared lenient pipeline: top-level validation, the per-row
        parse into a usable/unusable split, then the newest-wins
        duplicate collapse over id and url keys."""
        validate_feed(feed)
        unusable: List[Dict[str, Any]] = []
        parsed: List[Dict[str, Any]] = []
        for row in feed["articles"]:
            vals, reasons = _parse_article(row)
            if vals is None:
                ledger_id = "<missing-id>"
                if isinstance(row, dict):
                    raw_id = row.get("id")
                    if (isinstance(raw_id, str) and raw_id.strip()
                            and re.fullmatch(ID_RE, raw_id.strip())):
                        ledger_id = raw_id.strip()
                unusable.append({"id": ledger_id, "reasons": reasons})
                continue
            enriched = dict(vals)
            enriched.update(_enrich(vals))
            parsed.append(enriched)

        deduped: List[Dict[str, Any]] = []
        by_id: Dict[str, int] = {}
        by_url: Dict[str, int] = {}
        duplicates = 0
        for row in parsed:
            idx = by_id.get(row["id"])
            if idx is None:
                idx = by_url.get(row["url"])
            if idx is None:
                by_id[row["id"]] = len(deduped)
                by_url[row["url"]] = len(deduped)
                deduped.append(row)
                continue
            duplicates += 1
            if row["added_at"] > deduped[idx]["added_at"]:
                if deduped[idx]["id"] != row["id"]:
                    by_id[row["id"]] = idx
                if deduped[idx]["url"] != row["url"]:
                    by_url[row["url"]] = idx
                deduped[idx] = row
        return deduped, unusable, duplicates, len(feed["articles"])

    @staticmethod
    def _tf_order(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Newest-first by added_at; equal timestamps keep id-ascending
        order (stable two-pass sort)."""
        ordered = sorted(rows, key=lambda row: row["id"])
        ordered.sort(key=lambda row: row["added_at"], reverse=True)
        return ordered

    def build_brief(self, feed: Dict[str, Any],
                    day: Optional[str] = None,
                    brief_size: Any = HOUSE_URL_CAP) -> Dict[str, Any]:
        """The daily threat brief: parse the newsroom articles into a
        newest-first brief with category counts, deterministic threat
        tags, extracted CVE strings, and duplicate/unusable ledgers."""
        if day is not None:
            day = tf_scrub_text(day, max_len=10)
            if not re.fullmatch(DAY_RE, day):
                raise ValueError("day filter must be YYYY-MM-DD, got: %s"
                                 % _short_repr(day))
        size = _cap(brief_size)
        usable, unusable, duplicates, total = self._tf_digest(feed)
        rows = self._tf_order(usable)
        if day is not None:
            rows = [row for row in rows if row["added_at"][:10] == day]
        brief_date = day if day is not None else (
            rows[0]["added_at"][:10] if rows else "")
        shown = rows[:size]
        by_category: Dict[str, int] = {}
        for row in rows:
            by_category[row["category"]] = (
                by_category.get(row["category"], 0) + 1)
        by_category = {key: by_category[key] for key in sorted(by_category)}
        cves_seen = sorted({cve for row in rows for cve in row["cves"]})
        watchlist = [row["id"] for row in rows if row["priority"] == "high"]
        archived = len(feed.get("archive") or [])
        notes = [
            "planning-only lens: the brief never executes and never "
            "fetches",
            "counts equation: total=%d = usable=%d + duplicates=%d + "
            "unusable=%d" % (total, len(usable), duplicates, len(unusable)),
            "category counts: %s (sum=%d = briefed=%d)" % (
                ", ".join("%s=%d" % kv for kv in by_category.items()),
                sum(by_category.values()), len(rows)),
            "headlines capped at %d (house URL cap)" % size,
            "cves: %d distinct strings extracted; live validity NOT "
            "checked here" % len(cves_seen),
            "archive rows counted, never briefed: %d" % archived,
        ]
        return {
            "brief_date": brief_date,
            "counts": {
                "total": total,
                "unusable": len(unusable),
                "duplicates": duplicates,
                "usable": len(usable),
                "briefed": len(rows),
                "archived": archived,
                "shown": len(shown),
                "cves_seen": len(cves_seen),
                "by_category": by_category,
            },
            "headlines": [dict(row) for row in shown],
            "unusable": [dict(entry) for entry in unusable],
            "watchlist": watchlist,
            "notes": notes,
        }

    def story_links(self, feed: Dict[str, Any],
                    category: Optional[str] = None,
                    limit: Any = HOUSE_URL_CAP) -> Dict[str, Any]:
        """The URL-capped story roll (names + links + sources only): one
        deduped row per story, newest-first, optionally filtered by
        category."""
        cat: Optional[str] = None
        if category is not None:
            cat = tf_scrub_text(category, max_len=60)
        size = _cap(limit)
        usable, unusable, duplicates, total = self._tf_digest(feed)
        rows = self._tf_order(usable)
        if cat is not None:
            rows = [row for row in rows
                    if row["category"].casefold() == cat.casefold()]
        links = [{"id": row["id"], "title": row["title"], "url": row["url"],
                  "source": row["source"], "category": row["category"]}
                 for row in rows[:size]]
        return {
            "category": cat,
            "links": links,
            "counts": {"total": total, "unusable": len(unusable),
                       "duplicates": duplicates, "shown": len(links)},
            "truncated": len(rows) > len(links),
        }

    def watch_target(self, feed: Dict[str, Any], target: Any,
                     limit: Any = HOUSE_URL_CAP) -> Dict[str, Any]:
        """The stories mentioning one target string: the target is
        scrubbed and the host's validate_target gate is consulted via
        getattr (silent fallback when absent) at the planner boundary."""
        label = self._tf_target_guard(target)
        size = _cap(limit)
        usable, unusable, duplicates, total = self._tf_digest(feed)
        rows = self._tf_order(usable)
        needle = label.casefold()
        matches = [row for row in rows if any(
            needle in row[field].casefold()
            for field in ("title", "summary", "url"))][:size]
        return {
            "target": label,
            "matches": [dict(row) for row in matches],
            "counts": {"total": total, "unusable": len(unusable),
                       "duplicates": duplicates, "usable": len(usable),
                       "shown": len(matches)},
            "truncated": len(rows) > len(matches),
        }
