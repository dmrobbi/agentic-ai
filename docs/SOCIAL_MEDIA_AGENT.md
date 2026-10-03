# Social Media Agent — capability design

Status: DESIGN (approved capabilities go to implementation next).
Date: 2026-10-03. Author: fleet (Dawn Robbins's agent), per owner request.

## Why this agent exists

Bedim Security already runs the content engine (the agentic newsroom curates
real security policy stories, the capabilities page carries the measured
proof, the digest handles email). What a company still needs on top of that
is the social layer: the channel where the market actually sees the work and
where conversations start. This design maps what a professional social media
person does for a company onto the fleet — under the house rules: nothing
leaves the machine without the human approving it, and only measured numbers
are ever published.

## What a social media professional does (research synthesis)

Sources: B2B social guides 2026 (SocialwithRyan, Limadata, Kihan), cyber
domain guides (HackerContent's cyber social + founder-led marketing guides,
the Duo Security LinkedIn case analysis), platform research (Oktopost B2B
statistics and Q1 2026 LinkedIn benchmark report, Socialinsider platform
guide), pipeline-focused B2B social frameworks (Konecny; the "attention into
pipeline" school).

The job decomposes into eight domains:

1. **Strategy & planning** — audience and platform mix, positioning, cadence.
   B2B reality: LinkedIn dominates B2B social lead flow (Oktopost/co-research
   place ~80%+ of B2B social leads there); for a security vendor LinkedIn is
   the primary channel, X/Twitter is the infosec community space, plus
   lightweight fediverse presence (Mastodon/Bluesky) where security people
   actually are. Consistency beats volume.
2. **Content creation** — platform-native variants, not cross-posted clones.
   Repurpose long-form (newsroom stories, Laya reports, capability pages)
   into short hooks. Cyber-audience note (HackerContent): a skeptical, anti-
   marketing crowd; content must not read like a compliance memo; authority
   comes from technical depth and real numbers.
3. **Publishing & scheduling** — the calendar: slots per channel per week,
   consistent cadence (research anchors roughly 2-5 posts/week per channel),
   scheduling around audience time zones.
4. **Community engagement** — replies, comments, mention handling in the
   brand voice, fast and human; escalate hostile/critical conversations.
5. **Social listening** — brand/keyword/competitor monitoring, mention
   rollups, spike detection, sentiment split.
6. **Analytics & reporting** — engagement rate, link CTR, follower quality,
   share of voice — and the B2B discipline: social metrics tie to PIPELINE,
   not vanity counts. (Our first-party newsroom counters already measure
   site clicks; social CTR should join that story.)
7. **Advocacy / founder-led support** — founder-led content outperforms face-
   less corporate posting in cyber (HackerContent founder-led guide): the
   agent preps the founder's posts and materials; the human is the author.
8. **Brand safety & crisis** — hold-rules during an incident, what not to
   claim ever (no "unhackable", no invented stats), escalation paths.

## Boundary with the existing MarketingAgent

`MarketingAgent` owns campaign STRATEGY (campaign types incl. social,
budgets, A/B). The `SocialMediaAgent` owns channel OPERATIONS: the daily
work of calendars, platform-native drafting, engagement, listening, and
metric rollups. Marketing hands it a campaign theme; social executes
content. Social never sets budgets or campaign strategy. No changes to
marketing.py in v1.

## Capability design — v1 (deterministic, zero credentials, draft-only)

Class `SocialMediaAgent` (module `agentic_ai.agents.social_media`), category
"Business", permission STANDARD. Persistence identical in shape to the sales
agent's: lazy-load + eager-save via `state_store`, monotonic ids rebuilt
from persisted records, corrupt/mock stores tolerated, in-memory without one.

Core types:

- `Channel` enum: linkedin / x / mastodon / bluesky / other.
- `PostStatus` enum: drafted / owner_approved / handed_off / published /
  archived (recorded, never auto-advanced).
- `PostDraft`: post_id, channel, body, link, hashtags, status,
  requires_owner_send=True constant, created_at, slot, metrics (Optional
  owner-entered dict).
- `CalendarEntry`: date, channel, slot_kind, proposed_post_id, notes.
- `MentionRecord`: source, author, text, tone (question/praise/criticism/
  hostile/other), seen_at, responded (bool), notes.

Ops (all docstring'd for the CLI card; all sync except perform_task):

1. `content_calendar(days, channels=None)` — generate the calendar: slots
   from the CADENCE table (per channel, per week), seeded with anchor
   placeholders (newsroom newest stories get first claim on slots), returns
   entries + persists. No slot is ever "scheduled" to post by itself; the
   calendar is the owner's work plan.
2. `repurpose(article_id)` — pull a newsroom article from the local newsroom
   state (read-only read of ~/.openclaw/soc/news/bedim-news.json shape) and
   produce platform-native DRAFT variants (linkedin ~1300-2000 char post,
   x <=280 or a <=4-post thread, mastodon/bluesky <=500). HARD GATE: the
   article's URL is curl-verified (read-only GET, linkcheck UA) before any
   variant is produced; a dead link -> the article is skipped with a note
   (never publish an unverified link). Only title/summary/source fields are
   used - no invented facts.
3. `draft_post(channel, hook, angle="", link="")` — compose a draft from
   templates: hook, 1-3 body lines, measured proof point when relevant,
   verified link (curl 200 or drop with note), hashtag policy (<=3, no
   engagement-bait tags), char-limit validation per channel. Output carries
   `requires_owner_send: True` — ALWAYS.
4. `post_queue()` — the owner's work list: all drafts grouped by status with
   ages. `mark_status(post_id, status)` records owner decisions;
   `mark_published(post_id, url=None, metrics=None)` records that the OWNER
   actually posted (manual bookkeeping — data entry, not an action).
5. `engagement_draft(mention_text, channel="x", tone_hint="")` — classify
   tone and draft a reply following TONE_RULES: technical and concrete, no
   marketing fluff, cite published pages (verified links) only when real,
   hostile mentions -> no reply drafted + escalate note. Draft-only.
6. `listen_report(entries, baseline=0.0)` — rollup over provided
   MentionRecords: keyword frequency table, tone split, themes, spike flags
   vs baseline, unanswered count. v1 takes entries from the owner; no
   scraping (scraping at unknown scope = policy decision + v2 API work).
7. `metrics_report(period_days, entries=None)` — KPI rollup from owner-
   entered per-post outcome dicts (impressions/likes/comments/clicks/url):
   engagement rate per channel (reactions+comments / impressions, the
   standard definition, labeled), site CTR when the post used site links
   (cross-check vs the newsroom counter where possible), benchmark context
   labeled as RESEARCH anchor (from the 2026 benchmark literature), never
   presented as Bedim's own measured data.
8. `brand_check(text)` — pre-flight on any draft: banned-claim list
   (superintelligence framing, "unhackable/guaranteed", engagement bait),
   unsourced-number detection (any number not from MEASURED_STATS is
   flagged), live link verification, scrub patterns (internal hostnames,
   emails, /home paths), per-channel length check. Returns approved/flagged
   list. Used internally before anything enters the queue; exposed for the
   owner to run on arbitrary text, too.
9. `crisis_note(incident_summary)` — hold-rules and template language during
   an active incident: what to pause, what the first public line looks like,
   what never to claim, who (human) owns the final say. Draft-only.
10. `week_summary()` — queue state, published-this-week (owner-recorded),
    overdue calendar slots, unanswered mentions.

Constants: `CADENCE` (per-channel weekly slots + peak-time guidance),
`MEASURED_STATS` (imported from the sales agent's PROOF_POINTS — one source
of measured numbers fleet-wide), `TONE_RULES`, `BANNED_CLAIMS`.

## Hard rules (code-level, not aspirational)

- **There is no posting path.** No platform API client, no SMTP, no network
  POST in v1. The only network activity is read-only link verification
  (curl GET with the house linkcheck UA). Every outbound-facing artifact is
  a draft with `requires_owner_send: True`.
- **Verified links only.** Any URL in any output must pass a live 200 from
  an unauthenticated context, or it is dropped from the draft with a note
  (the /team/ + capabilities rule).
- **Measured numbers only.** Stats must come from MEASURED_STATS (published,
  measured); research benchmark figures are labeled as research anchors.
- **No fake engagement.** The agent does not follow, like, or inflate
  anything; it drafts replies for the human's account and voice.
- **No PII out.** Drafts are scrubbed via the house patterns before they
  reach the queue.

## v2 items (each needs an owner decision or credentials)

1. Publishing integration (LinkedIn app review / X API tier decision,
   mastodon/bluesky tokens) — replaces hand-off with a gated `hand_off`
   that stages platform-ready payloads for the owner's click, before any
   auto-post consideration (which stays owner-decision territory forever).
2. Listening via APIs (keywords, competitor accounts, spike alerts) —
   replaces pasted entries.
3. Social -> CRM handoff: a warm mention becomes a sales lead — via the
   message bus (the protocol exists) or a manual `sales.create_lead` call;
   auto-creating leads from unprompted social data is a policy decision.
4. Employee/founder advocacy pack: monthly prep bundles for the founder's
   personal posting (drafts remain owner-authored in name and review).

## /team/ page impact when implemented

Registry grows to 37 ids (36 member cards): the Business division goes 4 ->
5; the page lede "35 of them across seven divisions" becomes "36 of them
across seven divisions"; the assembler's card-count gate (currently hard 35)
and lede assert must be updated in the same change. Registration should set
`NEW_MARKS["social_media"]` for the next roster build so the new card
carries the dated New badge under the existing 15-day auto-removal.

## Build plan (on approval)

1. `agentic_ai/agents/social_media.py` (~500 lines: types + 10 ops + rules)
2. `tests/test_social_media_agent.py` (~35 tests: mirror the sales suite —
   tools list, calendar math, repurpose with verified/dead links, tone
   rules, queue state machine, listening/metrics math, brand_check catches,
   persistence round trip, never-posts invariant, perform_task dispatch)
3. Registry entry + full test suite + commit (Dawn) + lockstep push
4. /team/ regen: lede 35->36 sweep (also the assembler gates), Business
   division lede updates automatically, NEW_MARKS gains social_media
5. Optional same-day: CLI card check (`agenticai agent card social_media`)

## Second wave — built 2026-10-03 (credential-free v2 core)

- `hand_off(post_id)`: stages the platform-ready payload for the owner's
  click; state machine drafted -> owner_approved -> handed_off ->
  published (the owner records publishes via mark_published). No post
  credentials exist anywhere.
- `hand_to_sales(mention_id)`: the owner's warm-mention trigger - marks a
  handled mention as a CRM lead through a state-sharing SalesAgent
  (dedupe by email when present, else by author name across
  social-source leads). No lead is created from unprompted social data;
  the call itself is the policy gate.
- `site_counters()`: pulls the site's own cookie-free counters (home
  visits + per-article clicks) - first-party truth to sanity-check
  platform-reported social numbers against.
- `advocacy_pack(month)`: founder-personal bundle - the month's newsroom
  stories + published queue records as up to 6 founder-voice drafts
  (verified links only); sent from the owner's own account, in the
  owner's voice.

Still owner-gated (need credentials and a decision): LinkedIn/X publishing
APIs, listening APIs, per-post scheduled automation.

## The posting path — authorized activities (built 2026-10-03)

The draft-only wall remains for anything unauthorized; the posting path is
an AUTHORIZATION MODEL on top of it:

1. The owner SETS UP an activity: a social post from an owner_approved
   draft, or a limited-information reply to an inbound request (the request
   text is never echoed; the reply is canned-minimal: greeting, the
   published-material pointer, the supervisor-follow-up line - no pricing,
   no commitments, no internals).
2. The owner AUTHORIZES it (authorize_activity) - calling it IS the gate;
   the agent never self-authorizes. The activity is scheduled for its
   optimal time (PEAKS: next matching weekday at the channel's UTC window;
   explicit overrides via scheduled_for).
3. The ticker executes due authorized activities every 15 minutes: email
   replies mail for real via the verified mailbox (reports@ via STARTTLS
   587; credentials read at execute-time, never printed); social kinds
   report blocked_no_transport until platform tokens configure a
   transport (seams reserved).
4. Failed attempts retry on later ticks; after 3 the activity is recorded
   failed_final. Everything lands in the activity audit log
   (activity_log) plus the chassis transparency log.

Durable shared queue store: SHARED_ACTIVITY_DB (own sqlite blob under
~/.openclaw/soc/data/agentic-activities/). The autonomous executor runs as
the agentic-ai-activity-ticker automation (15m).

Next wave (needs credentials/decision): inbound-mailbox monitoring (IMAP),
the social transports (LinkedIn/X/Mastodon/Bluesky tokens), DM handling.

Policy state (owner decision 2026-10-03, now the code defaults): the gate
itself is unchanged - every post still needs a per-activity
authorize_activity call. Two loosening policies are live, flippable at
runtime via set_policy (the call IS the decision; flips persist in the
shared store under activity_policies):

- auto_approve_drafts (ON): a DRAFTED post authorizes directly, with the
  approval recorded in the activity log (owner_approved or
  auto_approve_drafts). Set false to require the owner_approved mark
  again.
- reply_style (rich): replies may carry ONE extra contextual paragraph,
  built only from a caller-supplied published note (house-scrub hits are
  rejected at the desk; the request text is still never echoed; no note
  = exactly the minimal template). Set "minimal" for the pure canned
  template.
