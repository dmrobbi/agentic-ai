# Publishing Blitz — October 2026 wave

Status: PLAN (the machinery below is built and tested; the sends are
owner-gated by design). Composed 2026-10-03, after the original blitz plan
could not be found in any memory or session corpus — this is the fresh one,
built against the fleet as it exists today.

## Goal

Turn one week of REAL fleet output into coordinated, market-visible
presence — and measure it with first-party numbers. The blitz's raw
material is genuine: the sales desk rebuild, the social desk, the new wiki,
the measured Laya results, and the newsroom's policy coverage. Nothing is
invented; that is the brand.

## Audience (per the 2026 research)

1. **The skeptics** — infosec people. They reward technical depth and real
   numbers; they punish marketing fluff and engagement bait.
2. **The buying committee** — compliance and security leaders. They respond
   to evidence, credentials, and named accountability.

## Channels, ranked

| Channel | Role | Cadence |
|---|---|---|
| LinkedIn | primary B2B social channel; founder-led personal + company page | 2-3/wk |
| X/Twitter | the infosec community square; short + threads | 3-5/wk |
| Repo (public) | CHANGELOG + wiki as the receipts | per wave |
| Email digest | the briefing list (owner sends via newsroom machinery) | 1 special edition |
| Site /news | the curator runs itself continuously | continuous |

## The pieces (all real)

1. **"We rebuilt our sales agent into a pricing desk."** — the sales agent
   now carries a productized price book, quote builder, proposals, and a
   pipeline forecast — deterministic ops, no LLM in the money path.
   Receipts: the public repo commits + the capability pages.
2. **"Our social agent can't post — by design."** — the draft-only
   invariant IS the thought-leadership piece: an agent with no posting
   path, in a rename-mad season. The skeptics' currency is honesty.
3. **"The whole system is documented now."** — the new wiki: 36 agents
   across 7 divisions, the chassis, the design principles. Link it.
4. **"Laya: measured 21s -> 1.2s."** — the evergreen measured proof
   (74% less GPU energy, 16x latency, 94.6% agreement over a 452-decision
   soak; replicated second host with 100% identical answers).
5. **Digest special edition:** "What the agent fleet shipped this week" —
   the listicle of real commits and stories (owner-gated send).

## Cadence (5 days)

- **Day 1**: repo side goes live (CHANGELOG + wiki receipt links); digest
  draft rendered for the owner's approval.
- **Day 2-3**: LinkedIn pieces 1-2; the X thread version of piece 2.
- **Day 4**: founder advocacy pack + the engagement window (reply drafts
  prepped for whatever lands; hostile mentions escalate, not engage).
- **Day 5**: the measured retro — before/after first-party deltas
  (`snapshot_counters` twice, `blitz_report`) + queue conversion stats.

## Guardrails (code-enforced; the owner flips policies via set_policy)

- Per-activity authorization is THE gate: every post and email reply
  enters the authorized-activities queue through an explicit
  authorize_activity call - the owner's decision, logged with the
  approval path it took (owner_approved or auto_approve_drafts). No
  queue entry self-materializes; the ticker executes only authorized
  records, at their scheduled optimal time.
- Loosening policies (owner decision 2026-10-03): auto_approve_drafts ON
  (a DRAFTED post may authorize without the owner_approved mark) and
  reply_style rich (a reply may add ONE house-scrubbed context paragraph
  from a caller-supplied published note). Both flip back via set_policy;
  flips persist in the shared store, so the ticker follows the same
  rules.
- Limited-information replies: the request text is never echoed; the
  reply carries only published material; no pricing, no commitments;
  composed by the fleet and mailed via the verified reports@ mailbox
  (credentials read at execute-time, never printed) with the human
  supervision sign-off line.
- House scrub patterns are non-negotiable: drafted posts AND reply
  context notes pass them; hits are rejected at the desk.
- Verified links only: any URL is fetched live before it ships.
- Measured numbers only: stats come from one shared measured source;
  `brand_check` flags everything else.
- No engagement bait, no fake personas, no astroturfing.
- Hostile mentions escalate to the owner; they never get drafted
  replies.
- Full audit: authorizations, retries (capped at 3 = failed_final), and
  executions land in the activity audit log plus the chassis
  transparency log.

## KPIs (the blitz_report math)

- Home visits delta + article-clicks delta (first-party, cookie-free).
- Queue conversion: drafts -> owner_approved -> handed_off -> published.
- Replies drafted; hostiles escalated (handled, not engaged).
- Platform-side metrics: owner-entered; benchmarked against labeled
  research anchors, never presented as Bedim data.

## Machinery status

Built and tested this session: `campaign_sources`, `blitz_plan`,
`blitz_report`, `snapshot_counters`, `blitz_digest` (plus the earlier
16-op desk: calendar, repurpose, queue bookkeeping, engagement, listening,
metrics, brand checks, hand-off, CRM handoff). The blitz now runs on the
fleet's own machinery, human-gated at every send.