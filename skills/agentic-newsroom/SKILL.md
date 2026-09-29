---
name: "agentic-newsroom"
description: "Use when installing, tuning, or porting an autonomous agentic newsroom (curator job, builder, newest-N news page + archive, RSS, go-links) on any OpenClaw host and static site."
---

# Agentic Newsroom

Generic version of the bedimsecurity.com news-curator: a curator automation
that curates one real story per cycle into a JSON state, plus a builder that
renders a newest-N primary page, an archive page holding everything older,
and an RSS feed. The builder - never the curator - moves entries older than
`archive_hours` into the state's archive key (atomic, deduped, nothing ever
deleted), so the curator carries no prune logic and every published link
stays resolvable. Live reference deployment: bedimsecurity.com/news.

Package files:

- [build_news.py](references/build_news.py) - the builder (stdlib only)
- [curator-payload.md](references/curator-payload.md) - the curator job
  message template (tokenized) + job-creation command
- [process_unsubs.py](references/process_unsubs.py) - optional unsubscribe
  processor (watermark-persisted)
- [newsroom.json.example](references/newsroom.json.example) - config example

## Steps

1. Copy `newsroom.json.example` to the newsroom dir (e.g.
   `~/.openclaw/newsroom/`) and fill it: `state`, `site_url`, `page_prefix`,
   `primary_count`, `rss_count`, `archive_hours`, `brand`, `copy`,
   `deploy {ssh, sudo, web_root, owner}`, and optionally `map`, `rss_file`,
   `counts_cmd`, `unsub`. Done when every key you intend to use is filled
   and the file parses as JSON.
2. Create the state file at config `state` exactly as
   `{"articles": [], "archive": []}`. Back it up before any manual mutation.
   Done when `json.load` succeeds.
3. Copy `references/build_news.py` beside the config and test it:
   `python3 build_news.py --config newsroom.json --dry-run` - on an empty
   state expect `no valid articles - pages and map left as-is`, exit 0, no
   deploy, no state write. Then seed a test state (a few entries with real
   200 URLs, some older than `archive_hours`, plus an extra untouched key)
   and run without `--dry-run` while `deploy.ssh` is null: expect the
   archive move printed, pages written to the out dir, and the extra state
   keys preserved. Done when both runs hold.
4. Deploy wiring: set `deploy.ssh` to the ssh alias of the site host and
   `deploy.web_root` to its webroot (the builder ships `/tmp/newsroom-*` and
   copies into `<web_root><page_prefix>`, 755 dirs / 640 files / `owner`).
   For click-through links mount the go-map in nginx (http block):
   `map $arg_id $news_target { include <map.path>; default ""; }`, in the
   vhost: `location <page_prefix>go { if ($news_target = "") { return 404; }
   return 302 $news_target; }` - unknown ids 404, mapped ids 302. Done when
   a real run prints both page HTTP 200s (or the local out-dir render).
5. Fill the tokens in curator-payload.md and create the curator automation:
   every 2h schedule with pacing min 1h / max 4h, isolated target, silent
   delivery, failure alerts after 2 consecutive failures. Done when the
   job's next_check sits inside the pacing window.
6. First live test: force-run the job once (`openclaw automations run <id>`
   / Automations page). Expect both pages 200, the state's newest
   `added_at` fresh, and the deployed page mtime just now. Verify liveness
   by GROUND evidence (newest added_at + deployed mtime), never by
   automations-inventory presence - a restricted inventory can hide jobs.
7. Optional extras: first-party counters (`counts_cmd` must print a last
   stdout line of JSON `{"visits": int, "clicks": {id: int}}`; write your
   own log matcher and test it `--dry` before any watermark-advancing run),
   the unsubscribe processor (`unsub` config key; verify the matcher against
   a real log line before the first run - a 0-hit run with a bad matcher
   still advances the watermark and swallows those events), and a digest
   sender (bring your own SMTP; not included).

## Rules

- The builder owns the archive split; the curator payload never deletes.
  State keys the curator does not touch must be preserved on every rewrite.
- Numbers on a public page are measured live at publish time, never carried
  from memory or a previous version.
- Publish nothing carrying site-internal names or credentials: tokens in the
  payload template stay placeholders, and scrub example hosts before reuse.