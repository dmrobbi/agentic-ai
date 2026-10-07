"""Owner one-glance dashboard widget (KA-100) - the payload builder.

Spec ("[100] Owner dashboard widget"): one-glance status - suite state,
CVE-DB coverage %, last battery run, evidence count.

The output is OpenClaw dashboard `session:report`-compatible - a payload
whose blocks follow the report contract:

  [
    {"type": "metrics", "title": ..., "items": [{label, value, detail}...]},
    {"type": "table",   "title": ..., "columns": [...], "rows": [...]},
    {"type": "links",   "title": ..., "items":  [{label, url}...]},  # optional
  ]

Every metric value and detail is a STRING (coerced here); the links block
is omitted when no validated link survives - links exist only where a
real https URL exists (file:// and every other scheme is dropped, never
emitted); the table is the deterministic audit row of what fed each
headline metric in.

ALL STRUCTURE lives here; NOTHING is fetched:

- the module NEVER runs pytest and NEVER measures - suite state arrives
  INJECTED (the pytest --collect-only total and/or the last measured
  verdict line, grep-selected). Only the companion tool script
  (tools/build_owner_widget.py) may run pytest, and only behind its
  --probe flag;
- the CVE corpus (tests/fixtures/cve/cve_eval_corpus.json, the 80+ real
  CVE fixture pinning the expected exploit modules) and the matcher (the
  CVEMatchingEngine in agentic_ai/agents/cyber/kali_v2.py, read-only) are
  INJECTED objects; this module imports neither - the tool script imports
  them lazily and passes them in, degrading to None on any failure
  (note: the pending-review proposal data in data/appliance_cves.json is
  NOT a coverage source - the committed eval corpus is, per the spec);
- battery state arrives INJECTED (a dict as parse_battery_log returns, or
  transcript text) - real runs are owner-gated per docs/KA-LAB-TARGET.md
  and the tool script skips the metric when no --battery-log path is
  given;
- evidence count arrives INJECTED (the tool counts artifact files
  recursively under kali_agent_v4/evidence/, the EVIDENCE_PACKAGE
  pattern, when the tree is discoverable).

Degradation contract: every missing or unusable input renders as
{"value": "unknown", "detail": <reason>} instead of raising - a hostile
shape can never crash the widget.

Determinism contract: build_payload is a pure function of its arguments
- identical injections produce an identical payload and identical
payload_json_text bytes (no wall-clock, no randomness; the "generated"
field is a curation-date constant, refreshed only when the committed
sample data/owner_widget.json is regenerated on purpose by its tool).

Purity contract: no subprocess, no os.system, no eval/exec, no network,
no disk reads here - planners may not execute, and this module's tests
pin that.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

SCHEMA = "ka-owner-widget/1"
GENERATED = "2026-10-07"  # sample curation date; never read from the clock
UNKNOWN = "unknown"

METRIC_LABELS = (
    "suite state",
    "CVE-DB coverage %",
    "last battery run",
    "evidence count",
)

TESTS_DIR_HINT = "tests/"
EVIDENCE_DOC_HINT = "docs/KA-LAB-TARGET.md"
BATTERY_MODE = "pve-lab battery transcript"

# House verdict rule as a regex: every line matching pytest's
# "N passed / N failed / N error" pattern is a candidate; parse_verdict
# reads the LAST one (the freshest summary) - mirrors
# `grep -E "[0-9]+ (passed|failed|error)"`, never tail.
_VERDICT_RE = re.compile(r"[0-9]+ (?:passed|failed|error)")
_COLLECT_RE = re.compile(r"^([0-9]+) tests collected", re.MULTILINE)
_RUN_STAMP_RE = re.compile(r"^run:\s*(\S.*?)\s*$")
_CONSENT_GATE = "REFUSED"

HTTPS_SCHEMES = ("http", "https")


# ---------------------------------------------------------------- helpers

def coerce_str(value):
    """String coercion for every value the widget emits: None stays None
    (missing-input marker), a blank string counts as missing, everything
    else (string, int, float, bool, ...) becomes a string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    return str(value)


def _unknown(reason, note=None):
    """The degradation shape: {"value": "unknown", "detail": <reason>}."""
    detail = coerce_str(reason) or "no input provided"
    extra = coerce_str(note)
    if extra and extra not in detail:
        detail += "; " + extra
    return {"value": UNKNOWN, "detail": detail}


def _metric(value, detail, note=None):
    """A rendered metric row; None/blank values degrade to unknown and the
    optional note is appended to the detail (deduplicated)."""
    detail = coerce_str(detail) or "no detail provided"
    extra = coerce_str(note)
    if extra and extra not in detail:
        detail += "; " + extra
    strong = coerce_str(value)
    if not strong:
        return {"value": UNKNOWN, "detail": detail}
    return {"value": strong, "detail": detail}


# ---------------------------------------------------- headline 1: suite

def suite_metric(collected_total=None, verdict=None, note=None):
    """Headline metric - suite state, from INJECTED suite inputs only.

    collected_total: the pytest --collect-only total (int or string);
    verdict: the last measured verdict line, grep-selected per the house
    rule (e.g. "5120 passed, 0 failed ..."). The module never measures;
    absent injections degrade to unknown with the reason in the detail."""
    total = coerce_str(collected_total)
    verdict_text = coerce_str(verdict)
    if total and verdict_text:
        return _metric(
            "collected %s - %s" % (total, verdict_text),
            "suite state injected (collect total + last measured verdict)",
            note)
    if total:
        return _metric(
            "collected %s" % total,
            "collect total injected; no verdict text available yet",
            note)
    if verdict_text:
        return _metric(
            verdict_text,
            "last measured verdict injected; collect total not provided",
            note)
    return _unknown(
        "no suite state injected (the module never measures; the tool"
        " script's --probe or a harness supplies it)", note)


def parse_verdict(text):
    """Extract the pytest summary line from run output, implementing the
    house rule "verdicts from a log-file grep, never tail": lines matching
    "[0-9]+ (passed|failed|error)" are the candidates and the LAST match
    wins (a log may chain runs; the summary is the freshest). None when
    nothing matches (e.g. the opentelemetry shutdown noise alone)."""
    if coerce_str(text) is None:
        return None
    hits = [line.strip() for line in str(text).splitlines()
            if _VERDICT_RE.search(line)]
    return hits[-1] if hits else None


def parse_collect_total(text):
    """Extract the pytest --collect-only total ("N tests collected") from
    run output; the last match wins; None when absent."""
    if coerce_str(text) is None:
        return None
    found = _COLLECT_RE.findall(str(text))
    return int(found[-1]) if found else None


# ------------------------------------------------- headline 2: coverage

def coverage_metric(corpus=None, matcher=None, note=None):
    """Headline metric - CVE-DB coverage %, matched/expected over the
    committed match eval corpus, deterministic from INJECTED inputs.

    corpus: the parsed tests/fixtures/cve/cve_eval_corpus.json dict
    {"known": [...], "edge": [...], "out_of_db": [...]} - the 80+ real
    CVEs pinning the expected exploit modules. Each known entry pins a
    match (its "cve" must resolve); each edge entry pins a shaped input
    ("found" entries carry the "expect_cve" a match must report, "null"
    entries pin a miss); out_of_db entries pin real CVE ids absent from
    the DB by design.

    matcher: an engine-like object exposing match_cve(cve_id) -> row or
    None, whose rows carry a .cve_id (the real CVEMatchingEngine shape).

    Coverage % = matched / expected, where the expected set is exactly
    the entries whose pinned outcome is a match (known + edge "found");
    expected-miss entries never count against coverage, but a false-
    positive match on one is surfaced as an over-reach in the detail.
    Missing or unusable injections degrade to unknown - never a crash."""
    if matcher is None:
        return _unknown("no matcher injected", note)
    if corpus is None:
        return _unknown("no corpus injected", note)
    if not isinstance(corpus, dict):
        return _unknown("corpus must be the parsed eval-corpus dict", note)
    match_fn = getattr(matcher, "match_cve", None)
    if not callable(match_fn):
        return _unknown("matcher must expose a callable match_cve", note)

    counts = {"known": 0, "edge": 0, "out_of_db": 0}
    expected = matched = overreach = 0

    def resolved(row, expect_id):
        if row is None:
            return False
        return coerce_str(getattr(row, "cve_id", None)) == coerce_str(expect_id)

    try:
        for name in counts:
            entries = corpus.get(name)
            if isinstance(entries, list):
                counts[name] = len(entries)

        for entry in corpus.get("known") or []:
            if not isinstance(entry, dict):
                continue
            cve = coerce_str(entry.get("cve"))
            if not cve:
                continue
            expected += 1
            if resolved(match_fn(cve), cve):
                matched += 1

        for entry in corpus.get("edge") or []:
            if not isinstance(entry, dict):
                continue
            outcome = coerce_str(entry.get("outcome"))
            raw = coerce_str(entry.get("raw"))
            row = match_fn(raw) if raw else None
            if outcome == "found":
                expected_id = coerce_str(entry.get("expect_cve"))
                if not expected_id:
                    continue
                expected += 1
                if resolved(row, expected_id):
                    matched += 1
            elif row is not None:
                overreach += 1  # a "null"-outcome shape unexpectedly matched

        for entry in corpus.get("out_of_db") or []:
            if not isinstance(entry, dict):
                continue
            cve = coerce_str(entry.get("cve"))
            if not cve:
                continue
            if match_fn(cve) is not None:
                overreach += 1  # an "absent by design" id unexpectedly matched
    except Exception as exc:  # a hostile matcher must degrade, never crash
        return _unknown("matcher raised: %s" % exc, note)

    total = sum(counts.values())
    if not expected:
        return _unknown("corpus carries no expected-match entries", note)
    detail = ("matched %d/%d expected entries over %d corpus entries"
              " (known %d, edge %d, out_of_db %d); over-reach %d"
              % (matched, expected, total, counts["known"], counts["edge"],
                 counts["out_of_db"], overreach))
    return _metric("%.1f%%" % (100.0 * matched / expected), detail, note)


# ------------------------------------------------- headline 3: battery

def parse_battery_log(text):
    """Parse a pve-lab battery transcript (scripts/lab/pve-lab-battery.sh
    output - its say() lines carry a "[battery] " prefix) into the state
    dict that feeds battery_metric.

    This builder's documented log convention:
    - an optional "run: <stamp>" header line records when;
    - a "[battery] FATAL" / "[battery] FAIL:" line makes the verdict fail;
    - a "[battery] REFUSED" line means the owner consent gate refused
      (nothing executed; see docs/KA-LAB-TARGET.md);
    - otherwise the transcript passed its tiers.

    Returns None when the text carries no battery lines at all (not a
    transcript) - callers degrade to unknown."""
    if coerce_str(text) is None:
        return None
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    battery_lines = [line for line in lines if line.startswith("[battery]")]
    if not battery_lines:
        return None
    when = None
    for line in lines:
        stamp = _RUN_STAMP_RE.match(line)
        if stamp is not None:
            when = stamp.group(1)
            break
    failures = [line for line in battery_lines
                if "FATAL" in line or "FAIL:" in line]
    refusals = [line for line in battery_lines if _CONSENT_GATE in line]
    if failures:
        verdict, anchor = "fail", failures[0]
    elif refusals:
        verdict, anchor = "refused", refusals[0]
    else:
        verdict, anchor = "pass", battery_lines[0]
    return {
        "mode": BATTERY_MODE,
        "verdict": verdict,
        "when": when,
        "detail": "%d battery lines; first issue/anchor: %s"
                  % (len(battery_lines), anchor),
    }


def battery_metric(state=None, note=None):
    """Headline metric - last battery run, from an INJECTED battery state.

    state: the dict parse_battery_log returns (keys verdict/when/detail/
    mode), OR battery transcript text (parsed here, so callers can inject
    either shape without touching a disk). The tool script feeds it from
    an optional --battery-log path and SKIPS the metric when the path is
    absent - real runs are owner-gated (docs/KA-LAB-TARGET.md). Missing
    states degrade to unknown."""
    if state is None or state == {}:
        return _unknown(
            "no battery log passed (skipped when absent; battery runs are"
            " owner-gated per docs/KA-LAB-TARGET.md)", note)
    if isinstance(state, str):
        state = parse_battery_log(state)
        if state is None:
            return _unknown(
                "injected battery text is not a battery transcript", note)
    if not isinstance(state, dict):
        return _unknown("battery state must be a dict or transcript text",
                        note)
    verdict = coerce_str(state.get("verdict"))
    when = coerce_str(state.get("when"))
    if not verdict and not when:
        return _unknown("battery state carries no verdict or run stamp",
                        note)
    when_part = ("run: %s" % when) if when else "run time not recorded"
    value = "%s - %s" % (verdict or "verdict not recorded", when_part)
    detail = (coerce_str(state.get("detail"))
              or coerce_str(state.get("mode"))
              or "battery state injected")
    return _metric(value, detail, note)


# ------------------------------------------------ headline 4: evidence

def evidence_metric(count=None, note=None):
    """Headline metric - the evidence artifact count under kali_agent_v4's
    evidence pattern, INJECTED (the tool walks the tree; this module never
    reads the disk). Zero is a real state ("0"); a missing count degrades
    to unknown; wrong-typed counts degrade with the reason."""
    if count is None:
        return _unknown("no evidence count provided/discoverable", note)
    if isinstance(count, bool) or count == "":
        return _unknown("evidence count must be an integer or numeric"
                        " string", note)
    if isinstance(count, int):
        number = count
    elif isinstance(count, str) and count.strip().isdigit():
        number = int(count.strip())
    else:
        return _unknown("evidence count must be an integer or numeric"
                        " string", note)
    if number < 0:
        return _unknown("evidence count must not be negative", note)
    return _metric(
        str(number),
        "files counted under kali_agent_v4/evidence/ recursively (the"
        " KaliAgent v4 EVIDENCE_PACKAGE pattern)",
        note)


# ---------------------------------------------------------------- links

def valid_links(items):
    """Validate dashboard link items: keep {label, url} pairs whose url is
    an absolute http(s) URL - file:// and every other scheme is DROPPED
    (never emitted) - with an optional string detail; order preserved;
    exact (label, url) duplicates collapse; anything unusable is skipped.
    Returns [] for nothing usable (the payload then omits the block)."""
    if not isinstance(items, list):
        return []
    keep = []
    seen = set()
    for entry in items:
        if not isinstance(entry, dict):
            continue
        label = coerce_str(entry.get("label"))
        url = coerce_str(entry.get("url"))
        if not label or not url:
            continue
        try:
            parts = urlsplit(url)
        except Exception:  # malformed url shapes degrade, never crash
            continue
        if parts.scheme not in HTTPS_SCHEMES or not parts.netloc:
            continue
        key = (label, url)
        if key in seen:
            continue
        seen.add(key)
        item = {"label": label, "url": url}
        detail = coerce_str(entry.get("detail"))
        if detail:
            item["detail"] = detail
        keep.append(item)
    return keep


# -------------------------------------------------------------- builder

def build_payload(*, collected_total=None, verdict=None, corpus=None,
                  matcher=None, battery=None, evidence_count=None,
                  links=None, suite_note=None, coverage_note=None,
                  battery_note=None, evidence_note=None,
                  generated=GENERATED):
    """Assemble the owner widget payload (session:report-compatible):
    blocks [metrics, table, links?] in that order - links omitted when no
    validated link survives, metrics/table ALWAYS present. Identical
    injections are byte-identical (see payload_json_text); hostile or
    missing inputs never raise, they degrade per metric."""
    built = [
        suite_metric(collected_total, verdict, suite_note),
        coverage_metric(corpus, matcher, coverage_note),
        battery_metric(battery, battery_note),
        evidence_metric(evidence_count, evidence_note),
    ]
    metrics = [{"label": label, **item}
               for label, item in zip(METRIC_LABELS, built)]
    table_rows = [
        [label,
         "ok" if item["value"] != UNKNOWN else "unknown",
         "injected" if item["value"] != UNKNOWN else "absent"]
        for label, item in zip(METRIC_LABELS, metrics)
    ]
    blocks = [
        {"type": "metrics",
         "title": "Kali fleet owner status (one glance)",
         "items": metrics},
        {"type": "table",
         "title": "Widget inputs (what fed each metric)",
         "columns": ["metric", "state", "source"],
         "rows": table_rows},
    ]
    validated = valid_links(links)
    if validated:
        blocks.append({"type": "links", "title": "Sources",
                       "items": validated})
    return {
        "schema": SCHEMA,
        "generated": coerce_str(generated) or GENERATED,
        "blocks": blocks,
    }


def payload_json_text(payload):
    """Deterministic JSON text for a built payload - indent 1, the
    insertion field order (schema, generated, blocks), trailing newline:
    the exact bytes data/owner_widget.json ships."""
    return json.dumps(payload, indent=1) + "\n"