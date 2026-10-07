"""Engagement -> SOC memory bridge (KA-075 / OPT-75): engagement summaries
routed into the SOC memory store under their tenant. PURE PLANNER: never
executes anything, never reads files, never reads the wall clock, and
NEVER touches the live memory tree - the store is INJECTED (mock/synthetic
world; the live wiring is a later P5 decision, not this module).

ENGAGEMENT SUMMARY CONTRACT (input): dict with
  tenant_id      required, ^[a-z0-9][a-z0-9_-]{0,63}$ (the tenant namespace
                 the summary is filed under - tenant routing is this
                 bridge's whole point)
  engagement_id  required, ^[A-Za-z0-9_.-]{1,64}$ (the findings id
                 convention shared with the findings bridge, KA-066)
  summary        required, non-blank free text; single-paragraph shape
                 (runs of spaces collapse to one; newline, other control,
                 zero-width/bidi/format characters are REJECTED),
                 MAX_SUMMARY_CHARS cap
  severity       optional, critical|high|medium|low|info case-insensitive
                 (safe default "info")
  tags           optional list of scrubable short strings, <= MAX_TAGS
  findings       optional list of finding-id strings (ID_RE each), house
                 cap MAX_FINDING_REFS, deduped preserving input order
  target         optional host string; scrubbed via the shared host scrub
                 then handed to the host agent's validate_target gate when
                 the carrying agent has one (getattr consult, silent
                 fallback when absent)

STORE PROTOCOL (injected, duck-typed, put-only):
  store.put(record) -> ack dict (echoed verbatim per row)
Without an injected store the bridge is plan-only: every record is BUILT
and none is written (stored stays empty by construction).

OUTPUT SCHEMA (push_summaries; pinned by test_soc_memory_bridge.py):
{
  "records": [                        # one built record per valid row
    {
      "record_id": str,               # "<tenant>:<engagement>:<pos>";
                                      # pos = 1-based input position per
                                      # push call (gaps mark rejections)
      "tenant_id": str,
      "engagement_id": str,
      "kind": "engagement_summary",
      "created_at": str|None,         # the INJECTED clock's isoformat;
                                      # None when the caller passes none -
                                      # the wall clock is NEVER read here
      "summary": str,                 # scrubbed single-paragraph text
      "severity": str,                # normalized lowercase
      "tags": [str],
      "findings": [str],
      "target": str|None              # scrubbed host, None when absent
    }
  ],
  "stored": {                         # record_id -> verbatim store ack
    ...                               # (dict acks only; a non-dict ack is
  },                                  # a store-contract violation)
  "rejected": [                       # invalid, duplicate, or failed-put
    {                                 # rows NEVER crash the flow
      "engagement_id": str,           # "<missing-id>" / "<missing-tenant>"
      "tenant_id": str,               # mark the unusable echoes
      "reasons": [str]
    }
  ],
  "summary": {
    "total": int, "built": int, "stored": int, "rejected": int,
    "tenants": int, "store_present": bool
  }
}

ROUTE INVARIANTS (pinned): every input row takes EXACTLY ONE terminal
route (built OR rejected), so total == built + rejected always; a valid
row with a store present always gets a dict ack (stored count == built
count). Statelessness: the same valid row pushes again in a NEW call;
per-call duplicate suppression is the bridge's idempotence floor -
cross-call idempotence belongs to the store. Legacy extras: every
public op absorbs unknown kwargs and never forwards them (pinned).

TENANT READ SIDE (planner strings only - nothing executes):
tenant_read_plan(tenant_id) returns the deterministic per-tenant recall
plan (steps/notes strings); tenant_index(records) folds built records
into the {tenant: [record_id...]} store-layout view.

Purity pins (source-scanned by test_soc_memory_bridge.py): no execution
facilities, no network, no file I/O, no wall-clock reads, and no
reference to the live SOC tree anywhere in the source. The one planned
module-level sibship is the shared host scrub (soc_bridge.scrub_host;
no cycle - the findings bridge's own chassis default is a lazy import).
The chassis and every other sibling are referenced ONLY lazily, and
this module needs neither."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple

from agentic_ai.agents.cyber.soc_bridge import scrub_host

ID_RE = r"[A-Za-z0-9_.\-]{1,64}"
TENANT_RE = r"[a-z0-9][a-z0-9_\-]{0,63}"
RECORD_KIND = "engagement_summary"
SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_SEVERITY = "info"
MAX_TAGS = 10
MAX_FINDING_REFS = 25
MAX_SUMMARY_CHARS = 2000
POS_PAD = 4
TENANT_READ_LIMIT = 10
BAD_TEXT_CATS = frozenset(("Cc", "Cf", "Zl", "Zp"))
_MISSING_ID = "<missing-id>"
_MISSING_TENANT = "<missing-tenant>"


def scrub_summary_text(text: str) -> str:
    """The shared input gate for summary/tag text (wp_scrub_target pattern)."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    scrubbed = text.strip()
    for ch in scrubbed:
        if unicodedata.category(ch) in BAD_TEXT_CATS:
            raise ValueError(
                "rejected text with control/format character: %r" % (ch,))
    cleaned = re.sub(r" {2,}", " ", scrubbed)
    if len(cleaned) > MAX_SUMMARY_CHARS:
        raise ValueError(
            "text exceeds the %d character cap" % MAX_SUMMARY_CHARS)
    return cleaned


def scrub_tenant_id(tenant: str) -> str:
    """The shared input gate for tenant namespaces (wp_scrub_target pattern)."""
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError("tenant_id must be a non-empty string")
    scrubbed = tenant.strip()
    if not re.fullmatch(TENANT_RE, scrubbed):
        raise ValueError(
            "rejected tenant_id (lowercase a-z0-9 slug, - or _): %r"
            % (tenant,))
    return scrubbed


def _echo(value: Any, fallback: str) -> str:
    """Deterministic JSON-safe echo for rejected-row provenance."""
    if isinstance(value, str):
        return value.strip()[:64]
    if value is None:
        return fallback
    return repr(value)[:64]


class EngagementMemoryBridge:
    """Route engagement summaries into tenant memory records (planners only)."""

    def __init__(self, store=None):
        self.store = store

    @staticmethod
    def _em_scrub(text: str) -> str:
        """Thin staticmethod wrapper over the shared summary text scrub."""
        return scrub_summary_text(text)

    def _em_target(self, value: Any, what: str = "target") -> str:
        """Scrub, then consult the host agent's validate_target via
        getattr with a silent fallback when the chassis lacks one."""
        scrubbed = scrub_host(value)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(scrubbed)
            if not ok:
                raise ValueError(
                    "%s rejected by host agent gate: %s" % (what, msg))
        return scrubbed

    def build_record(
        self, item: Any, seq: int = 1, now: Any = None, **_legacy: Any
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Validate one engagement summary and build its tenant memory record."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        reasons: List[str] = []
        row = item if isinstance(item, dict) else {}

        try:
            tenant = scrub_tenant_id(row.get("tenant_id"))
        except ValueError as exc:
            tenant = _MISSING_TENANT
            reasons.append(str(exc))

        engagement = _MISSING_ID
        eng_raw = row.get("engagement_id")
        if not isinstance(eng_raw, str) or not eng_raw.strip():
            reasons.append("engagement id missing")
        elif not re.fullmatch(ID_RE, eng_raw.strip()):
            reasons.append("engagement id malformed: %r" % (eng_raw,))
        else:
            engagement = eng_raw.strip()

        try:
            summary = self._em_scrub(row.get("summary"))
        except ValueError as exc:
            summary = ""
            reasons.append(str(exc))

        severity_raw = row.get("severity")
        if severity_raw is None:
            severity = DEFAULT_SEVERITY
        elif (isinstance(severity_raw, str)
              and severity_raw.strip().lower() in SEVERITIES):
            severity = severity_raw.strip().lower()
        else:
            severity = DEFAULT_SEVERITY
            reasons.append(
                "severity must be one of %s, got: %r"
                % ("|".join(SEVERITIES), severity_raw))

        tags: List[str] = []
        tags_raw = row.get("tags")
        if tags_raw is not None:
            if (not isinstance(tags_raw, list)
                    or not all(isinstance(t, str) for t in tags_raw)):
                reasons.append("tags must be a list of strings")
            elif len(tags_raw) > MAX_TAGS:
                reasons.append("tags exceed cap %d" % MAX_TAGS)
            else:
                for tag in tags_raw:
                    try:
                        tags.append(self._em_scrub(tag))
                    except ValueError as exc:
                        reasons.append("tag %r: %s" % (tag, exc))

        findings: List[str] = []
        refs_raw = row.get("findings")
        if refs_raw is not None:
            if (not isinstance(refs_raw, list)
                    or not all(isinstance(x, str) for x in refs_raw)):
                reasons.append("findings must be a list of id strings")
            elif len(refs_raw) > MAX_FINDING_REFS:
                reasons.append(
                    "findings references exceed cap %d" % MAX_FINDING_REFS)
            else:
                seen_refs: Set[str] = set()
                for ref in refs_raw:
                    ref_cleaned = ref.strip()
                    if not re.fullmatch(ID_RE, ref_cleaned):
                        reasons.append(
                            "finding reference malformed: %r" % (ref,))
                        continue
                    if ref_cleaned in seen_refs:
                        continue  # dedupe, preserving input order
                    seen_refs.add(ref_cleaned)
                    findings.append(ref_cleaned)

        target: Optional[str] = None
        target_raw = row.get("target")
        if target_raw is not None:
            try:
                target = self._em_target(target_raw)
            except ValueError as exc:
                reasons.append(str(exc))

        if reasons:
            return None, reasons

        record = {
            "record_id": "%s:%s:%s"
            % (tenant, engagement, str(seq).rjust(POS_PAD, "0")),
            "tenant_id": tenant,
            "engagement_id": engagement,
            "kind": RECORD_KIND,
            "created_at": now.isoformat() if now is not None else None,
            "summary": summary,
            "severity": severity,
            "tags": tags,
            "findings": findings,
            "target": target,
        }
        return record, []

    def push_summaries(
        self, summaries: Any, store: Any = None, now: Any = None,
        **_legacy: Any,
    ) -> Dict[str, Any]:
        """Route engagement summaries into tenant SOC memory records
        (plan-only builds without any initialized store)."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if store is None:
            store = self.store
        if isinstance(summaries, dict):
            rows_in: List[Any] = [summaries]  # a single summary object is fine
        elif isinstance(summaries, (list, tuple)):
            rows_in = list(summaries)
        else:
            raise ValueError(
                "summaries must be a list of engagement summary dicts, "
                "got: %r" % (summaries,))

        records: List[Dict[str, Any]] = []
        stored: Dict[str, Any] = {}
        rejected: List[Dict[str, Any]] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        for position, row in enumerate(rows_in, start=1):
            record, reasons = self.build_record(row, seq=position, now=now)
            if reasons:
                rejected.append({
                    "engagement_id": _echo(
                        row.get("engagement_id") if isinstance(row, dict)
                        else row, _MISSING_ID),
                    "tenant_id": _echo(
                        row.get("tenant_id") if isinstance(row, dict)
                        else row, _MISSING_TENANT),
                    "reasons": reasons,
                })
                continue
            pair = (record["tenant_id"], record["engagement_id"])
            if pair in seen_pairs:
                rejected.append({
                    "engagement_id": record["engagement_id"],
                    "tenant_id": record["tenant_id"],
                    "reasons": ["duplicate engagement summary for tenant"],
                })
                continue
            if store is not None:
                try:
                    ack = store.put(record)
                except Exception as exc:
                    rejected.append({
                        "engagement_id": record["engagement_id"],
                        "tenant_id": record["tenant_id"],
                        "reasons": ["store put failed: %s" % exc],
                    })
                    continue
                if not isinstance(ack, dict):
                    rejected.append({
                        "engagement_id": record["engagement_id"],
                        "tenant_id": record["tenant_id"],
                        "reasons": ["store ack not a dict: %r" % (ack,)],
                    })
                    continue
                stored[record["record_id"]] = ack
            seen_pairs.add(pair)
            records.append(record)

        tenants = {rec["tenant_id"] for rec in records}
        return {
            "records": records,
            "stored": stored,
            "rejected": rejected,
            "summary": {
                "total": len(rows_in),
                "built": len(records),
                "stored": len(stored),
                "rejected": len(rejected),
                "tenants": len(tenants),
                "store_present": store is not None,
            },
        }

    def tenant_index(self, records: Any) -> Dict[str, List[str]]:
        """Index built memory records under their tenants (store layout view)."""
        index: Dict[str, List[str]] = {}
        for row in list(records or []):
            if not isinstance(row, dict):
                continue
            tenant = row.get("tenant_id")
            record_id = row.get("record_id")
            if isinstance(tenant, str) and isinstance(record_id, str):
                index.setdefault(tenant, []).append(record_id)
        return {tenant: index[tenant] for tenant in sorted(index)}

    def tenant_read_plan(self, tenant_id: Any, **_legacy: Any) -> Dict[str, Any]:
        """Plan the per-tenant SOC memory recall (strings only, none execute)."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        try:
            tenant = scrub_tenant_id(tenant_id)
        except ValueError as exc:
            return {"tenant_id": _echo(tenant_id, _MISSING_TENANT),
                    "error": str(exc), "steps": [], "notes": []}
        steps = [
            "list %s records filed under tenant '%s'" % (RECORD_KIND, tenant),
            "select the newest %d records by created_at descending"
            % TENANT_READ_LIMIT,
            "fold each summary line into the daily SOC brief",
        ]
        notes = [
            "planner strings only: this module executes nothing",
            "finding ids refer to the findings bridge corpus, never payloads",
            "cross-tenant rollups are a wiring decision, never a bridge op",
        ]
        return {"tenant_id": tenant, "steps": steps, "notes": notes}
