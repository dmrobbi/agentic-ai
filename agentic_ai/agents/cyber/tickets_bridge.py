"""Engagement tickets bridge (KA-069): an engagement's unresolved
findings -> append-ready soc-tickets payloads (open lines, close lines,
and the per-id store-state fold). Pure planner; the soc-tickets contract
is MOCKED: dict shapes only - nothing here touches the store, the MCP,
or the network, ever (source-scanned).

SOC-TICKETS CONTRACT (the thing1 SOC task store ~/.openclaw/soc/
tasks.jsonl line schema, modeled verbatim):
  {"id": <12 lowercase hex>,     # a fresh uuid4().hex[:12] on open
   "ts": <UTC ISO-8601 +00:00>,  # the line's stamp (aware datetimes are
                                 # normalized to UTC; naive is refused)
   "kind": <str>,                # non-blank ID_RE charset; the default
                                 # KIND_REMEDIATION is "kali_remediate" -
                                 # a new kind on the existing store;
                                 # wiring may pass the store's own
                                 # kinds instead
   "target": <hostname>,         # survives scrub_target
   "status": "running"|"done",
   "ended": null|<timestamp>,    # null on open; equals ts on close
   "details": {...}}             # free-form; decisions stay lookups

Lifecycle (append-only; MODELED, never enforced here - the bridge
writes nothing anywhere):
  open  = one "running" line with ended null; exactly one open line per
          id: duplicates are never emitted from this module
  close = a "done" line with the SAME id/kind/target, ended = the new
          stamp, and the outcome in details
  state = a ticket's LATEST line per id - never "any running line
          exists" (verified SOC store semantics, the fold below)

ENGAGEMENT CONTRACT (input; the record the wiring assembles from a
kali-agent run): dict with
  engagement_id   required, ID_RE pattern (^[A-Za-z0-9_.\-]{1,64}$)
  target          required, non-blank target string surviving scrub_target
  findings        required list of finding dicts:
    id            required, ID_RE pattern (also fits AF-... style
                  refs); the bundle route carries the STRIPPED id
                  (surrounding whitespace is tolerated there; the
                  direct open op stays exact)
    summary       optional str - verbatim in details; blank -> None
    severity      required, critical|high|medium|low (case-insensitive;
                  normalized to lowercase)
    resolved      optional truthiness, default False; truthy -> NO ticket
                  is opened (counted as already_resolved)
    evidence      optional str path/pointer - verbatim in details
    extra keys    absorbed silently; the payload shape is fixed
Per-finding malformation NEVER crashes the flow (the soc_bridge
pattern): it lands in "skipped" with reasons. Engagement-level
malformation (non-dict, missing keys, malformed engagement_id, scrub
rejections, findings not a list) raises ValueError naming the offender
- caller errors, not skip-route material.

PLANNER PURITY: no process spawning, no network facilities,
no local I/O; the clocks are ARGUMENTS (consent_gate / auth_expiry shape). No host
object exists in a plain-module bridge (as in kev_bridge and
soc_bridge, which consult no gate either): scrub_target IS the
external-string gate; validate_target consultation on the execution
path belongs to whatever chassis composes these bridges.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --- contract constants (the drift alarm; the tests pin them) ------------

ID_RE = r"[A-Za-z0-9_.\-]{1,64}"
TICKET_ID_RE = r"[0-9a-f]{12}"
SEVERITIES = ("critical", "high", "medium", "low")
STATUS_RUNNING = "running"
STATUS_DONE = "done"
KIND_REMEDIATION = "kali_remediate"
DETAIL_SOURCE = "kali-agent-engagement"
MISSING_ID = "<missing-id>"

REASON_NOT_DICT = "engagement finding must be a dict"
REASON_ID_MISSING = "finding id missing"
REASON_ID_MALFORMED = "finding id malformed: %r"
REASON_SEVERITY = (
    "severity must be one of critical|high|medium|low, got: %r")
REASON_TEXT = "%s must be a string, got: %r"


def scrub_target(target: Any) -> str:
    """The shared input gate for engagement targets (wp_scrub_target
    pattern)."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")
    scrubbed = target.strip()
    if re.search(r"[;|&`$()\n\r<>\"'\s]", scrubbed) or ".." in scrubbed:
        raise ValueError(
            "rejected target with disallowed characters: %r" % target)
    return scrubbed


def new_ticket_id() -> str:
    """A fresh 12-hex soc-tickets ticket id (uuid4().hex[:12])."""
    return uuid.uuid4().hex[:12]


def _utc_stamp(moment: Any, slot: str) -> str:
    """An aware datetime -> the store's UTC +00:00 ISO stamp; anything
    else is a ValueError naming the slot."""
    if not isinstance(moment, datetime):
        raise ValueError(
            "%s must be an aware datetime, got: %r" % (slot, moment))
    if moment.utcoffset() is None:
        raise ValueError(
            "%s must be timezone-aware (the soc-tickets store stamps "
            "UTC +00:00), got naive: %r" % (slot, moment))
    return moment.astimezone(timezone.utc).isoformat()


def _require_id(value: Any, slot: str) -> str:
    """A non-blank ID_RE string; the error names slot + value."""
    if not isinstance(value, str) or not re.fullmatch(ID_RE, value):
        raise ValueError(
            "%s malformed: %r (wanted pattern %s)" % (slot, value, ID_RE))
    return value


def _require_kind(kind: Any) -> str:
    """ID_RE charset on a ticket kind (the store's own kinds pass)."""
    if not isinstance(kind, str) or not re.fullmatch(ID_RE, kind):
        raise ValueError("kind malformed: %r" % (kind,))
    return kind


def _ticket_id(ticket_id: Optional[str]) -> str:
    """None -> a fresh 12-hex id; otherwise a validated 12-hex string."""
    if ticket_id is None:
        return new_ticket_id()
    if not isinstance(ticket_id, str) or not re.fullmatch(
            TICKET_ID_RE, ticket_id):
        raise ValueError(
            "ticket id must be 12 lowercase hex chars, got: %r"
            % (ticket_id,))
    return ticket_id


def _severity_norm(value: Any) -> Optional[str]:
    """The severity field normalized to lowercase, or None when
    non-conforming (call sites carry the message)."""
    if isinstance(value, str) and value.strip().lower() in SEVERITIES:
        return value.strip().lower()
    return None


def _free_text(value: Any, slot: str) -> Optional[str]:
    """A free-text details slot: absent/None -> None, a non-blank str
    verbatim, a blank str -> None, a non-str -> the ValueError."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(REASON_TEXT % (slot, value))
    return value if value.strip() else None


def open_ticket(
    engagement_id: Any,
    finding: Any,
    target: Any,
    now: Any,
    kind: str = KIND_REMEDIATION,
    ticket_id: Optional[str] = None,
) -> Dict[str, Any]:
    """One append-ready soc-tickets open payload for a single
    engagement finding."""
    good_engagement = _require_id(engagement_id, slot="engagement_id")
    good_target = scrub_target(target)
    good_kind = _require_kind(kind)
    hex_id = _ticket_id(ticket_id)
    ts = _utc_stamp(now, "now")
    if not isinstance(finding, dict):
        raise ValueError(REASON_NOT_DICT + ": %r" % (finding,))
    finding_id = _require_id(finding.get("id"), slot="finding id")
    if finding.get("resolved"):
        raise ValueError(
            "finding %s is already resolved - remediation tickets are "
            "opened for unresolved findings only" % finding_id)
    severity_norm = _severity_norm(finding.get("severity"))
    if severity_norm is None:
        raise ValueError(REASON_SEVERITY % (finding.get("severity"),))
    return {
        "id": hex_id,
        "ts": ts,
        "kind": good_kind,
        "target": good_target,
        "status": STATUS_RUNNING,
        "ended": None,
        "details": {
            "source": DETAIL_SOURCE,
            "engagement_id": good_engagement,
            "finding_id": finding_id,
            "severity": severity_norm,
            "summary": _free_text(finding.get("summary"), "summary"),
            "evidence": _free_text(finding.get("evidence"), "evidence"),
        },
    }


def tickets_for_engagement(
    engagement: Any,
    now: Any,
    kind: str = KIND_REMEDIATION,
    ticket_ids: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Append-ready soc-tickets open payloads for an engagement's
    unresolved findings (bundle: tickets / skipped / summary)."""
    if not isinstance(engagement, dict):
        raise ValueError("engagement must be a dict, got: %r" % (engagement,))
    missing = [key for key in ("engagement_id", "target", "findings")
               if key not in engagement]
    if missing:
        raise ValueError("engagement missing required keys: %s" % missing)
    good_engagement = _require_id(
        engagement["engagement_id"], slot="engagement_id")
    good_target = scrub_target(engagement["target"])
    rows = engagement["findings"]
    if not isinstance(rows, (list, tuple)):
        raise ValueError("findings must be a list, got: %r" % (rows,))
    id_map = dict(ticket_ids or {})
    tickets: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    already_resolved = 0
    for row in rows:
        if not isinstance(row, dict):
            skipped.append({"finding_id": MISSING_ID,
                            "reasons": [REASON_NOT_DICT]})
            continue
        reasons: List[str] = []
        raw_id = row.get("id")
        finding_id = MISSING_ID
        if isinstance(raw_id, str) and raw_id.strip():
            finding_id = raw_id.strip()
        if not (isinstance(raw_id, str) and raw_id.strip()):
            reasons.append(REASON_ID_MISSING)
        elif not re.fullmatch(ID_RE, raw_id.strip()):
            reasons.append(REASON_ID_MALFORMED % (raw_id,))
        severity_norm = _severity_norm(row.get("severity"))
        if severity_norm is None:
            reasons.append(REASON_SEVERITY % (row.get("severity"),))
        if row.get("summary") is not None and not isinstance(
                row.get("summary"), str):
            reasons.append(REASON_TEXT % ("summary", row.get("summary")))
        if row.get("evidence") is not None and not isinstance(
                row.get("evidence"), str):
            reasons.append(REASON_TEXT % ("evidence", row.get("evidence")))
        if reasons:
            skipped.append({"finding_id": finding_id, "reasons": reasons})
            continue
        if row.get("resolved"):
            already_resolved += 1
            continue
        clean_row = dict(row, id=finding_id)
        tickets.append(open_ticket(
            good_engagement, clean_row, good_target, now,
            kind=kind, ticket_id=id_map.get(finding_id)))
    return {
        "tickets": tickets,
        "skipped": skipped,
        "summary": {
            "total": len(rows),
            "tickets": len(tickets),
            "skipped": len(skipped),
            "already_resolved": already_resolved,
        },
    }


def close_ticket_payload(
    open_line: Any,
    outcome: Any,
    ended: Any,
    evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """The append-ready soc-tickets done line that closes an open
    engagement ticket (same id/kind/target; one clock stamps both ts
    and ended)."""
    if not isinstance(open_line, dict):
        raise ValueError(
            "close_ticket_payload needs a dict open line, got: %r"
            % (open_line,))
    hex_id = open_line.get("id")
    if not isinstance(hex_id, str) or not re.fullmatch(TICKET_ID_RE, hex_id):
        raise ValueError("cannot close: ticket id malformed: %r" % (hex_id,))
    if (open_line.get("status") != STATUS_RUNNING
            or open_line.get("ended") is not None):
        raise ValueError(
            "cannot close ticket %s: the given line is not an open "
            "running line (status %r, ended %r)"
            % (hex_id, open_line.get("status"), open_line.get("ended")))
    kind = _require_kind(open_line.get("kind"))
    if "target" not in open_line:
        raise ValueError("cannot close: open line missing target")
    good_target = scrub_target(open_line["target"])
    ended_iso = _utc_stamp(ended, "ended")
    if not isinstance(outcome, str) or not outcome.strip():
        raise ValueError(
            "outcome must be a non-blank string, got: %r" % (outcome,))
    if evidence_path is not None and not isinstance(evidence_path, str):
        raise ValueError(
            "evidence_path must be a string, got: %r" % (evidence_path,))
    details = open_line.get("details")
    details = details if isinstance(details, dict) else {}
    engagement_id = details.get("engagement_id")
    finding_id = details.get("finding_id")
    return {
        "id": hex_id,
        "ts": ended_iso,
        "kind": kind,
        "target": good_target,
        "status": STATUS_DONE,
        "ended": ended_iso,
        "details": {
            "source": DETAIL_SOURCE,
            "engagement_id": (
                engagement_id
                if isinstance(engagement_id, str) and engagement_id.strip()
                else None),
            "finding_id": (
                finding_id
                if isinstance(finding_id, str) and finding_id.strip()
                else None),
            "outcome": outcome,
            "evidence": evidence_path,
        },
    }


def ticket_states(lines: Any) -> Dict[str, Any]:
    """Fold recorded soc-tickets lines into per-id open/closed state;
    the latest line per id wins (reopened ids are open again)."""
    rows = list(lines) if lines else []
    latest: Dict[str, Dict[str, Any]] = {}
    bad_lines: List[Dict[str, Any]] = []
    for index, line in enumerate(rows):
        if not isinstance(line, dict):
            bad_lines.append({"index": index, "id": None,
                              "reason": "line must be a dict"})
            continue
        hex_id = line.get("id")
        if not isinstance(hex_id, str) or not re.fullmatch(
                TICKET_ID_RE, hex_id):
            bad_lines.append({
                "index": index,
                "id": hex_id if isinstance(hex_id, str) else None,
                "reason": "line id malformed: %r" % (hex_id,)})
            continue
        latest[hex_id] = line
    states: Dict[str, str] = {}
    for hex_id, line in latest.items():
        if (line.get("status") == STATUS_RUNNING
                and line.get("ended") is None):
            states[hex_id] = "open"
        elif line.get("status") == STATUS_DONE:
            states[hex_id] = "closed"
        else:
            states[hex_id] = "unknown"
    open_ids = sorted(i for i, s in states.items() if s == "open")
    closed_ids = sorted(i for i, s in states.items() if s == "closed")
    return {
        "states": states,
        "open_ids": open_ids,
        "closed_ids": closed_ids,
        "bad_lines": bad_lines,
        "counts": {
            "lines": len(rows),
            "open": len(open_ids),
            "closed": len(closed_ids),
            "unknown": sum(1 for s in states.values() if s == "unknown"),
            "bad": len(bad_lines),
        },
    }
