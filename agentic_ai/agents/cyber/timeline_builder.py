"""Attack-path timeline builder (KA-083): audit events -> an ordered,
time-aware attack-path chronology. Pure planner module: dict shapes
only - no store, no MCP, no network, no local I/O, and no clock of its
own (the `now` argument is the injectable clock; source-scanned).

AUDIT-EVENT CONTRACT (input `events`): list/tuple of audit-event dicts
with
  ts       ISO-8601 string ("2026-10-07T12:00:00+00:00"; the "Z"
           suffix, offset-less (read as UTC), and fractional-second
           stamps are all tolerated) or a unix epoch string
           ("1696118400", "1696118400.5"; magnitudes at 1e11 or above
           are read as MILLISECONDS). A raw datetime (aware or naive;
           naive reads as UTC) or a numeric epoch is accepted too.
  actor    optional str - who acted (verbatim after the scrub)
  action   optional str - what they did (the phase keyword text)
  target   optional str - where it happened
  source   optional str - which sensor/log produced the row

TOLERANCE (the soc_bridge skip-route pattern): per-event malformation
NEVER raises - it lands in `warnings` and/or the unparsed bucket:
  - a ts that fails to parse sinks the event to the tail of `events`
    (stable, original order) with ts_status "unparsed" and
    ts_utc/ts_epoch None, plus one warning; unparsed rows are excluded
    from the chronology, the gap walk, and the future-skew check - they
    still carry a phase (classification is time-independent)
  - a non-string / blank text field becomes None and warns once
  - a non-dict row warns once and is skipped entirely
CALLER-LEVEL CONTRACT (ValueError, raised - caller errors, not
skip-route material): events not list/tuple, non-positive max_events,
negative or NaN gap threshold, or a naive/wrong-typed now.

RESULT SHAPE (exactly four keys):
  chronology  phase buckets in FIRST-APPEARANCE order along the
              time-sorted parsed stream: {phase, count, started_at,
              ended_at, event_indexes}; the indexes reference the
              row's position in the ORIGINAL input list (= event
              "index" everywhere in this module)
  events      normalized events, STABLY sorted by parsed ts - equal
              stamps keep input order and the unparsed tail keeps
              input order. phase = the fixed keyword table's FIRST
              match scanning PHASES in fixed order over the scrubbed
              action text (unknown/malformed -> "other")
  gaps        adjacent same-target parsed events whose delta EXCEEDS
              gap_threshold_seconds (strictly greater): {target,
              earlier_index, later_index, earlier_ts, later_ts,
              delta_seconds}, emitted along the sorted stream
  warnings    one string per issue, in processing order: the cap
              notice (once) -> input-order row problems -> future-skew
              notices (sorted order) when `now` is injected

CAPS (documented sane sizes): at most max_events rows are processed
(MAX_EVENTS default); every scrubbed string field is control-character
stripped, end-trimmed, and capped at MAX_FIELD_CHARS; warning messages
at MAX_MESSAGE_CHARS; warnings and gaps are therefore also bounded by
the row cap. The scrub is SANITIZE-ONLY (no refusal): hostile
characters are removed, never rejected - refusing hostile inputs stays
the execution boundary of whatever chassis consumes this output
downstream.

PLANNER PURITY: no process spawning, no network facilities, no local
I/O; the only clock is the `now` argument.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- contract constants (the drift alarm; the tests pin them) ------------

PHASES: Tuple[str, ...] = (
    "recon",
    "initial-access",
    "execution",
    "persistence",
    "lateral-movement",
    "post-exploitation",
    "defense-evasion",
    "cleanup",
)
PHASE_OTHER = "other"

# Re-authored keyword -> phase table: scanned phase by phase in the
# fixed PHASES order, keyword by keyword; the FIRST keyword whose
# substring appears in the scrubbed action text wins. Benign triage
# vocabulary only - classifier tokens, never payload strings.
PHASE_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "recon": ("scan", "sweep", "probe", "enumerate", "discover",
              "ping", "whois", "fingerprint", "port"),
    "initial-access": ("login", "logon", "auth", "brute", "credential",
                       "phish", "exploit", "vpn", "password"),
    "execution": ("exec", "run ", "command", "script", "shell", "spawn",
                  "powershell", "process", "wmi", "python", "bash"),
    "persistence": ("persist", "cron", "scheduled", "startup", "autorun",
                    "service install", "backdoor", "systemd", "launchd",
                    "account add", "registry"),
    "lateral-movement": ("lateral", "rdp", "smb ", "pass-the-hash",
                         "psexec", "pivot", "remote login", "jump host",
                         "mount", "network share"),
    "post-exploitation": ("dump", "escalat", "privesc", "sudo", "keylog",
                          "harvest", "collect", "exfil", "mimikatz",
                          "hashdump"),
    "defense-evasion": ("evasion", "obfusc", "clear log", "log clear",
                        "disable", "auditpol", "tamper", "bypass",
                        "wevutil"),
    "cleanup": ("cleanup", "clean up", "erase", "wipe", "shred", "delete",
                "cover track"),
}

MAX_EVENTS = 5000          # sane cap: rows processed per timeline
MAX_FIELD_CHARS = 512      # sane cap: characters kept per scrubbed field
MAX_MESSAGE_CHARS = 240    # sane cap: warning message length
DEFAULT_GAP_SECONDS = 3600.0

REASON_NOT_DICT = "event %d must be a dict, got: %r"
REASON_FIELD_TYPE = "event %d %s must be a string, got: %r"
REASON_TS_MISSING = "event %d ts missing"
REASON_TS_TYPE = "event %d ts must be a string, datetime, or number, got: %r"
REASON_TS_UNPARSED = "event %d ts unparsed: %r"
REASON_CAPPED = ("events capped: processed %d of %d rows; the rest are "
                 "dropped from this timeline")
REASON_FUTURE = "event %d ts is later than the injected now (clock skew)"

NUMERIC_TS = re.compile(r"-?\d+(?:\.\d+)?\Z")
# at or above this magnitude a numeric stamp reads as milliseconds
MS_EPOCH_FLOOR = 1e11


def scrub_text(value: Any) -> Optional[str]:
    """The shared input scrub for event text fields (wp_scrub_target
    pattern, tolerant sanitize form): non-strings and blanks -> None,
    otherwise control characters stripped, ends trimmed, length
    capped."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        ch for ch in value if ord(ch) >= 32 and ord(ch) != 127)
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    return cleaned[:MAX_FIELD_CHARS]


def _truncate(message: str) -> str:
    """Warning messages stay under MAX_MESSAGE_CHARS."""
    return message[:MAX_MESSAGE_CHARS]


def _parse_unix(value: float) -> Optional[datetime]:
    """A unix epoch float -> an aware UTC datetime; magnitudes at
    MS_EPOCH_FLOOR or above read as milliseconds; unrepresentable
    stamps return None instead of raising."""
    seconds = value / 1000.0 if abs(value) >= MS_EPOCH_FLOOR else value
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_ts(value: Any) -> Optional[datetime]:
    """ISO-8601 / unix string / datetime / number -> an aware UTC
    datetime; anything unparseable returns None (never a raise)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        naive = value
    elif isinstance(value, (int, float)):
        return _parse_unix(float(value))
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if NUMERIC_TS.fullmatch(text):
            return _parse_unix(float(text))
        candidate = (text[:-1] + "+00:00") if text[-1] in "Zz" else text
        try:
            naive = datetime.fromisoformat(candidate)
        except ValueError:
            return None
    else:
        return None
    if naive.tzinfo is None or naive.utcoffset() is None:
        naive = naive.replace(tzinfo=timezone.utc)
    return naive.astimezone(timezone.utc)


def _phase_for(action: Optional[str]) -> str:
    """The fixed keyword table, scanned in PHASES order; the first
    keyword that appears anywhere in the scrubbed action wins; no
    text or no match -> "other"."""
    if not action:
        return PHASE_OTHER
    text = action.casefold()
    for phase in PHASES:
        for keyword in PHASE_KEYWORDS[phase]:
            if keyword in text:
                return phase
    return PHASE_OTHER


def build_timeline(
    events: Any,
    now: Optional[datetime] = None,
    max_events: int = MAX_EVENTS,
    gap_threshold_seconds: float = DEFAULT_GAP_SECONDS,
) -> Dict[str, Any]:
    """Audit events -> {chronology, events, gaps, warnings} (the module
    card above is the contract)."""
    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list, got: %r" % (events,))
    if (not isinstance(max_events, int) or isinstance(max_events, bool)
            or max_events <= 0):
        raise ValueError("max_events must be a positive int, got: %r"
                         % (max_events,))
    if (isinstance(gap_threshold_seconds, bool)
            or not isinstance(gap_threshold_seconds, (int, float))
            or not gap_threshold_seconds >= 0):
        raise ValueError(
            "gap_threshold_seconds must be a non-negative number, "
            "got: %r" % (gap_threshold_seconds,))
    if now is not None and (not isinstance(now, datetime)
                            or now.utcoffset() is None):
        raise ValueError(
            "now must be an aware datetime (naive is refused), got %r"
            % (now,))
    threshold = float(gap_threshold_seconds)
    now_epoch = now.timestamp() if now is not None else None

    total = len(events)
    warnings: List[str] = []
    if total > max_events:
        warnings.append(_truncate(REASON_CAPPED % (max_events, total)))

    normalized: List[Dict[str, Any]] = []
    for row_index, row in enumerate(events[:max_events]):
        if not isinstance(row, dict):
            warnings.append(_truncate(
                REASON_NOT_DICT % (row_index, row)))
            continue
        fields: Dict[str, Optional[str]] = {}
        for slot in ("actor", "action", "target", "source"):
            raw = row.get(slot)
            if raw is not None and not isinstance(raw, str):
                warnings.append(_truncate(
                    REASON_FIELD_TYPE % (row_index, slot, raw)))
            fields[slot] = scrub_text(raw)

        ts_value = row.get("ts")
        ts_raw: Optional[str] = None
        moment: Optional[datetime] = None
        if ts_value is None:
            warnings.append(_truncate(REASON_TS_MISSING % (row_index,)))
        elif isinstance(ts_value, bool) or not isinstance(
                ts_value, (str, datetime, int, float)):
            warnings.append(_truncate(
                REASON_TS_TYPE % (row_index, ts_value)))
        elif isinstance(ts_value, str):
            ts_raw = scrub_text(ts_value)
            if ts_raw is None:
                warnings.append(_truncate(
                    REASON_TS_UNPARSED % (row_index, ts_value)))
            else:
                moment = _parse_ts(ts_raw)
        else:
            ts_raw = str(ts_value)
            moment = _parse_ts(ts_value)
        if moment is None and ts_raw is not None:
            warnings.append(_truncate(
                REASON_TS_UNPARSED % (row_index, ts_raw)))

        normalized.append({
            "index": row_index,
            "ts_raw": ts_raw,
            "ts_utc": moment.isoformat() if moment is not None else None,
            "ts_epoch": moment.timestamp() if moment is not None else None,
            "ts_status": "parsed" if moment is not None else "unparsed",
            "actor": fields["actor"],
            "action": fields["action"],
            "target": fields["target"],
            "source": fields["source"],
            "phase": _phase_for(fields["action"]),
        })

    ordered = sorted(
        normalized,
        key=lambda event: event["ts_epoch"]
        if event["ts_epoch"] is not None else float("inf"))

    chronology: List[Dict[str, Any]] = []
    phase_buckets: Dict[str, Dict[str, Any]] = {}
    per_target: Dict[str, List[Dict[str, Any]]] = {}
    gaps: List[Dict[str, Any]] = []
    for event in ordered:
        if event["ts_epoch"] is None:
            continue  # the unparsed tail: no chronology, no gaps
        bucket = phase_buckets.get(event["phase"])
        if bucket is None:
            bucket = {"phase": event["phase"], "count": 0,
                      "started_at": None, "ended_at": None,
                      "event_indexes": []}
            phase_buckets[event["phase"]] = bucket
            chronology.append(bucket)
        bucket["count"] += 1
        bucket["event_indexes"].append(event["index"])
        if bucket["started_at"] is None:
            bucket["started_at"] = event["ts_utc"]
        bucket["ended_at"] = event["ts_utc"]

        target = event["target"]
        if not target:
            continue
        stream = per_target.get(target)
        if stream is None:
            stream = []
            per_target[target] = stream
        if stream:
            previous = stream[-1]
            delta_seconds = event["ts_epoch"] - previous["ts_epoch"]
            if delta_seconds > threshold:
                gaps.append({
                    "target": target,
                    "earlier_index": previous["index"],
                    "later_index": event["index"],
                    "earlier_ts": previous["ts_utc"],
                    "later_ts": event["ts_utc"],
                    "delta_seconds": delta_seconds,
                })
        stream.append(event)

    if now_epoch is not None:
        for event in ordered:
            if (event["ts_epoch"] is not None
                    and event["ts_epoch"] > now_epoch):
                warnings.append(REASON_FUTURE % (event["index"],))

    return {
        "chronology": chronology,
        "events": ordered,
        "gaps": gaps,
        "warnings": warnings,
    }
