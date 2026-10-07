"""Remediation-ticket bridge (KA-070 / OPT-70): failed lab verifications
-> append-ready SOC ticket lines in the soc-remediation-tickets store
contract. PURE PLANNER: no file I/O, no process spawning, no network, no
wall-clock reads - the clock `now` is INJECTED, the store arrives as an
in-memory list of already-parsed JSONL lines, and the actual append stays
with the wiring layer.

THE STORE CONTRACT (pinned from the soc-remediation-tickets skill;
mocked shapes only in this [none] environment):
  line keys (EXACT): id (12 lowercase hex), ts (UTC ISO-8601 +00:00),
  kind (stig_remediate|stig_scan), target (hostname or control id),
  status (running|done), ended (null while running, timestamp when
  done), details (dict).

  - an OPEN ticket is the id whose LATEST line is running with ended
    null; a CLOSE appends a done line for the same id (never rewrites,
    never deletes); the done line's details carry the outcome.
  - never append a line for an id whose current state is open.
  - a done line is the LAST line for that id, forever.
  - ticket state = the LATEST line for the id, never "any running line
    exists" (the per-line filter misreport the skill bans).

TARGETING (pinned from the skill):
  - host-targeted (target = hostname; details carries the per-control
    dicts) when one host fails several controls
  - control-targeted (target = the control id - the stig_remediate
    original convention) when one control spans many hosts
  - host names and control ids are NEVER mixed into one target string
  - host rule has precedence: once a host is group-claimed, ALL of its
    failures (its controls AND its control-less verifications) ride that
    one host ticket; a multi-host control then only gets tickets for its
    UNCLAIMED hosts. (The one determinism decision the two skill rules
    leave open when both are true for a pair - pinned here.)
  - an isolated failure (single host x single control, neither rule)
    defaults to the control-targeted original convention
  - a control-less verification (a lab-battery result with no STIG
    control) is host-targeted by necessity

OWNER EXCEPTIONS: recorded as CLOSED tickets (status done) - the close
carries the owner's directive quoted verbatim in details (modulo the
control-character scrub), the per-unit decisions, and the evidence
paths; the excepted failure stays visible by design.

BOOKING-SLIP RECOVERY: an accidental re-append under a fresh id is
repaired APPEND-ONLY - plan_slip_recovery plans a done line superseding
the slip ("superseded-duplicate: ... already open as <real-id>") plus
the intended record under its own id.

FAILURE INPUT (one lab-verification result; dict):
  verification_id  required, ^[A-Za-z0-9_.-]{1,64}$
  host             required, must survive scrub_target
  control_id       optional (STIG control), same charset as the id
  severity         optional, critical|high|medium|low (case-insensitive)
  summary          optional free text (control-char scrub)
  evidence_path    optional, space-free path-ish string
  finding_ref      optional (AF-... register references)
  fix / exception  optional remediation-path option texts
  unknown keys are absorbed (ignored). None means absent everywhere.

validate_target is consulted via an INJECTED validator - an agent duck
(.validate_target attribute) or a bare callable - and its ValueError
lands in the refused bucket, never a crash; absent (None) is the silent
fallback, no consult. The consult guards the HOST (the touched system);
control ids are registry strings, not targets. No chassis import exists
in this module (lazy or otherwise): the bridge composes nothing.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

# --- store-contract constants (renames are loud drift alarms) ------------

LINE_KEYS = ("id", "ts", "kind", "target", "status", "ended", "details")
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUSES = (STATUS_RUNNING, STATUS_DONE)

KIND_STIG_REMEDIATE = "stig_remediate"
KIND_STIG_SCAN = "stig_scan"
KINDS = (KIND_STIG_REMEDIATE, KIND_STIG_SCAN)
DEFAULT_KIND = KIND_STIG_REMEDIATE

TICKET_ID_RE = r"[0-9a-f]{12}"
NAME_RE = r"[A-Za-z0-9_.\-]{1,64}"
TARGET_RE = r"[A-Za-z0-9_.\-]{1,128}"
EVIDENCE_RE = r"[A-Za-z0-9_./:@%~+\-]{1,200}"
SEVERITIES = ("critical", "high", "medium", "low")
ISO_SUFFIX = "+00:00"

ORIGIN_TAG = "kali-agent:lab-verification"

DECISION_FIXED = "fixed"
DECISION_EXCEPTION = "excepted"
DECISIONS = (DECISION_FIXED, DECISION_EXCEPTION)

_OPTIONAL_FIELDS = ("severity", "summary", "evidence_path",
                    "finding_ref", "fix", "exception")


# --- shared input gates ---------------------------------------------------


def iso_utc(now: Any) -> str:
    """iso_utc(now) -> str; normalize an injected clock to the store's
    UTC ISO-8601 +00:00 timestamp string."""
    if isinstance(now, datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError(
                "now must be timezone-aware (the store stamps UTC "
                "+00:00); got naive %r" % (now.isoformat(),))
        if now.utcoffset().total_seconds() != 0:
            raise ValueError(
                "now must be UTC (offset 0), got offset %r" % (
                    now.utcoffset(),))
        return now.isoformat()
    if isinstance(now, str):
        if not now.endswith(ISO_SUFFIX):
            raise ValueError(
                "timestamp must end with +00:00 (store convention); "
                "got %r" % (now,))
        try:
            parsed = datetime.fromisoformat(now)
        except ValueError:
            raise ValueError(
                "timestamp is not ISO-8601: %r" % (now,)) from None
        if parsed.utcoffset() is None or \
                parsed.utcoffset().total_seconds() != 0:
            raise ValueError(
                "timestamp must be a UTC zero-offset stamp: %r" % (now,))
        return now
    raise ValueError(
        "now must be an aware datetime or a UTC ISO-8601 +00:00 string, "
        "got %r" % (now,))


def scrub_target(target: Any) -> str:
    """scrub_target(target) -> str; the shared input gate for ticket
    target strings (hostname or control id)."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")
    scrubbed = target.strip()
    if re.fullmatch(TARGET_RE, scrubbed) is None:
        raise ValueError(
            "rejected target %r: characters outside [A-Za-z0-9_.-], "
            "control characters/whitespace, or over 128 chars" % (target,))
    if ".." in scrubbed:
        raise ValueError(
            "rejected target %r: '..' path-traversal marker" % (target,))
    if not re.search(r"[A-Za-z0-9]", scrubbed):
        raise ValueError(
            "rejected target %r: needs at least one alphanumeric" % (
                target,))
    return scrubbed


def scrub_text(text: Any) -> Optional[str]:
    """scrub_text(text) -> str|None; the shared free-text scrub for
    detail values (summaries, outcomes, owner directives): None
    passthrough, control characters and line breaks become spaces."""
    if text is None:
        return None
    if not isinstance(text, str):
        raise ValueError(
            "free-text detail must be a string or None, got %r" % (text,))
    cleaned = "".join(
        " " if (ord(ch) < 32 or ord(ch) == 0x7f) else ch for ch in text)
    return cleaned.strip()


def _scrub_evidence(path: Any) -> str:
    """Evidence-path scrub: space-free, control-free, capped at 200."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("evidence_path must be a non-empty string")
    scrubbed = path.strip()
    if not re.fullmatch(EVIDENCE_RE, scrubbed):
        raise ValueError(
            "rejected evidence_path %r: use a space-free path of "
            "letters, digits and _ . / : @ ~ + - up to 200 chars" % (
                path,))
    return scrubbed


def _check_ticket_id(value: Any, what: str) -> str:
    """A store id must be 12 lowercase hex (uuid4().hex[:12] discipline)."""
    if not (isinstance(value, str)
            and re.fullmatch(TICKET_ID_RE, value)):
        raise ValueError(
            "%s must be 12 lowercase hex (uuid4().hex[:12] discipline), "
            "got %r" % (what, value))
    return value


def new_ticket_id() -> str:
    """new_ticket_id() -> str; a fresh 12-hex store id - the
    soc-remediation-tickets uuid4().hex[:12] discipline."""
    return uuid.uuid4().hex[:12]


def consult_target_validator(validator: Any, target: str) -> None:
    """consulta consult helper: consult_target_validator(validator,
    target) -> None; consult the chassis validate_target through an
    injected validator - agent duck (.validate_target attribute) or bare
    callable - with the silent fallback (no consult) when absent."""
    fn = getattr(validator, "validate_target", None)
    if fn is None:
        fn = validator
    if not callable(fn):
        return  # absent validator: silent fallback, no consult
    fn(target)


# --- store-contract validation -------------------------------------------


def validate_line(line: Any) -> None:
    """validate_line(line) -> None; actionable ValueError on any
    single-line store-contract miss (registry-unknown-ID pattern: the
    message names the offending field and value)."""
    if not isinstance(line, dict):
        raise ValueError("ticket line must be a dict, got %r" % (line,))
    missing = [key for key in LINE_KEYS if key not in line]
    if missing:
        raise ValueError("ticket line missing keys: %s" % (missing,))
    extra = [key for key in line if key not in LINE_KEYS]
    if extra:
        raise ValueError("ticket line carries unknown keys: %s" % (extra,))
    _check_ticket_id(line["id"], "ticket id")
    try:
        iso_utc(line["ts"])
    except ValueError as exc:
        raise ValueError("ts: %s" % exc) from None
    status = line["status"]
    if status not in STATUSES:
        raise ValueError(
            "status must be one of running|done, got %r" % (status,))
    ended = line["ended"]
    if status == STATUS_RUNNING:
        if ended is not None:
            raise ValueError(
                "a running line must carry ended: null, got %r" % (ended,))
    else:
        try:
            iso_utc(ended)
        except ValueError as exc:
            raise ValueError("ended: %s" % exc) from None
    if line["kind"] not in KINDS:
        raise ValueError(
            "kind must be one of stig_remediate|stig_scan, got %r" % (
                line["kind"],))
    try:
        scrub_target(line["target"])
    except ValueError as exc:
        raise ValueError("target: %s" % exc) from None
    details = line["details"]
    if not isinstance(details, dict):
        raise ValueError("details must be a dict, got %r" % (details,))
    if status == STATUS_DONE:
        outcome = details.get("outcome")
        if not (isinstance(outcome, str) and outcome.strip()):
            raise ValueError(
                "a done line's details must carry a non-blank outcome")


def validate_store(lines: Any) -> List[str]:
    """validate_store(lines) -> list; append-only structural findings
    for a parsed store snapshot - malformed lines, duplicate open
    appends for a still-open id, and appends after a done line (empty
    list = clean)."""
    if not isinstance(lines, (list, tuple)):
        raise ValueError("store lines must be a list of parsed lines")
    findings: List[str] = []
    state: Dict[str, str] = {}
    first_open: Dict[str, int] = {}
    for index, line in enumerate(lines, start=1):
        prefix = "line %d" % index
        try:
            validate_line(line)
        except ValueError as exc:
            findings.append("%s: %s" % (prefix, exc))
            continue
        tid = line["id"]
        prev = state.get(tid)
        if prev == STATUS_DONE:
            findings.append(
                "%s: append after close for id %s (a done line is the "
                "last line for its id)" % (prefix, tid))
        elif prev == STATUS_RUNNING and line["status"] == STATUS_RUNNING:
            findings.append(
                "%s: duplicate open append for id %s (already open at "
                "line %d)" % (prefix, tid, first_open[tid]))
        state[tid] = line["status"]
        if line["status"] == STATUS_RUNNING and prev != STATUS_RUNNING:
            first_open[tid] = index
    return findings


def ticket_state(lines: Any) -> Dict[str, Any]:
    """ticket_state(lines) -> dict; replay the store to each ticket's
    LATEST line - state is the latest line, never 'any running line
    exists' (the misreport the skill bans)."""
    if not isinstance(lines, (list, tuple)):
        raise ValueError("store lines must be a list of parsed lines")
    open_lines: Dict[str, Dict[str, Any]] = {}
    closed: Dict[str, Dict[str, Any]] = {}
    for index, line in enumerate(lines, start=1):
        try:
            validate_line(line)
        except ValueError as exc:
            raise ValueError("line %d: %s" % (index, exc)) from None
        tid = line["id"]
        if line["status"] == STATUS_RUNNING:
            open_lines[tid] = line
            closed.pop(tid, None)
        else:
            closed[tid] = line
            open_lines.pop(tid, None)
    return {
        "open": open_lines,
        "closed": closed,
        "open_targets": {line["target"]: line["id"]
                         for line in open_lines.values()},
        "summary": {"ids": len(open_lines) + len(closed),
                    "open": len(open_lines),
                    "closed": len(closed)},
    }


# --- line builders --------------------------------------------------------


def open_ticket_line(
    target: Any,
    details: Any,
    *,
    id: Any,
    now: Any,
    kind: str = DEFAULT_KIND,
    target_validator: Any = None,
) -> Dict[str, Any]:
    """open_ticket_line(target, details, *, id, now, kind=...,
    target_validator=None) -> dict; one append-ready running ticket
    line for a failed lab verification (the fresh id comes from the
    caller's uuid4 discipline, the clock is injected)."""
    scrubbed = scrub_target(target)
    if not isinstance(details, dict):
        raise ValueError(
            "ticket details must be a dict, got %r" % (details,))
    consult_target_validator(target_validator, scrubbed)
    if kind not in KINDS:
        raise ValueError(
            "kind must be one of stig_remediate|stig_scan, got %r" % (
                kind,))
    line = {
        "id": _check_ticket_id(id, "ticket id"),
        "ts": iso_utc(now),
        "kind": kind,
        "target": scrubbed,
        "status": STATUS_RUNNING,
        "ended": None,
        "details": dict(details),
    }
    validate_line(line)  # self-checked contract: every produced line is valid
    return line


def _decidable_units(open_line: Dict[str, Any]) -> List[str]:
    """The units a close must decide, in first-appearance order: a
    host ticket's controls and verifications; a control ticket's own
    control id; a foreign line's target itself."""
    details = open_line["details"]
    units: List[str] = []
    for entry in details.get("controls") or []:
        if not isinstance(entry, dict) or not (
                isinstance(entry.get("control"), str)
                and entry["control"].strip()):
            raise ValueError(
                "details carries a malformed control entry: %r" % (entry,))
        units.append(entry["control"].strip())
    for entry2 in details.get("verifications") or []:
        if not isinstance(entry2, dict) or not (
                isinstance(entry2.get("verification_id"), str)
                and entry2["verification_id"].strip()):
            raise ValueError(
                "details carries a malformed verification entry: %r" % (
                    entry2,))
        units.append(entry2["verification_id"].strip())
    if not units:
        units = [open_line["target"]]
    return units


def close_ticket_line(
    open_line: Any,
    *,
    decisions: Any,
    outcome: Any,
    now: Any,
    owner_directive: Any = None,
    evidence_paths: Any = None,
) -> Dict[str, Any]:
    """close_ticket_line(open_line, *, decisions, outcome, now,
    owner_directive=None, evidence_paths=None) -> dict; the append-only
    done line that closes an open ticket - partial resolution is
    refused, and owner exceptions carry the directive verbatim."""
    validate_line(open_line)
    if open_line["status"] != STATUS_RUNNING:
        raise ValueError(
            "only an open (running) ticket may be closed; ticket %s is "
            "already done" % (open_line["id"],))
    units = _decidable_units(open_line)
    if not isinstance(decisions, dict):
        raise ValueError(
            "decisions must be a {unit: fixed|excepted} dict, got %r" % (
                decisions,))
    expected = set(units)
    given = {str(key) for key in decisions}
    missing = sorted(expected - given)
    extra = sorted(given - expected)
    if missing:
        raise ValueError(
            "partial resolution is not a close - undecided units: %s" % (
                missing,))
    if extra:
        raise ValueError(
            "decisions name units not covered by this ticket: %s" % (
                extra,))
    bad_values = sorted(
        {str(value) for value in decisions.values()
         if str(value) not in DECISIONS})
    if bad_values:
        raise ValueError(
            "decision values must be fixed|excepted, got: %s" % (
                bad_values,))
    directive = scrub_text(owner_directive)
    if any(str(value) == DECISION_EXCEPTION
           for value in decisions.values()) and not directive:
        raise ValueError(
            "an owner-accepted exception requires the owner's directive "
            "quoted verbatim (owner_directive)")
    cleaned_outcome = scrub_text(outcome)
    if not cleaned_outcome:
        raise ValueError("the close outcome must be a non-blank summary")
    now_str = iso_utc(now)
    details: Dict[str, Any] = {
        "outcome": cleaned_outcome,
        "decisions": {key: str(decisions[key])
                      for key in sorted(decisions)},
    }
    if directive:
        details["owner_directive"] = directive
    if evidence_paths is not None:
        if not isinstance(evidence_paths, (list, tuple)):
            raise ValueError(
                "evidence_paths must be a list of strings, got %r" % (
                    evidence_paths,))
        cleaned_paths = [_scrub_evidence(path) for path in evidence_paths]
        if cleaned_paths:
            details["evidence_paths"] = cleaned_paths
    line = {
        "id": open_line["id"],
        "ts": now_str,
        "kind": open_line["kind"],
        "target": open_line["target"],
        "status": STATUS_DONE,
        "ended": now_str,
        "details": details,
    }
    validate_line(line)
    return line


# --- the bridge core ------------------------------------------------------


def plan_tickets(
    failures: Any,
    *,
    now: Any,
    store_lines: Any = None,
    kind: str = DEFAULT_KIND,
    id_factory: Any = None,
    target_validator: Any = None,
) -> Dict[str, Any]:
    """plan_tickets(failures, *, now, store_lines=None, kind=...,
    id_factory=None, target_validator=None) -> dict; THE bridge core:
    failed lab verifications in, append-ready SOC ticket lines out (the
    wiring layer owns the actual file append)."""
    if kind not in KINDS:
        raise ValueError(
            "kind must be one of stig_remediate|stig_scan, got %r" % (
                kind,))
    if id_factory is None:
        id_factory = new_ticket_id
    open_targets: Dict[str, str] = {}
    if store_lines is not None:
        state = ticket_state(store_lines)
        open_targets = state["open_targets"]

    rows: List[Any] = (
        [failures] if isinstance(failures, dict) else list(failures or []))
    refused: List[Dict[str, Any]] = []
    survivors: List[Dict[str, Any]] = []
    seen_pairs: set = set()
    notes: List[str] = []

    for row in rows:
        raw_id = row.get("verification_id") if isinstance(row, dict) else None
        vid = raw_id.strip() if (
            isinstance(raw_id, str) and raw_id.strip()) else None
        if vid is not None and re.fullmatch(NAME_RE, vid) is None:
            vid = None
        reasons: List[str] = []
        if not isinstance(row, dict):
            reasons.append("verification result not a dict")
        else:
            if raw_id is None or not (
                    isinstance(raw_id, str) and raw_id.strip()):
                reasons.append("verification_id missing")
            elif re.fullmatch(NAME_RE, raw_id.strip()) is None:
                reasons.append(
                    "verification_id malformed: %r" % (raw_id,))
            scrubbed = None
            host = row.get("host")
            if isinstance(host, str) and host.strip():
                try:
                    scrubbed = scrub_target(host)
                except ValueError as exc:
                    reasons.append("host: %s" % exc)
            else:
                reasons.append("host missing")
            control = row.get("control_id")
            control_valid: Optional[str] = None
            if control is not None:
                if isinstance(control, str) and \
                        re.fullmatch(NAME_RE, control.strip() or ""):
                    control_valid = control.strip()
                else:
                    reasons.append(
                        "control_id malformed: %r" % (control,))
            severity = row.get("severity")
            severity_valid: Optional[str] = None
            if severity is not None:
                if isinstance(severity, str) and \
                        severity.strip().lower() in SEVERITIES:
                    severity_valid = severity.strip().lower()
                else:
                    reasons.append(
                        "severity must be one of critical|high|medium|"
                        "low, got: %r" % (severity,))
            packed: Dict[str, Any] = {}
            for field in ("summary", "fix", "exception"):
                value = row.get(field)
                if value is not None:
                    try:
                        packed[field] = scrub_text(value)
                    except ValueError as exc:
                        reasons.append("%s: %s" % (field, exc))
            evidence = row.get("evidence_path")
            if evidence is not None:
                try:
                    packed["evidence_path"] = _scrub_evidence(evidence)
                except ValueError as exc:
                    reasons.append("evidence_path: %s" % exc)
            find_ref = row.get("finding_ref")
            if find_ref is not None:
                if isinstance(find_ref, str) and \
                        re.fullmatch(NAME_RE, find_ref.strip() or ""):
                    packed["finding_ref"] = find_ref.strip()
                else:
                    reasons.append("finding_ref malformed: %r" % (find_ref,))
            # the validate_target consult runs only for otherwise-clean
            # rows; its ValueError joins the refusal reasons
            if not reasons and scrubbed is not None:
                try:
                    consult_target_validator(target_validator, scrubbed)
                except ValueError as exc:
                    reasons.append("target validator: %s" % exc)
        if reasons:
            refused.append({"verification_id": vid or "<missing-id>",
                            "reasons": reasons})
            continue
        survivor = dict(packed)
        survivor["verification_id"] = vid
        survivor["host"] = scrubbed
        survivor["control_id"] = control_valid
        survivor["severity"] = severity_valid
        pair = (scrubbed, control_valid or "")
        if pair in seen_pairs:
            notes.append(
                "duplicate verification result ignored: %s (first "
                "occurrence wins)" % (vid,))
            continue
        seen_pairs.add(pair)
        survivors.append(survivor)

    def _unit(survivor: Dict[str, Any],
              name_key: Optional[tuple]) -> Dict[str, Any]:
        unit: Dict[str, Any] = {}
        if name_key is not None:
            unit[name_key[0]] = survivor[name_key[1]]
        unit["verification_id"] = survivor["verification_id"]
        for field in _OPTIONAL_FIELDS:
            if survivor.get(field):
                unit[field] = survivor[field]
        return unit

    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for survivor in survivors:
        by_host.setdefault(survivor["host"], []).append(survivor)

    # pass 1: host rule (host fails several DISTINCT controls) claims
    # every failure of the claimed host - the host ticket holds its
    # controls AND its control-less verifications in one place.
    claimed: set = set()
    host_claimed_a_spread_control = False
    lines_planned: List[Dict[str, Any]] = []
    host_controls_spread: Dict[str, set] = {}
    for host, items in by_host.items():
        distinct = {item["control_id"] for item in items
                    if item["control_id"] is not None}
        if len(distinct) >= 2:
            claimed.add(host)
            host_controls_spread[host] = distinct
    for host, items in by_host.items():
        if host not in claimed:
            continue
        for item in items:
            if item["control_id"] is not None:
                claimed.add((host, item["control_id"]))
        controls = [
            _unit(item, ("control", "control_id")) for item in items
            if item["control_id"] is not None]
        verifications = [
            _unit(item, None) for item in items
            if item["control_id"] is None]
        lines_planned.append((host, {
            "origin": ORIGIN_TAG,
            "host": host,
            "controls": controls,
            "verifications": verifications,
        }))
    for host, distinct in host_controls_spread.items():
        for survivor in survivors:
            if survivor["control_id"] in distinct and \
                    survivor["host"] != host:
                host_claimed_a_spread_control = True

    # pass 2/3: control rule among UNCLAIMED failures; a leftover
    # control gets one control-targeted line for its survivors (the
    # original stig_remediate convention); leftover control-less
    # verifications become their hosts' own (verification-only) tickets.
    by_control: Dict[str, List[Dict[str, Any]]] = {}
    for survivor in survivors:
        if survivor["control_id"] is None:
            continue
        if (survivor["host"], survivor["control_id"]) in claimed:
            continue
        by_control.setdefault(survivor["control_id"], []).append(survivor)
    for control, items in by_control.items():
        lines_planned.append((control, {
            "origin": ORIGIN_TAG,
            "control": control,
            "hosts": [_unit(item, ("host", "host")) for item in items],
        }))
    controlless: Dict[str, List[Dict[str, Any]]] = {}
    for survivor in survivors:
        if survivor["control_id"] is None and survivor["host"] not in claimed:
            controlless.setdefault(survivor["host"], []).append(survivor)
    for host, items in controlless.items():
        lines_planned.append((host, {
            "origin": ORIGIN_TAG,
            "host": host,
            "controls": [],
            "verifications": [_unit(item, None) for item in items],
        }))

    skipped: List[Dict[str, Any]] = []
    used_targets: set = set()
    final_lines: List[Dict[str, Any]] = []
    for target, details in lines_planned:
        if target in used_targets or target in open_targets:
            if target in open_targets:
                skipped.append({
                    "target": target,
                    "ticket_id": open_targets[target],
                    "reason": "already open as %s" % (
                        open_targets[target],),
                })
                continue
            raise ValueError(
                "two planned tickets share target %r - fix the "
                "reported data first" % (target,))
        used_targets.add(target)
        ticket_id = id_factory()
        existing = set()
        if store_lines is not None:
            existing = {line["id"] for line in store_lines
                        if isinstance(line, dict)}
        if ticket_id in existing:
            raise ValueError(
                "planned id %s already exists in the store - never "
                "re-append for an existing id" % (ticket_id,))
        final_lines.append(open_ticket_line(
            target, details, id=ticket_id, now=now, kind=kind,
            target_validator=None))

    host_count = sum(1 for _, details in lines_planned
                     if "hosts" not in details)
    control_count = sum(1 for _, details in lines_planned
                        if "hosts" in details)
    notes.insert(0, (
        "append-only contract: these are PLANNED appends; the wiring "
        "layer owns the store write (soc-remediation-tickets skill)"))
    notes.insert(1, "targeting: %d host-targeted, %d control-targeted "
                 "planned ticket(s)" % (host_count, control_count))
    if store_lines is None:
        notes.append(
            "no store snapshot supplied - the duplicate-target check "
            "was skipped")
    if host_claimed_a_spread_control:
        notes.append(
            "a control spanning several hosts rides its host's ticket "
            "where the host rule has precedence")
    return {
        "lines": final_lines,
        "refused": refused,
        "skipped": skipped,
        "notes": notes,
        "summary": {
            "verifications": len(rows),
            "plannable": len(survivors),
            "refused": len(refused),
            "skipped": len(skipped),
            "lines": len(final_lines),
        },
    }


# --- append-only repair ---------------------------------------------------


def plan_slip_recovery(
    store_lines: Any,
    slip_id: Any,
    real_id: Any,
    *,
    now: Any,
    intended: Any = None,
) -> Dict[str, Any]:
    """plan_slip_recovery(store_lines, slip_id, real_id, *, now,
    intended=None) -> dict; append-only booking-slip repair: a done
    line superseding the slip (superseded-duplicate, pointing at the
    real open ticket) plus the intended record under its own id."""
    if not isinstance(store_lines, (list, tuple)):
        raise ValueError("store lines must be a list of parsed lines")
    _check_ticket_id(slip_id, "slip id")
    _check_ticket_id(real_id, "real ticket id")
    if slip_id == real_id:
        raise ValueError(
            "the slip and the already-open ticket must be different "
            "ids (got %s for both)" % (slip_id,))
    state = ticket_state(store_lines)
    if slip_id not in state["open"]:
        raise ValueError(
            "slip %s is not an open ticket (its latest line is %s)" % (
                slip_id,
                state["closed"][slip_id]["status"]
                if slip_id in state["closed"] else "absent"))
    if real_id not in state["open"]:
        raise ValueError(
            "the already-open ticket %s was not found among the open "
            "tickets" % (real_id,))
    slip_line = state["open"][slip_id]
    appends: List[Dict[str, Any]] = [{
        "id": slip_id,
        "ts": iso_utc(now),
        "kind": slip_line["kind"],
        "target": slip_line["target"],
        "status": STATUS_DONE,
        "ended": iso_utc(now),
        "details": {
            "outcome": "superseded-duplicate: re-append for target %s "
                       "already open as %s" % (slip_line["target"],
                                               real_id),
            "superseded_by": real_id,
        },
    }]
    if intended is not None:
        validate_line(intended)
        if intended["status"] != STATUS_RUNNING:
            raise ValueError(
                "the intended line must be a running (open) line, got "
                "status %r" % (intended["status"],))
        if intended["target"] in state["open_targets"]:
            raise ValueError(
                "the intended ticket target %r is already open as %s - "
                "appending it would create the next slip" % (
                    intended["target"], state["open_targets"].get(
                        intended["target"])))
        appends.append(intended)
    for line in appends:
        validate_line(line)
    return {
        "appends": appends,
        "notes": [
            "append-only repair: the slip's done line closes it without "
            "rewriting or deleting anything",
            "verify through the reader (tasks_list) after the wiring "
            "append - invisible means schema problem",
        ],
    }
