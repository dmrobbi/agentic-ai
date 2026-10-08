"""Report email bridge (KA-077): engagement reports and battery
completions compose into outbound EMAIL PLANNING for the reports@
mailbox (OPT-77: engagement reports via the reports@bedimsecurity.com
plumbing; owner-notified on battery completion).

DRY-SEND DEFAULT - the draft-only rule: every compose op returns the
composed email DICT stamped send_mode "dry". The module composes and
validates; it never sends: no transport binding, no mailbox contacts,
no network facilities of any kind (source-scanned pins in the tests).
send_report_mail exists ONLY as a contract stub documented for the
owner-gated wiring - an agent that must not publish carries no
network-write path, so binding the real transport and the mailbox
secret stays in owner-approved code, never here.

MAILBOX ENV PATTERN (the reports@ loader shape the SOC agents use):
the env VAR is named REPORTS_MAILBOX_ENV (see MAILBOX_ENV_VAR) and
selects the env FILE path in owner-gated wiring; this planner reads no
environment - wiring resolves the variable and hands the file path
(read_mailbox_env) or already-parsed entries (parse_mailbox_env) over.
FILE CONTENT - the mailbox env-file convention (credvault carries the
identical rules): KEY=VALUE lines, # comment lines, blank lines, and
lines without = are skipped; the first = splits; both sides trimmed;
identical duplicate keys collapse, conflicting duplicates are
malformed. REQUIRED FIELDS: SMTP_HOST, SMTP_PORT, IMAP_HOST,
IMAP_PORT, REPORTS_MAILBOX, REPORTS_MAILBOX_PW. OPTIONAL:
WAZUH_REPORTS_RECIPIENT (the default owner recipient).

VALUES DISCIPLINE: plans and composed dicts carry credential
REFERENCES, never values - the mailbox secret reduces to its
CREDENTIAL_REF token (@mailbox-env:REPORTS_MAILBOX_PW@); redact() is
the safety net proving returned surfaces never embed a supplied
secret (the tests needle-scan every payload).

OPS - dicts in, dicts out, every op docstringed (first line = the CLI
card detail):
  parse_mailbox_env(text)    env-file content -> entries (raises on
                             malformed lines: line numbers + key names
                             only, never the raw line)
  read_mailbox_env(path)     THE single file-read seam - values
                             surface only here; missing/unreadable/
                             malformed content land as deterministic
                             plain-dict errors, never an exception
                             at the seam
  mailbox_plan(entries)      values-free validated mailbox plan
  compose_report_mail(...)   engagement report record -> composed
                             email dict (findings -> body lines)
  compose_battery_mail(...)  battery-completion record -> the owner
                             notification composed email dict
  send_report_mail(...)      owner-gated send seam (contract stub) -
                             validates the composed shape, then
                             raises by design
  redact(payload, needles)   secret-occurrence scrub net

INPUT GATES (one helper per concern; every external string passes
through one of them):
  scrub_target               engagement targets (the shared gate,
                             wp_scrub_target pattern)
  scrub_address              envelope fields: recipient + mailbox
                             values (header-injection armor)
  scrub_text                 free text (title/summary/notes): control
                             characters rejected, CRLF normalized,
                             ends stripped, length-capped
Engagement-level and battery-level malformation (non-dict record,
missing keys, malformed ids, count/recipient problems) raises
ValueError naming the offender - caller errors, not skip-route
material. Per-finding malformation never crashes the flow: it lands
in "skipped" with reasons (the soc_bridge pattern).

PLANNER PURITY: no process spawning, no network facilities, exactly
one file-read seam (the caller-supplied path), no wall clock (stamps
stay with the callers), no chassis import (plain-module bridge, the
kev_bridge/soc_bridge shape; the host boundary belongs to whatever
chassis composes the bridges).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# --- contract constants (the drift alarm; the tests pin them) ------------

ID_RE = r"[A-Za-z0-9_.\-]{1,64}"

SEND_MODE_DRY = "dry"
KIND_ENGAGEMENT = "engagement_report"
KIND_BATTERY = "battery_completion"
COMPOSED_KINDS = (KIND_ENGAGEMENT, KIND_BATTERY)
TRANSPORT_NONE = None  # a planner binds no transport; the field stays

# the reports@ mailbox env-file contract (the SOC agents' loader shape)
MAILBOX_ENV_VAR = "REPORTS_MAILBOX_ENV"
MAILBOX_ENV_DEFAULT = "/etc/agentic-soc/soc-mailbox.env"
REQUIRED_FIELDS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "IMAP_HOST",
    "IMAP_PORT",
    "REPORTS_MAILBOX",
    "REPORTS_MAILBOX_PW",
)
RECIPIENT_FIELD = "WAZUH_REPORTS_RECIPIENT"
DEFAULT_MAILBOX = "reports@bedimsecurity.com"

# length caps: subject lines stay header-safe, body text is capped
# against oversize payloads
SUBJECT_CAP = 240
BODY_CAP = 200_000
ADDRESS_CAP = 254

# credentials stay references (the credvault shape): the plan and the
# composed dict carry the token, never the value behind it
CREDENTIAL_REF = "@mailbox-env:REPORTS_MAILBOX_PW@"

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_HINT = "critical|high|medium|low"
MISSING_ID = "<missing-id>"
NO_SUMMARY = "(no summary)"

REDACTED = "<redacted>"
ERROR_KIND = "mailbox_env_error"
REASON_NOT_FOUND = "not_found"
REASON_UNREADABLE = "unreadable"
REASON_MALFORMED = "malformed"
REASON_NOT_DICT = "record must be a dict"
REASON_ID_MISSING = "finding id missing"
REASON_ID_MALFORMED = "finding id malformed: %r"
REASON_SEVERITY = (
    "severity must be one of critical|high|medium|low, got: %r")
REASON_TEXT = "%s must be a string, got: %r"


class MailboxEnvError(ValueError):
    """Env-file content violates the mailbox env-file convention.

    Messages carry line numbers and key names only - never raw line or
    value content - so a malformed value cannot leak through an error
    path.
    """


# --- input gates (one helper per concern) ---------------------------------


def _has_controls(value: str) -> bool:
    """Any C0 control, DEL, or C1 codepoint present."""
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            return True
    return False


def scrub_header(value: Any, slot: str, cap: int = SUBJECT_CAP) -> str:
    """A single-line header-field string: one non-blank line, no
    control characters (newlines included - header-injection armor),
    length-capped."""
    if not isinstance(value, str):
        raise ValueError(REASON_TEXT % (slot, value))
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(
            "%s must be a non-blank string, got: %r" % (slot, value))
    if _has_controls(cleaned):
        raise ValueError(
            "%s must be a single line without control characters, "
            "got: %r" % (slot, value))
    if len(cleaned) > cap:
        raise ValueError(
            "%s oversize: %d > %d chars" % (slot, len(cleaned), cap))
    return cleaned


def scrub_text(value: Any, slot: str, cap: int = BODY_CAP) -> str:
    """Free text for body lines: CRLF normalized to newlines, control
    characters rejected (tab and newline stay), ends stripped,
    length-capped."""
    if not isinstance(value, str):
        raise ValueError(REASON_TEXT % (slot, value))
    cleaned = value.strip()
    normalized = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    for ch in normalized:
        code = ord(ch)
        if ((code < 0x20 and ch not in "\t\n") or code == 0x7F
                or 0x80 <= code <= 0x9F):
            raise ValueError(
                "%s must be clean text without control characters, "
                "got: %r" % (slot, value))
    if len(normalized) > cap:
        raise ValueError(
            "%s oversize: %d > %d chars" % (slot, len(normalized), cap))
    return normalized


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


_ADDRESS_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")


def scrub_address(value: Any, slot: str = "address") -> str:
    """A bare mailbox address for envelope fields: exactly one @-split,
    no display names, no whitespace or control characters
    (header-injection armor), length-capped."""
    if not isinstance(value, str):
        raise ValueError(REASON_TEXT % (slot, value))
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(
            "%s must be a non-blank string, got: %r" % (slot, value))
    if _has_controls(cleaned) or re.search(r"\s", cleaned):
        raise ValueError(
            "%s must be a single bare address without whitespace or "
            "control characters, got: %r" % (slot, value))
    if len(cleaned) > ADDRESS_CAP:
        raise ValueError(
            "%s oversize over %d chars, got: %r"
            % (slot, ADDRESS_CAP, value))
    if not _ADDRESS_RE.fullmatch(cleaned):
        raise ValueError(
            "%s must be a bare address (local@dotted-host), got: %r"
            % (slot, value))
    return cleaned


# --- shared small validators ----------------------------------------------


def _free_text(value: Any, slot: str, cap: int = BODY_CAP) -> Optional[str]:
    """absent/None -> None; blank -> None; else scrubbed text."""
    if value is None:
        return None
    cleaned = scrub_text(value, slot, cap)
    return cleaned if cleaned.strip() else None


def _require_id(value: Any, slot: str) -> str:
    """A non-blank ID_RE string; the error names slot + value."""
    if not isinstance(value, str) or not re.fullmatch(ID_RE, value):
        raise ValueError(
            "%s malformed: %r (wanted pattern %s)" % (slot, value, ID_RE))
    return value


def _count(value: Any, slot: str) -> int:
    """A non-negative int count (bool refused: True is not a count)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            "%s must be a non-negative int, got: %r" % (slot, value))
    if value < 0:
        raise ValueError(
            "%s must be a non-negative int, got: %r" % (slot, value))
    return value


def _port(value: Any, slot: str) -> int:
    """A TCP port: int, or a digit string; range 1..65535."""
    if isinstance(value, bool):
        raise ValueError(
            "%s must be a port number 1-65535, got: %r" % (slot, value))
    if isinstance(value, int):
        candidate = value
    elif isinstance(value, str) and value.strip().isdigit():
        candidate = int(value.strip())
    else:
        raise ValueError(
            "%s must be a port number 1-65535, got: %r" % (slot, value))
    if not (1 <= candidate <= 65535):
        raise ValueError(
            "%s must be a port number 1-65535, got: %r" % (slot, value))
    return candidate


def _host(value: Any, slot: str) -> str:
    """A mailbox host field: one line, no controls, no interior
    whitespace, DNS-length-capped."""
    cleaned = scrub_header(value, slot, cap=255)
    if re.search(r"\s", cleaned):
        raise ValueError(
            "%s must be a bare host name, got: %r" % (slot, value))
    return cleaned


def _severity(value: Any) -> Optional[str]:
    """The severity field normalized to lowercase, or None when
    non-conforming (call sites carry the message)."""
    if isinstance(value, str) and value.strip().lower() in SEVERITIES:
        return value.strip().lower()
    return None


def _blank(value: Any) -> bool:
    """absent/None or a whitespace-only string."""
    return value is None or (isinstance(value, str) and not value.strip())


# --- mailbox env-file pattern ---------------------------------------------


def parse_mailbox_env(text: Any) -> Dict[str, str]:
    """Pure parse of mailbox env-file CONTENT (the mailbox env-file
    convention): # comments, blank lines, and lines without = are
    skipped; the first = splits; both sides trimmed; identical
    duplicates collapse, conflicting duplicates or an empty key are
    malformed (line number + key named, never the raw line)."""
    if not isinstance(text, str):
        raise TypeError("parse_mailbox_env expects env-file content text")
    entries: Dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise MailboxEnvError(
                "malformed mailbox env file: empty key at line %d"
                % lineno)
        if key in entries and entries[key] != value:
            raise MailboxEnvError(
                "malformed mailbox env file: conflicting duplicate "
                "entry for key %r at line %d" % (key, lineno))
        entries[key] = value
    return entries


def _env_error(reason: str, detail: str) -> Dict[str, Any]:
    """The values-free seam error dict shape."""
    return {
        "ok": False,
        "error": {"kind": ERROR_KIND, "reason": reason, "detail": detail},
    }


def read_mailbox_env(env_path: Any) -> Dict[str, Any]:
    """THE single file-read seam: reads the PATH PASSED IN BY THE
    CALLER through the mailbox env-file convention. Never raises at
    the seam: a missing file, an unreadable path, and malformed
    content become a deterministic values-free error dict on "error"
    ("ok": False); success carries the parsed entries on "entries"
    ("ok": True) - entry VALUES surface only at this seam and the
    caller must bind them nowhere except its own exec-time binding."""
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return _env_error(REASON_NOT_FOUND, "mailbox env file not found")
    except (OSError, ValueError, TypeError) as exc:
        return _env_error(
            REASON_UNREADABLE,
            "mailbox env file unreadable: " + exc.__class__.__name__,
        )
    try:
        entries = parse_mailbox_env(text)
    except MailboxEnvError as exc:
        return _env_error(REASON_MALFORMED, str(exc))
    return {"ok": True, "entries": entries}


def _credential(entries: Dict[str, Any]) -> str:
    """Presence gate on the mailbox secret field; returns the FIXED
    reference token - the value behind it never leaves the envelope
    the caller holds."""
    value = entries.get("REPORTS_MAILBOX_PW")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "REPORTS_MAILBOX_PW must be a non-blank string, got: %r"
            % (value,))
    return CREDENTIAL_REF


def mailbox_plan(entries: Any) -> Dict[str, Any]:
    """The VALUES-FREE validated mailbox plan: routing fields only,
    the mailbox secret reduced to its CREDENTIAL_REF reference token -
    safe for records, tests, and wiring handoff. Raises ValueError
    naming the first offending field (the env file is owner
    configuration; loud beats silent)."""
    if not isinstance(entries, dict):
        raise ValueError(
            "entries must be a dict of env-file fields, got: %r"
            % (entries,))
    missing = [field for field in REQUIRED_FIELDS if field not in entries]
    if missing:
        raise ValueError(
            "mailbox env missing required fields: %s" % (missing,))
    recipient_raw = entries.get(RECIPIENT_FIELD)
    return {
        "ok": True,
        "smtp_host": _host(entries["SMTP_HOST"], "SMTP_HOST"),
        "smtp_port": _port(entries["SMTP_PORT"], "SMTP_PORT"),
        "imap_host": _host(entries["IMAP_HOST"], "IMAP_HOST"),
        "imap_port": _port(entries["IMAP_PORT"], "IMAP_PORT"),
        "mailbox": scrub_address(
            entries["REPORTS_MAILBOX"], "REPORTS_MAILBOX"),
        "credential": _credential(entries),
        "default_recipient": (
            None if _blank(recipient_raw)
            else scrub_address(recipient_raw, RECIPIENT_FIELD)),
    }


def _mailbox_arg(mailbox: Any) -> Optional[Dict[str, Any]]:
    """None -> None (compose from the DEFAULT_MAILBOX address); a
    plan-shaped dict re-scrubs its address; an env-file entries dict
    (uppercase field names) runs through mailbox_plan; anything else
    is a caller error."""
    if mailbox is None:
        return None
    if isinstance(mailbox, dict):
        if "smtp_host" in mailbox and "credential" in mailbox:
            if mailbox.get("ok") is not True:
                raise ValueError(
                    "mailbox plan malformed: ok is %r"
                    % (mailbox.get("ok"),))
            plan = dict(mailbox)
            plan["mailbox"] = scrub_address(plan["mailbox"], "mailbox")
            return plan
        if "SMTP_HOST" in mailbox:
            return mailbox_plan(mailbox)
    raise ValueError(
        "mailbox must be None, a mailbox_plan dict, or env-file "
        "entries, got: %r" % (mailbox,))


def _resolve_recipient(
    recipient: Any, plan: Optional[Dict[str, Any]]
) -> str:
    """The owner notification contract: an explicit recipient wins;
    else the plan's default recipient (the env file's WAZUH_REPORTS_
    RECIPIENT field); with neither there is nobody to notify - a
    ValueError, not a silent draft."""
    if recipient is not None:
        return scrub_address(recipient, "recipient")
    if plan is not None and plan["default_recipient"]:
        return plan["default_recipient"]
    raise ValueError(
        "recipient required: the owner notification contract needs a "
        "to: address (explicit recipient or the env file's "
        "WAZUH_REPORTS_RECIPIENT)")


# --- composition -----------------------------------------------------------


def _compose(
    kind: str,
    frm: str,
    to: str,
    subject: str,
    body: str,
    plan: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """The composed-email dict shape (the tests pin it exactly)."""
    return {
        "ok": True,
        "send_mode": SEND_MODE_DRY,
        "kind": kind,
        "transport": TRANSPORT_NONE,
        "envelope": {"from": frm, "to": to, "reply_to": None},
        "subject": subject,
        "body": body,
        "credential": CREDENTIAL_REF,
        "mailbox": plan,
    }


def compose_report_mail(
    report: Any,
    mailbox: Any = None,
    recipient: Any = None,
    send_mode: Any = SEND_MODE_DRY,
) -> Dict[str, Any]:
    """Compose the engagement-report email DICT (dry-send default):
    subject + body + envelope for the reports@ mailbox with one body
    line per finding - nothing is sent here."""
    _require_dry(send_mode)
    if not isinstance(report, dict):
        raise ValueError(
            "report must be a dict record, got: %r" % (report,))
    missing = [
        key for key in ("engagement_id", "target", "findings")
        if key not in report
    ]
    if missing:
        raise ValueError("report missing required keys: %s" % (missing,))
    engagement_id = _require_id(report["engagement_id"], "engagement_id")
    target = scrub_target(report["target"])
    rows = report["findings"]
    if not isinstance(rows, (list, tuple)):
        raise ValueError("findings must be a list, got: %r" % (rows,))
    findings: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            skipped.append(
                {"finding_id": MISSING_ID, "reasons": [REASON_NOT_DICT]})
            continue
        reasons: List[str] = []
        raw_id = row.get("id")
        finding_id = MISSING_ID
        if isinstance(raw_id, str) and re.fullmatch(ID_RE, raw_id):
            finding_id = raw_id
        elif isinstance(raw_id, str) and raw_id.strip():
            reasons.append(REASON_ID_MALFORMED % (raw_id,))
        else:
            reasons.append(REASON_ID_MISSING)
        severity_norm = _severity(row.get("severity"))
        if severity_norm is None:
            reasons.append(REASON_SEVERITY % (row.get("severity"),))
        summary_raw = row.get("summary")
        if summary_raw is not None and not isinstance(summary_raw, str):
            reasons.append(REASON_TEXT % ("summary", summary_raw))
        evidence_raw = row.get("evidence")
        if evidence_raw is not None and not isinstance(evidence_raw, str):
            reasons.append(REASON_TEXT % ("evidence", evidence_raw))
        if reasons:
            skipped.append({"finding_id": finding_id, "reasons": reasons})
            continue
        findings.append({
            "id": finding_id,
            "severity": severity_norm,
            "summary": _free_text(summary_raw, "summary"),
            "evidence": _free_text(evidence_raw, "evidence"),
        })
    title = _free_text(report.get("title"), "title")
    notes = _free_text(report.get("notes"), "notes")
    plan = _mailbox_arg(mailbox)
    frm = plan["mailbox"] if plan else DEFAULT_MAILBOX
    to = _resolve_recipient(recipient, plan)
    # the subject counts COMPOSED findings only
    subject = "Engagement report %s - %d findings (target %s)" % (
        engagement_id, len(findings), target)
    lines = [
        title or "Engagement report " + engagement_id,
        "target: " + target,
        "findings: %d composed, %d skipped"
        % (len(findings), len(skipped)),
    ]
    for row in findings:
        lines.append("- [%s] %s: %s" % (
            row["severity"], row["id"], row["summary"] or NO_SUMMARY))
        if row["evidence"]:
            lines.append("  evidence: " + row["evidence"])
    for skip in skipped:
        lines.append("- skipped finding %s: %s" % (
            skip["finding_id"], "; ".join(skip["reasons"])))
    if notes:
        lines.append("")
        lines.append(notes)
    return _compose(
        KIND_ENGAGEMENT, frm, to, subject, "\n".join(lines), plan)


def compose_battery_mail(
    run: Any,
    mailbox: Any = None,
    recipient: Any = None,
    send_mode: Any = SEND_MODE_DRY,
) -> Dict[str, Any]:
    """Compose the battery-completion OWNER-NOTIFICATION email DICT
    (dry-send default): the battery record folds into subject/body,
    the owner's to: address resolves through the recipient contract -
    nothing is sent here."""
    _require_dry(send_mode)
    if not isinstance(run, dict):
        raise ValueError("run must be a dict record, got: %r" % (run,))
    missing = [
        key for key in ("battery_id", "completed", "failed")
        if key not in run
    ]
    if missing:
        raise ValueError(
            "battery run missing required keys: %s" % (missing,))
    battery_id = _require_id(run["battery_id"], "battery_id")
    completed = _count(run["completed"], "completed")
    failed = _count(run["failed"], "failed")
    skipped = _count(run.get("skipped", 0), "skipped")
    raw_target = run.get("target")
    target = None if _blank(raw_target) else scrub_target(raw_target)
    notes = _free_text(run.get("notes"), "notes")
    plan = _mailbox_arg(mailbox)
    frm = plan["mailbox"] if plan else DEFAULT_MAILBOX
    to = _resolve_recipient(recipient, plan)
    subject = "battery %s complete: %d ok, %d failed, %d skipped" % (
        battery_id, completed, failed, skipped)
    lines = ["battery %s complete" % battery_id]
    if target:
        lines.append("target: " + target)
    lines.append("completed: %d" % completed)
    lines.append("failed: %d" % failed)
    lines.append("skipped: %d" % skipped)
    if notes:
        lines.append("")
        lines.append(notes)
    return _compose(
        KIND_BATTERY, frm, to, subject, "\n".join(lines), plan)


def _require_dry(send_mode: Any) -> None:
    """The draft-only gate: non-dry send_mode values are refused at
    the planner level - delivery belongs to owner-gated wiring."""
    if send_mode != SEND_MODE_DRY:
        raise ValueError(
            "send_mode must be the dry-send default %r, got: %r - "
            "this planner composes drafts only; delivery belongs to "
            "owner-gated wiring" % (SEND_MODE_DRY, send_mode))


def _require_composed(composed: Any) -> None:
    """Shape gate on a dict before the send stub accepts it as one of
    this module's compositions."""
    if not isinstance(composed, dict):
        raise ValueError(
            "composed must be a composed email dict, got: %r"
            % (composed,))
    if composed.get("ok") is not True:
        raise ValueError(
            "not a composed email dict: ok is %r" % (composed.get("ok"),))
    if composed.get("send_mode") != SEND_MODE_DRY:
        raise ValueError(
            "refusing non-dry composition: send_mode is %r (the "
            "dry-send default governs)" % (composed.get("send_mode"),))
    if composed.get("kind") not in COMPOSED_KINDS:
        raise ValueError(
            "unknown composed kind: %r" % (composed.get("kind"),))
    for slot in ("subject", "body"):
        if not isinstance(composed.get(slot), str):
            raise ValueError(
                "composed %s must be a string, got: %r"
                % (slot, composed.get(slot)))
    if not isinstance(composed.get("envelope"), dict):
        raise ValueError(
            "composed envelope must be a dict, got: %r"
            % (composed.get("envelope"),))


NOT_IMPLEMENTED_MSG = (
    "send_report_mail is an owner-gated contract stub: the "
    "report-email planner composes dry-send drafts only and carries "
    "no network-write path (draft-only rule); owner-approved wiring "
    "binds a real transport and the mailbox env at exec time")


def send_report_mail(composed: Any, transport: Any = None) -> str:
    """OWNER-GATED send seam (contract stub) - validates a composed
    dict, then raises by design: the planner carries no
    network-write path."""
    _require_composed(composed)
    # transport is reserved for the owner-gated implementation of this
    # seam (wiring binds it with the mailbox env); the planner stub
    # accepts and ignores it so callers can hold the final shape
    raise NotImplementedError(NOT_IMPLEMENTED_MSG)


def redact(payload: Any, needles: Any) -> Any:
    """The scrub net: replace every occurrence of each needle (a
    supplied secret string, or a list/tuple of them) in the payload's
    string VALUES with REDACTED - keys are untouched; tuple nodes come
    back as lists (JSON-safe). Non-JSON-able nodes raise TypeError;
    empty needles raise ValueError."""
    if isinstance(needles, str):
        needles = (needles,)
    if not isinstance(needles, (list, tuple)):
        raise ValueError(
            "needles must be a non-empty string or a list/tuple of "
            "them, got: %r" % (needles,))
    checked: List[str] = []
    for needle in needles:
        if not isinstance(needle, str) or not needle:
            raise ValueError(
                "needles must be a non-empty string or a list/tuple "
                "of them, got: %r" % (needle,))
        checked.append(needle)

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            text = node
            for needle in checked:
                text = text.replace(needle, REDACTED)
            return text
        if isinstance(node, dict):
            return {key: walk(value) for key, value in node.items()}
        if isinstance(node, (list, tuple)):
            return [walk(value) for value in node]
        if isinstance(node, (int, float, bool)) or node is None:
            return node
        raise TypeError(
            "payload node not JSON-able: %s" % (type(node).__name__,))

    return walk(payload)
