"""Execution consent gate (KA-060): owner consent for real-effect runs.

A pure planner module (standalone, in the auth_expiry shape: no chassis
import, no process spawning, no network facilities, no wall-clock reads
- the clock `now` is INJECTED; naive/aware datetime mixes propagate the
caller's TypeError exactly as pinned in KA-052).

THE HOUSE GATE SHAPE:
- consent_gate(action, dry_run, consent, now) returns a (bool, reason)
  tuple and nothing else. Asserting any other shape (a dict, a raise,
  a third element) is the test's bug, not this module's.

CONSENT DISCIPLINE (generalizes the removed kali_agent_v4 generation's
evidence discipline - read-only inspiration, nothing imported; that
line's record lives at git history c965747):
- A non-dry-run execution (real effects: live scans, exploit steps,
  anything touching a target system) REQUIRES an owner-signed consent
  RECORD: a structured ConsentRecord carrying engagement_id, action,
  signed_by, signed_at, and an optional expires_at.
- dry_run=True passes WITHOUT consent by design: planning and
  inspection are unrestricted (house precedent: role_can_dry_run).
- "Owner-signed" at planner level means a present signer: signed_by
  must be a non-blank string. An unsigned record is not consent.
- Action scoping is an EXACT string match (consent.action == action;
  no normalization, no case-folding, no prefix matching). Engagement
  scoping is wiring's concern - the record's engagement_id is carried
  and audited, not matched here (the gate signature has no engagement
  argument).
- EXPIRY reuses the auth-expiry convention (KA-052/KA-015, "at and
  after"): a consent with expires_at set is EXPIRED once
  now >= expires_at; expires_at=None never expires.

REFUSAL AUDIT:
- consent_refusal_event(action, dry_run, consent, now) re-runs the gate
  and returns the deterministic audit-event dict for a refusal (event
  kind + stable reason + the record's JSON-safe echoes), or exactly
  None when the gate allows the run - refusal and tuple stay
  consistent by construction because both derive from one decision.
  Malformed consent objects are never echoed (only their refusal
  reason is), keeping every event JSON-serializable.

DECISION PRECEDENCE (pinned; first match wins):
  1. action not a non-blank string   -> action_invalid (deny; applies
     even to dry runs)
  2. truthy dry_run (consent entirely ignored) ->
     dry_run_no_consent_required (allow)
  3. consent is None                 -> consent_missing (deny)
  4. consent not a well-formed record -> consent_malformed (deny:
     wrong record type, blank engagement_id/action, non-datetime
     provenance stamps, non-string garbage signer)
  5. signed_by absent (None) or blank -> consent_unsigned (deny)
  6. consent.action != action        -> consent_action_mismatch (deny)
  7. expired (now >= expires_at)     -> consent_expired (deny)
  8. otherwise                       -> consent_valid (allow)

Chassis wiring (consulting this gate ahead of authorization on the
execution path - see rate_limit's KA-INT-4 gate order "consent -> auth
-> blast-radius") is an INTEGRATION decision; this module carries the
semantics only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

EVENT_KIND = "execution_consent_refused"

# Stable reason codes. The tests pin them literally, so any rename is a
# loud drift alarm, not a silent one.
REASON_ACTION_INVALID = "action_invalid"
REASON_DRY_RUN = "dry_run_no_consent_required"
REASON_MISSING = "consent_missing"
REASON_MALFORMED = "consent_malformed"
REASON_UNSIGNED = "consent_unsigned"
REASON_ACTION_MISMATCH = "consent_action_mismatch"
REASON_EXPIRED = "consent_expired"
REASON_VALID = "consent_valid"


@dataclass(frozen=True)
class ConsentRecord:
    """One owner-signed execution consent for exactly one action.

    Required provenance: signed_by and signed_at (who consented and
    when). expires_at is optional; when set, the KA-015 "at and after"
    boundary applies (now >= expires_at means consent is EXPIRED). The
    record is frozen: an audited refusal must never be repairable in
    place.
    """

    engagement_id: str
    action: str
    signed_by: str
    signed_at: datetime
    expires_at: Optional[datetime] = None


def _action_well_formed(action: Any) -> bool:
    """Caller contract for the requested action: a non-blank string."""
    return isinstance(action, str) and bool(action.strip())


def _record_well_formed(consent: Any) -> bool:
    """Type-level record sanity.

    A None signed_by is deliberately allowed through here: absent or
    blank signer is the separate unsigned refusal, not object-level
    malformation. Any other type garbage in signed_by is malformation.
    """
    if not isinstance(consent, ConsentRecord):
        return False
    if not (isinstance(consent.engagement_id, str)
            and bool(consent.engagement_id.strip())):
        return False
    if not (isinstance(consent.action, str)
            and bool(consent.action.strip())):
        return False
    if not isinstance(consent.signed_at, datetime):
        return False
    if consent.expires_at is not None and not isinstance(
            consent.expires_at, datetime):
        return False
    if not (consent.signed_by is None or isinstance(consent.signed_by, str)):
        return False
    return True


def consent_gate(
    action: Any,
    dry_run: bool,
    consent: Optional[ConsentRecord],
    now: datetime,
) -> Tuple[bool, str]:
    """consent_gate(action, dry_run, consent, now) -> (bool, reason);
    non-dry-run executions demand an owner-signed consent record."""
    if not _action_well_formed(action):
        return False, REASON_ACTION_INVALID
    if dry_run:
        # By design: planning/inspection is unrestricted; the gate never
        # consults (or cares about) consent state for a dry run.
        return True, REASON_DRY_RUN
    if consent is None:
        return False, REASON_MISSING
    if not _record_well_formed(consent):
        return False, REASON_MALFORMED
    signed_by = consent.signed_by
    if signed_by is None or not signed_by.strip():
        return False, REASON_UNSIGNED
    if consent.action != action:
        return False, REASON_ACTION_MISMATCH
    expires_at = consent.expires_at
    if expires_at is not None and now >= expires_at:
        # auth-expiry convention (KA-052/KA-015): refused AT and AFTER
        # the boundary, not only strictly after it.
        return False, REASON_EXPIRED
    return True, REASON_VALID


def consent_refusal_event(
    action: Any,
    dry_run: bool,
    consent: Optional[ConsentRecord],
    now: datetime,
) -> Optional[Dict[str, Any]]:
    """The gate's refusal, audited: the deterministic JSON-serializable
    audit-event dict for a refused run; None when the gate allows it."""
    allowed, reason = consent_gate(action, dry_run, consent, now)
    if allowed:
        return None
    engagement_id: Optional[str] = None
    signed_by: Optional[str] = None
    signed_at: Optional[str] = None
    expires_at: Optional[str] = None
    if _record_well_formed(consent):
        engagement_id = consent.engagement_id
        signed_by = consent.signed_by
        signed_at = consent.signed_at.isoformat()
        if consent.expires_at is not None:
            expires_at = consent.expires_at.isoformat()
    return {
        "event": EVENT_KIND,
        "action": action if isinstance(action, str) else repr(action),
        "dry_run": bool(dry_run),
        "engagement_id": engagement_id,
        "signed_by": signed_by,
        "signed_at": signed_at,
        "expires_at": expires_at,
        "reason": reason,
        "checked_at": (
            now.isoformat() if isinstance(now, datetime) else None),
    }
