"""Engagement budget/quota planner (KA-062): a pure admission gate.

A pure planner module (standalone, in the consent_gate/auth_expiry
shape: no chassis import, no process spawning, no network facilities,
no wall-clock reads - the clock `now` is INJECTED and the consumption
ledger (enforcement state) is INJECTED as the module's own audit-event
dicts: what is audited is what is enforced, one source of truth).

BUDGET UNITS (the three per-engagement fields of one Budget):
- max_command_invocations - cap on command invocations for the
  engagement ("command invocations"). None means uncapped.
- max_external_requests - cap on outbound external requests for the
  engagement ("external-request caps"). None means uncapped.
- window_seconds - the consumption-accounting window: a consumption
  stamped T counts against the caps for a decision at `now` iff
  (now - T).total_seconds() < window_seconds (house sliding-window
  boundary, KA-054: strictly less, continuous slide, no scheduled
  reset - capacity frees exactly when individual consumptions age out).
  window_seconds=None makes BOTH caps lifetime caps: every recorded
  consumption for the engagement counts at any age, and the caller must
  therefore never drop ledger entries (dropped units are invisible to
  later gates). Under windowed accounting, entries older than the
  window may be dropped safely - they can no longer count.

THE HOUSE GATE SHAPE:
- check_budget(ledger, budget, kind, now) returns a (bool, reason)
  tuple and nothing else. Asserting any other shape (a dict, a raise,
  a third element) is the test's bug, not this module's (consent_gate
  precedent, KA-060).

DECISION PRECEDENCE (pinned; first match wins):
  1. kind not one of the exact KINDS strings (no normalization, no
     case-folding)              -> budget_kind_invalid (deny)
  2. budget not well-formed     -> budget_malformed (deny; malformed
     budgets are never echoed into events)
  3. ledger corruption during the count -> RAISES (see below); the
     gate never returns a reason tuple for untrusted state
  4. the kind's cap is None     -> budget_ok (allow; the budget still
     meters - allowed consumptions always emit the pinned event)
  5. used >= cap (including cap 0, which blocks even a fresh ledger)
     -> the unit-naming cap-reached deny code
  6. otherwise                  -> budget_ok (allow)

EXHAUSTION (nothing invented):
- A cap-reached admission is DENIED with a stable unit-naming reason
  code and NOTHING is consumed: a blocked attempt appends no ledger
  entry, so hammering a full budget never extends it (rate_limit
  precedent). The two caps are independent counters: exhausting
  commands never blocks external requests and vice versa.

REQUEST-SIDE vs STATE-SIDE (the consent/rate_limit split, pinned):
- Request garbage DENIES with the stable codes above - the gate is
  total over its request arguments.
- State corruption raises loudly: a non-dict ledger entry, or an entry
  of this module's event kind with malformed internals (bad
  engagement_id/kind/window_seconds, unparseable or non-string `at`)
  raises ValueError naming the ledger index (TypeError for a non-string
  `at`), rather than reading as unused quota. Entries that are dicts
  of a DIFFERENT event kind are foreign audit material and are skipped
  without validation.

CONSUMPTION EVENTS (the pinned, JSON-serializable dict shape):
  {"event": EVENT_KIND, "engagement_id": ..., "kind": ...,
   "window_seconds": float-or-None, "at": iso8601}
Keys appear in exactly that order (pinned). consumption_event builds
one; the CALLER appends it to the ledger after an ALLOWED admission
(the gate is a pure read: it never mutates the injected ledger, so a
denied engagement may be re-checked arbitrarily without drift). The
counting window for a decision is the BUDGET's window_seconds at
decision time; a stored per-entry window_seconds is provenance only -
budget definitions may be retightened/rewidened freely.

Datetime tz-ness is the CALLER's contract: stamps pass through
untouched; with a window in force, a naive/aware mix between `now` and
a parsed stamp propagates the TypeError (pinned). Under lifetime
accounting nothing is subtracted, so mixed tz-ness is tolerated there
by design.

Chassis wiring (consulting this gate in the execution path's gate
order, and attaching the ledger to engagement state) is an integration
decision; this module carries the semantics only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Tuple

EVENT_KIND = "engagement_budget_consumed"

# The two measurable units, as exact kind strings (no normalization).
KIND_COMMAND_INVOCATION = "command_invocation"
KIND_EXTERNAL_REQUEST = "external_request"
KINDS = (KIND_COMMAND_INVOCATION, KIND_EXTERNAL_REQUEST)

# Stable reason codes. The tests pin them literally, so any rename is a
# loud drift alarm, not a silent one.
REASON_OK = "budget_ok"
REASON_BUDGET_MALFORMED = "budget_malformed"
REASON_KIND_INVALID = "budget_kind_invalid"
REASON_COMMANDS_EXHAUSTED = "command_invocation_cap_reached"
REASON_EXTERNALS_EXHAUSTED = "external_request_cap_reached"


@dataclass(frozen=True)
class Budget:
    """One engagement's budget in the three documented units.

    Caps of None are uncapped; a cap of 0 is a meaningful total block
    for that unit. window_seconds=None selects lifetime accounting for
    both caps, otherwise both caps are enforced over the rolling
    window. Frozen: an audited budget must never be repairable in
    place (house precedent: ConsentRecord).
    """

    engagement_id: str
    max_command_invocations: Optional[int] = None
    max_external_requests: Optional[int] = None
    window_seconds: Optional[float] = None


def _budget_well_formed(budget: Any) -> bool:
    """Type-level Budget sanity: a real Budget with a non-blank id,
    int-or-None (>= 0, bools rejected) caps, and a positive-or-None
    numeric window (bools rejected). Cap 0 is deliberately well-formed.
    """
    if not isinstance(budget, Budget):
        return False
    if not (isinstance(budget.engagement_id, str)
            and bool(budget.engagement_id.strip())):
        return False
    for cap in (budget.max_command_invocations, budget.max_external_requests):
        if cap is None:
            continue
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
            return False
    window = budget.window_seconds
    if window is not None:
        if (isinstance(window, bool)
                or not isinstance(window, (int, float))
                or not window > 0):
            return False
    return True


def _validated_entry(entry: Dict[str, Any], index: int) -> Tuple[str, str, datetime]:
    """Validate one ledger entry known to be of this module's event
    kind and return (engagement_id, kind, stamp); ValueError/TypeError
    name the ledger index. The stamp round-trips the house isoformat
    parse; tz-ness passes through untouched (caller's contract)."""
    engagement_id = entry.get("engagement_id")
    if not isinstance(engagement_id, str):
        raise ValueError(
            "budget ledger entry #%d has a non-string engagement_id: %r"
            % (index, engagement_id))
    entry_kind = entry.get("kind")
    if not (isinstance(entry_kind, str) and entry_kind in KINDS):
        raise ValueError(
            "budget ledger entry #%d has an unknown kind: %r"
            % (index, entry_kind))
    stored_window = entry.get("window_seconds")
    if not (stored_window is None
            or (not isinstance(stored_window, bool)
                and isinstance(stored_window, (int, float))
                and stored_window > 0)):
        raise ValueError(
            "budget ledger entry #%d has malformed window_seconds: %r"
            % (index, stored_window))
    stamp_value = entry.get("at")
    if not isinstance(stamp_value, str):
        raise TypeError(
            "budget ledger entry #%d: 'at' must be an iso8601 string, got %r"
            % (index, stamp_value))
    stamp = datetime.fromisoformat(stamp_value)  # ValueError if unparsable
    return engagement_id, entry_kind, stamp


def _counted_usage(
    ledger: Iterable[Any],
    budget: Budget,
    kind: str,
    now: datetime,
) -> int:
    """Count prior consumptions the decision must pay for: entries of
    this module's event kind for THIS engagement and kind, inside the
    budget's window when one is in force (strictly-less boundary), all
    of them when window_seconds is None. Foreign event kinds or other
    engagements are skipped; corruption in THIS module's entries is a
    loud ValueError/TypeError with the ledger index."""
    window = budget.window_seconds
    count = 0
    for index, entry in enumerate(ledger):
        if not isinstance(entry, dict):
            raise ValueError(
                "budget ledger entry #%d is not a dict: %r"
                % (index, entry))
        if entry.get("event") != EVENT_KIND:
            continue  # foreign audit material in a shared stream
        engagement_id, entry_kind, stamp = _validated_entry(entry, index)
        if engagement_id != budget.engagement_id or entry_kind != kind:
            continue
        if window is None or (now - stamp).total_seconds() < window:
            count += 1
    return count


def check_budget(
    ledger: Iterable[Any],
    budget: Any,
    kind: Any,
    now: datetime,
) -> Tuple[bool, str]:
    """Gate one admission against an engagement's remaining quota.

    Pure planner: state is the injected `ledger` (prior consumption
    events, read once, never mutated), the clock is the injected
    `now`; returns the house (bool, reason) tuple and nothing else."""
    if not (isinstance(kind, str) and kind in KINDS):
        return False, REASON_KIND_INVALID
    if not _budget_well_formed(budget):
        return False, REASON_BUDGET_MALFORMED
    used = _counted_usage(ledger, budget, kind, now)
    cap = (budget.max_command_invocations
           if kind == KIND_COMMAND_INVOCATION
           else budget.max_external_requests)
    if cap is None:
        return True, REASON_OK
    if used >= cap:
        return False, (REASON_COMMANDS_EXHAUSTED
                       if kind == KIND_COMMAND_INVOCATION
                       else REASON_EXTERNALS_EXHAUSTED)
    return True, REASON_OK


def consumption_event(
    budget: Budget,
    kind: str,
    now: datetime,
) -> Dict[str, Any]:
    """The deterministic consumption event for one admitted unit.

    The caller appends the returned dict to its ledger after an
    ALLOWED check_budget; malformed budget/kind raise ValueError (this
    is a construction call, not a gate - a malformed event must never
    enter the enforcement state)."""
    if not _budget_well_formed(budget):
        raise ValueError(
            "consumption_event needs a well-formed Budget, got %r" % (budget,))
    if not (isinstance(kind, str) and kind in KINDS):
        raise ValueError(
            "consumption_event kind must be one of %r, got %r"
            % (KINDS, kind))
    window = budget.window_seconds
    return {
        "event": EVENT_KIND,
        "engagement_id": budget.engagement_id,
        "kind": kind,
        "window_seconds": (None if window is None else float(window)),
        "at": now.isoformat(),
    }