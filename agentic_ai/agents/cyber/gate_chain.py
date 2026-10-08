"""Composed P4 safety-gate chain (KA-INT-4): the execution-authorization
policy surface for the kali chassis.

Pinned gate ORDER (the phase-4 acceptance contract - reordering is a bug):

  1. consent        (KA-060): non-dry-run executions demand an
     owner-signed ConsentRecord; dry-run passes free by design (the
     documented carve-out, pinned even with an expired record on file).
  2. budget         (KA-062, OPTIONAL): consulted only when the caller
     supplies `budget` (+ `ledger`); not part of the mandatory chain.
     Runs between consent and auth on the REAL path: paperwork before
     quota, quota before authorization.
  3. auth           (KA-015): role-vs-level authorization. The check is
     INJECTED (`auth_check(tool_name, role, required_level) ->
     (bool, reason)`); the default consults the engagement RBAC
     `authorize_call` with `required_level=tool_level`. The chassis
     supplies its own level-based checker (engagement_authorizations
     math). `role=None` with the default check denies fail-closed.
  4. blast-radius   (KA-053): static classification of the command.
     The mapping may only ESCALATE: a `required_level` above the tool's
     authorized level denies (escalation breach);
     `staging_required=True` demands lab staging in the egress step.
  5. egress         (KA-055): RFC1918 targets require lab staging;
     external and unset targets require EGRESS-AUTH in auth_tags;
     localhost passes free. Lab staging is established via the
     caller's `lab_staged` claim or an injected `staging_probe` the
     caller builds over staging_gate when a declaration exists.
     Skipped ENTIRELY on dry runs (nothing leaves the machine).
  6. rate-limit     (KA-054): sliding-window cap per (tool, target) on
     the INJECTED store, with the injected `now`. Real executions
     require a store and a target (fail-closed); dry runs skip the
     gate entirely (nothing consumed).
  7. execute        : the TERMINAL state is the authorization TO
     execute. The chain never executes anything - the caller owns
     execution (planner purity) - and receives the collectable
     audit-event bundle in gate order.

Dry runs deviate from the mandatory chain by design (KA-051: planning /
inspection is unrestricted for every role): consent still runs (the
carve-out lives inside it - a malformed action still refuses), the
blast-radius classification is recorded for the audit trail, and every
effect gate (budget / auth / egress / rate-limit) is skipped.

Fail-closed: the FIRST refusal stops the chain (later gates and their
side effects uninvolved), reports a `stopped_at` gate name plus the
precise reason, and carries the events gathered so far. Structural
misuse (bad tool_level, non-datetime now, non-callable checks) raises
ValueError so wiring mistakes are loud, not silent denials.

Planner purity: imports are the pure planner siblings only; no chassis
import, no wall-time reads (`now` is injected and required), no file or
network I/O; source-scanned in tests.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from agentic_ai.agents.cyber.blast_radius import audit_event as br_audit_event
from agentic_ai.agents.cyber.blast_radius import classify as br_classify
from agentic_ai.agents.cyber.budgets import check_budget
from agentic_ai.agents.cyber.consent_gate import (
    ConsentRecord,
    consent_gate,
    consent_refusal_event,
)
from agentic_ai.agents.cyber.engagement_rbac import authorize_call
from agentic_ai.agents.cyber.egress_guard import AUTH_TAG, egress_gate
from agentic_ai.agents.cyber.rate_limit import check as rate_check

GATE_NAMES = ("consent", "budget", "auth", "blast_radius", "egress",
              "rate_limit", "execute")
EVENT_BUDGET_REFUSED = "gate_chain_budget_refused"

_AUTH_CHECK = Callable[[str, Any, int], Tuple[bool, str]]


@dataclass(frozen=True)
class GateChainDecision:
    """Terminal decision of one gate-chain run.

    `stopped_at` names the deciding gate (or "execute" when the chain
    passed). `events` preserves gate order; refusals carry the refusing
    gate's audit event.
    """

    allowed: bool
    reason: str
    stopped_at: str
    level: int
    events: Tuple[Dict[str, Any], ...]


def _norm_level(value: Any) -> int:
    """Accept int or a duck-typed enum (.value int); 0..3 else ValueError."""
    level = getattr(value, "value", value)
    if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 3:
        raise ValueError(
            "gate_chain: tool_level must be an int in 0..3, got %r" % (value,))
    return level


def _default_auth_check(
    tool_name: str,
    role: Any,
    required_level: int,
) -> Tuple[bool, str]:
    if role is None:
        return False, "gate_chain: role required for the default auth check"
    try:
        return authorize_call(tool_name, role, required_level=required_level)
    except ValueError as e:
        return False, "gate_chain: auth consult failed: %s" % (e,)


def run_gate_chain(
    command: str,
    *,
    tool_name: str,
    tool_level: Any,
    now: dt.datetime,
    dry_run: bool = False,
    consent: Optional[ConsentRecord] = None,
    role: Any = None,
    auth_check: Optional[_AUTH_CHECK] = None,
    auth_tags: Iterable[str] = (),
    rate_store: Optional[Dict[Any, List[dt.datetime]]] = None,
    target: Optional[str] = None,
    cap: int = 10,
    window_seconds: float = 60.0,
    lab_staged: bool = False,
    staging_probe: Optional[Callable[[str], Tuple[bool, str]]] = None,
    budget: Any = None,
    ledger: Any = None,
) -> GateChainDecision:
    """Run the composed chain in the pinned order; return the decision.

    `now` is injected and REQUIRED (no wall-time reads anywhere). All
    state (rate store, auth tags, staging posture, budget ledger) is
    caller-owned/injected; the module performs no I/O.
    """
    if not isinstance(now, dt.datetime):
        raise ValueError(
            "gate_chain: now must be a datetime (injected clock), got %r"
            % (now,))
    if not isinstance(dry_run, bool):
        raise ValueError("gate_chain: dry_run must be bool, got %r" % (dry_run,))
    level = _norm_level(tool_level)
    check: _AUTH_CHECK = auth_check or _default_auth_check
    tags = tuple(auth_tags)
    events: List[Dict[str, Any]] = []

    # 1. consent (KA-060) - dry-run carve-out applies inside the gate;
    #    a malformed/unknown action refuses even on dry runs.
    c_ok, c_reason = consent_gate(tool_name, dry_run, consent, now)
    if not c_ok:
        event = consent_refusal_event(tool_name, dry_run, consent, now)
        if event is None:  # defensive: refusal must carry its event
            event = {"event": "execution_consent_refused", "reason": c_reason}
        return GateChainDecision(False, c_reason, "consent", level,
                                 tuple(events + [event]))

    # 2. budget (KA-062, optional; real path only - KA-051 exempts
    # dry runs from every effect gate) - paperwork before quota.
    if budget is not None and not dry_run:
        b_ok, b_reason = check_budget(ledger, budget, "command_invocation",
                                      now)
        if not b_ok:
            events.append({
                "event": EVENT_BUDGET_REFUSED,
                "tool_name": tool_name,
                "reason": b_reason,
                "at": now.isoformat(),
            })
            return GateChainDecision(False, b_reason, "budget", level,
                                     tuple(events))

    # 3. auth (KA-015): the level math gates every run (dry included;
    # the tool floor + effective-level denials keep their seat).
    a_ok, a_reason = check(tool_name, role, level)
    if not a_ok:
        return GateChainDecision(False, a_reason, "auth", level,
                                 tuple(events))

    # Dry-run path (KA-051: planning/inspection unrestricted): record
    # the blast-radius classification, skip every effect gate,
    # authorize. A hostile/unclassifiable command becomes an audit
    # note here (dry runs execute nothing; the real path refuses).
    if dry_run:
        try:
            verdict = br_classify(command)
        except ValueError as e:
            events.append({"event": "gate_chain_blast_unclassifiable",
                           "detail": str(e), "at": now.isoformat()})
            return GateChainDecision(
                True, "authorized (dry run; effects skipped)", "execute",
                level, tuple(events))
        return GateChainDecision(
            True, "authorized (dry run; effects skipped)", "execute",
            level, tuple(events + [br_audit_event(verdict)]))

    # 4. blast-radius (KA-053): static classification - the class's
    # mapped requirement rides IN THE AUDIT BUNDLE (the mapping is the
    # record; enforcement lives in the auth seat above). A
    # hostile/unclassifiable command refuses here, fail-closed.
    try:
        verdict = br_classify(command)
    except ValueError as e:
        return GateChainDecision(
            False, "gate_chain: blast classification refused: %s" % (e,),
            "blast_radius", level, tuple(events))
    br_event = br_audit_event(verdict)
    staging_required = bool(verdict.staging_required)
    events.append(br_event)

    # 5. egress (KA-055) with KA-063 staging establishment.
    if staging_required and staging_probe is None and not lab_staged:
        return GateChainDecision(
            False,
            "gate_chain: command requires lab staging "
            "(blast-radius staging_required=True) and no staging was "
            "established",
            "egress", level, tuple(events))
    lab_claim = lab_staged
    if staging_probe is not None:
        ps_ok, ps_reason = staging_probe(command)
        if not ps_ok:
            return GateChainDecision(False, ps_reason, "egress", level,
                                     tuple(events))
        lab_claim = True
    e_ok, e_reason = egress_gate(command, lab_staged=lab_claim,
                                 auth_tags=tags)
    if not e_ok:
        return GateChainDecision(False, e_reason, "egress", level,
                                 tuple(events))

    # 6. rate-limit (KA-054).
    if rate_store is None:
        return GateChainDecision(
            False, "gate_chain: rate store unavailable for a real execution",
            "rate_limit", level, tuple(events))
    if not isinstance(target, str) or not target.strip():
        return GateChainDecision(
            False, "gate_chain: a real execution needs a scrubbed target "
            "for the rate gate", "rate_limit", level, tuple(events))
    decision = rate_check(rate_store, tool_name, target, now,
                          cap=cap, window_seconds=window_seconds)
    event = decision.event
    events.append(event)
    if not decision.allowed:
        retry = ""
        if isinstance(event, dict) and event.get("retry_at"):
            retry = "; retry_at=%s" % (event["retry_at"],)
        return GateChainDecision(
            False,
            "gate_chain: rate limited (remaining %s)%s"
            % (str(decision.remaining), retry),
            "rate_limit", level, tuple(events))

    # 7. execute - authorization terminal.
    return GateChainDecision(
        True, "authorized to execute (gate chain passed)", "execute", level,
        tuple(events))
