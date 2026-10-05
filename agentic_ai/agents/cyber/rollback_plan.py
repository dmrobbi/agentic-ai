"""Rollback requirements (KA-058): a pure plan-contract checker.

A planner must prove, BEFORE execution, that every mutating step of a
plan declares how to undo it. This module enforces exactly that
planner-level contract on injected data - it never executes anything,
never calls out, and never reads state.

Inputs - a plan is an ordered iterable of steps; every step is either a
`PlanStep` or a mapping with the keys:
    name       required string: the planned operation's name
    category   optional: one of the known categories, or None
    undo       optional: an `UndoAction`, or a mapping with `action`
               (string), `args` (mapping, may be empty) and `verify`
               (string)
Unknown mapping keys are absorbed (ignored); the contract applies to
declared keys only.

THE CLASSIFIER (pinned): a step MUTATES unless it is provably
read-only.
    category in READ_ONLY_CATEGORIES -> read-only; undo not required
    category in MUTATING_CATEGORIES  -> mutating
    category is None (undeclared)    -> mutating, fail closed: an op
        the planner has not proven read-only must declare its undo
    otherwise (declared but unknown)-> ValueError, never silent
A category is orthogonal to authorization levels: it records what the
op touches, not who may run it.

THE CONTRACT (pinned): every mutating step carries a COMPLETE declared
undo AT PLAN TIME - `action` names the exact inverse operation, `args`
is the fully specified argument mapping for it (may be empty for an
argless inverse), and `verify` is the verification check that proves
the rollback took effect. A missing, incomplete or non-structured undo
is a deterministic result-level REJECTION with a precise reason - never
silence. Exceptions are reserved for structural errors that would make
a violation unreportable (a step that is neither a `PlanStep` nor a
mapping, or a name/category/engagement_id that cannot be scrubbed into
a clean string). Per step, completeness is checked in a fixed order:
the undo object itself, then `action`, `args`, `verify`. Undos carried
by NON-mutating steps are neither required nor validated - the contract
binds mutating steps only.

Ops:
- classify_step(step) -> bool: the pinned classifier ("is this step
  mutating?"); the declared undo is never consulted.
- validate_plan(steps) -> (ok, reason): the house tuple. The reason
  strings, exactly (index is the step's 0-based position in plan order,
  name is the scrubbed step name):
    "Rollback contract satisfied: no mutating steps (nothing requires undo)"
    "Rollback contract satisfied: 1 mutating step(s) with declared undo"
    "Rejected: mutating step 1 (rm_user) requires a declared undo - none present"
    "Rejected: undo for mutating step 1 (rm_user) is not a structured undo plan"
    "Rejected: undo for mutating step 1 (rm_user) does not declare an inverse action"
    "Rejected: undo for mutating step 1 (rm_user) does not declare inverse arguments"
    "Rejected: undo for mutating step 1 (rm_user) does not declare a verification check"
  The FIRST offending step in plan order decides the returned reason;
  every offending step gets its own rejection event.
- rollback_report(steps, engagement_id=None) -> dict:
    {"ok": bool, "reason": str, "events": [...], "steps_total": int,
     "mutating_steps": int}
  Each event is one JSON-ready dict in house audit-event shape, in
  input order:
    {"event": EVENT_KIND, "engagement_id": ..., "step_index": int,
     "step_name": str, "reason": str}
  `engagement_id` is optional plan metadata; when given it is scrubbed
  and carried into every event exactly as scrubbed.

Purity: no chassis import, no wall clock, no I/O, no execution or
network facilities. Inputs are never mutated: every declared field is
read, never written, and the report holds plain values only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

EVENT_KIND = "rollback_contract_rejected"

#: Operation categories proven observation-only: their steps never
#: change target state, so they are exempt from the undo contract.
READ_ONLY_CATEGORIES = frozenset({
    "recon", "scan", "inspect", "read", "verify", "monitor",
})

#: Operation categories known to change or potentially change target
#: state. The classifier's default is fail closed regardless of this
#: registry: an UNDECLARED category counts as mutating too.
MUTATING_CATEGORIES = frozenset({
    "execute", "write", "create", "modify", "delete",
    "deploy", "exploit", "persist", "reconfigure",
})

#: The closed set a declared category must belong to. CATEGORY_NAMES is
#: the sorted name tuple used in deterministic error messages.
KNOWN_CATEGORIES = READ_ONLY_CATEGORIES | MUTATING_CATEGORIES
CATEGORY_NAMES = tuple(sorted(KNOWN_CATEGORIES))

_SATISFIED_NONE = ("Rollback contract satisfied: no mutating steps "
                   "(nothing requires undo)")
_SATISFIED_FMT = ("Rollback contract satisfied: %d mutating step(s) "
                  "with declared undo")


@dataclass(frozen=True)
class UndoAction:
    """A declared undo for one mutating step: the exact inverse
    operation (`action`) with its fully specified argument mapping
    (`args`, may be empty for an argless inverse), plus the
    verification check (`verify`) that proves the rollback took
    effect."""

    action: str
    args: Dict[str, Any]
    verify: str


@dataclass(frozen=True)
class PlanStep:
    """One planned action. `category` is the classifier's declared
    input (None = undeclared, which classifies as mutating, fail
    closed); `undo` is the declared reversal, required by the contract
    exactly when this step classifies as mutating."""

    name: str
    category: Optional[str] = None
    undo: Optional[UndoAction] = None


def _scrub_text(value: Any, what: str) -> str:
    """House scrub: must be a non-empty string after whitespace strip;
    otherwise a structural error (wrong type or empty)."""
    if not isinstance(value, str):
        raise TypeError("%s must be a string, got: %r" % (what, value))
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("%s must be a non-empty string" % (what,))
    return cleaned


def _clean_declared_text(value: Any) -> Optional[str]:
    """A declared undo field: a string with usable content, stripped.
    Anything else (None, wrong type, blank after strip) reads as
    undeclared - reported as that field's rejection, not an exception,
    so the violation stays named and reportable."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _iter_steps(steps: Any) -> Iterable[Any]:
    """Guard the plan-level shape: a plan is an iterable of steps, not
    a single step, undo, or mapping mistaken for a whole plan."""
    if isinstance(steps, (PlanStep, UndoAction, Mapping, str)):
        raise TypeError("steps must be an iterable of plan steps, "
                        "got: %r" % (steps,))
    return steps


def _normalize_step(index: int, raw: Any) -> Tuple[str, Optional[str], Any]:
    """Structural read of one step: scrubbed name, validated category
    (None or a known string), declared undo passed through untouched.
    Structural problems raise; the undo is contract-checked later."""
    if isinstance(raw, PlanStep):
        name_raw = raw.name
        category_raw = raw.category
        undo = raw.undo
    elif isinstance(raw, Mapping):
        if "name" not in raw:
            raise ValueError(
                "plan step %d does not declare a name" % (index,))
        name_raw = raw.get("name")
        category_raw = raw.get("category")
        undo = raw.get("undo")
    else:
        raise TypeError("plan step %d must be a PlanStep or a mapping, "
                        "got: %r" % (index, raw))
    name = _scrub_text(name_raw, "plan step %d name" % (index,))
    if category_raw is None:
        return name, None, undo
    category = _scrub_text(category_raw,
                           "plan step %d category" % (index,))
    if category not in KNOWN_CATEGORIES:
        raise ValueError(
            "plan step %d declares unknown category %r "
            "(known categories: %s)"
            % (index, category_raw, ", ".join(CATEGORY_NAMES)))
    return name, category, undo


def _is_mutating(category: Optional[str]) -> bool:
    """The pinned classifier over a VALIDATED category (None counts as
    mutating - fail closed)."""
    return category is None or category in MUTATING_CATEGORIES


def _undo_violation(index: int, name: str, undo: Any) -> Optional[str]:
    """The precise contract reason for this step's undo declaration, in
    the fixed check order (undo object, action, args, verify), or None
    when the undo is complete."""
    if undo is None:
        return ("Rejected: mutating step %d (%s) requires a declared "
                "undo - none present" % (index, name))
    if not isinstance(undo, (UndoAction, Mapping)):
        return ("Rejected: undo for mutating step %d (%s) is not a "
                "structured undo plan" % (index, name))
    if isinstance(undo, UndoAction):
        action, args, verify = undo.action, undo.args, undo.verify
    else:
        action = undo.get("action")
        args = undo.get("args")
        verify = undo.get("verify")
    if _clean_declared_text(action) is None:
        return ("Rejected: undo for mutating step %d (%s) does not "
                "declare an inverse action" % (index, name))
    if not isinstance(args, Mapping):
        return ("Rejected: undo for mutating step %d (%s) does not "
                "declare inverse arguments" % (index, name))
    if _clean_declared_text(verify) is None:
        return ("Rejected: undo for mutating step %d (%s) does not "
                "declare a verification check" % (index, name))
    return None


def _evaluate(steps: Any, engagement_id: Any = None) -> Dict[str, Any]:
    """The shared evaluator behind both public ops. Deterministic:
    events land in input order, the first offending step (in plan
    order) decides the returned reason."""
    eid = None
    if engagement_id is not None:
        eid = _scrub_text(engagement_id, "engagement_id")
    normalized = [_normalize_step(i, raw)
                  for i, raw in enumerate(_iter_steps(steps))]
    events: List[Dict[str, Any]] = []
    mutating = 0
    rejection: Optional[str] = None
    for index, (name, category, undo) in enumerate(normalized):
        if not _is_mutating(category):
            continue
        mutating += 1
        violation = _undo_violation(index, name, undo)
        if violation is not None:
            events.append({
                "event": EVENT_KIND,
                "engagement_id": eid,
                "step_index": index,
                "step_name": name,
                "reason": violation,
            })
            if rejection is None:
                rejection = violation
    if rejection is None:
        reason = (_SATISFIED_NONE if mutating == 0
                  else _SATISFIED_FMT % (mutating,))
        ok = True
    else:
        reason = rejection
        ok = False
    return {
        "ok": ok,
        "reason": reason,
        "events": events,
        "steps_total": len(normalized),
        "mutating_steps": mutating,
    }


def classify_step(step: Any) -> bool:
    """True exactly when `step` classifies as MUTATING (the pinned
    classifier; undeclared categories count as mutating, fail closed).
    Structural errors raise exactly as in the plan ops; the declared
    undo is never consulted."""
    _, category, _ = _normalize_step(0, step)
    return _is_mutating(category)


def validate_plan(steps: Iterable[Any]) -> Tuple[bool, str]:
    """Enforce the rollback contract; return the house tuple (ok,
    reason). True only when every mutating step declares a complete
    structured undo."""
    report = _evaluate(steps)
    return report["ok"], report["reason"]


def rollback_report(steps: Iterable[Any],
                    engagement_id: Any = None) -> Dict[str, Any]:
    """Full contract report: the validate_plan pair plus counts and one
    house audit-event dict per offending step (see module docstring)."""
    return _evaluate(steps, engagement_id=engagement_id)