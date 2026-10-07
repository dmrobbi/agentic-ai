"""Per-target rate limiting (KA-054): a pure sliding-window gate.

Contract:
- `check(store, tool, target, now, *, cap, window_seconds)` gates ONE
  (tool, target) hit and returns a RateDecision whose `.event` is a
  deterministic, JSON-ready audit-event dict (allowed decisions audited
  too; the exact shapes are pinned in tests/test_rate_limit.py).
- State is INJECTED: `store` is a caller-owned mutable mapping (dict)
  keyed by `(tool, target)` tuples, each value a list of previously
  allowed hit datetimes. The module mutates ONLY the addressed key: it
  REPLACES that bucket with a fresh list (expired hits pruned; `now`
  appended when allowed). Other keys and their list objects are
  untouched; a caller-provided bucket list is never mutated in place.
- The clock is INJECTED (`now`): no wall-time reads, no I/O, and no
  import of the agent chassis (planner purity; source-scan pinned in
  the tests).
- Sliding-window semantics (precise):
  * A recorded hit at time T counts against the cap for a decision at
    `now` iff `(now - T).total_seconds() < window_seconds` - strictly
    less, so a hit exactly window_seconds old has slid OUT of the
    window and no longer counts.
  * The window slides continuously; it never resets at boundaries.
    Capacity frees as individual hits age out: the first slot frees at
    the earliest in-window hit + window_seconds - emitted as `retry_at`
    on blocked events.
  * A decision is allowed iff the in-window hit count is below the cap:
    the first `cap` hits inside a window are allowed; hit number
    cap+1 and beyond within that window are blocked.
  * Blocked attempts consume NO quota: no timestamp is appended, so
    hammering against a full window never extends the block.
  * Reset behavior: there is no scheduled reset. A bucket with zero
    in-window hits behaves exactly like a fresh key. Expired hits are
    pruned from the stored bucket on EVERY decision, so the store stays
    bounded; the caller may also delete keys it no longer needs.
- Defaults are house constants (`DEFAULT_CAP`, `DEFAULT_WINDOW_SECONDS`);
  per-call overrides are the caller's tuning decision. The cap in force
  for a decision is the one passed to THAT call. Events always carry
  `window_seconds` normalized to float.
- Tool/target strings are UNTRUSTED: both are scrubbed by `scrub_token`
  (explicit contract: non-empty string, stripped once; shell
  metacharacters, interior whitespace, and `..` traversal are rejected
  with ValueError) BEFORE keying or audit emission, so store keys and
  event fields carry normalized values. Host-agent gate consultation
  (`validate_target`) is the CALLER's layer (mixin/integration).
- Datetime tz-ness is the CALLER's contract: `now` and recorded hits
  pass through untouched; a naive/aware mix propagates TypeError
  (pinned). Recorded bucket values are datetimes by contract; anything
  else also propagates the arithmetic TypeError. `retry_at` is computed
  from the EARLIEST in-window hit (chronologically identical to bucket
  order under a monotonic clock).
- Chassis wiring (KA-INT-4 gate order: consent -> auth -> blast-radius
  -> egress -> rate-limit -> execute) is an integration decision; this
  module carries the gate semantics only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple
import unicodedata

EVENT_ALLOWED = "tool_target_rate_allowed"
EVENT_BLOCKED = "tool_target_rate_blocked"

DEFAULT_CAP = 10
DEFAULT_WINDOW_SECONDS = 60.0

# house scrub pattern (wp_scrub_target): reject shell metacharacters
_METACHARS = re.compile(r"[;|&`$()\n\r<>\"']")


def scrub_token(value: Any, kind: str) -> str:
    """Normalize an untrusted tool/target token (shared helper).

    Explicit contract: the value must be a non-empty string; it is
    stripped once; any shell metacharacter, interior whitespace, or
    `..` traversal is then rejected with ValueError. The normalized
    string is returned and is what lands in store keys and events.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s must be a non-empty string" % kind)
    t = value.strip()
    if _METACHARS.search(t) or ".." in t or re.search(r"\s", t):
        raise ValueError("rejected %s with shell metacharacters: %r" % (kind, value))
    if len(t) > 2048:
        raise ValueError("rejected over-length %s (>2048 chars)" % kind)
    for ch in t:
        o = ord(ch)
        if o in (0, 0x7F):
            raise ValueError("rejected %s with control char U+%04X" % (kind, o))
        if 0x200B <= o <= 0x200D or o == 0xFEFF:
            raise ValueError("rejected %s with zero-width char U+%04X" % (kind, o))
        if 0x202A <= o <= 0x202E:
            raise ValueError("rejected %s with bidi override U+%04X" % (kind, o))
        if unicodedata.combining(ch):
            raise ValueError("rejected %s with combining char" % kind)
    if "%" in t or "~" in t:
        raise ValueError("rejected %s with format-string/tilde content: %r" % (kind, value))
    return t


def _validated_config(cap: Any, window_seconds: Any) -> Tuple[int, float]:
    """Validate per-decision gate config; ValueError on every bad shape."""
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an int >= 1 (bools rejected), got %r" % (cap,))
    if (isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not window_seconds > 0):
        raise ValueError(
            "window_seconds must be a positive number (bools rejected), got %r"
            % (window_seconds,))
    return cap, float(window_seconds)


@dataclass(frozen=True)
class RateDecision:
    """Outcome of one gate check; `.event` is a JSON-ready audit dict.

    `hits_in_window` is the count the decision was made against (for
    allowed decisions AFTER appending the new hit); `remaining` is the
    capacity left in the current window (0 when blocked).
    """

    allowed: bool
    hits_in_window: int
    remaining: int
    event: Dict[str, Any]


def check(
    store: Dict[Tuple[str, str], List[datetime]],
    tool: Any,
    target: Any,
    now: datetime,
    *,
    cap: int = DEFAULT_CAP,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> RateDecision:
    """Gate one (tool, target) hit against its sliding window.

    Pure planner: state is the injected `store`, the clock is the
    injected `now`; only the addressed bucket is written back.
    """
    cap_i, window = _validated_config(cap, window_seconds)
    tool_n = scrub_token(tool, "tool")
    target_n = scrub_token(target, "target")
    key = (tool_n, target_n)
    recorded = store.get(key, [])
    in_window = [
        t for t in recorded if (now - t).total_seconds() < window
    ]
    if len(in_window) >= cap_i:
        retry_at = min(in_window) + timedelta(seconds=window)
        store[key] = in_window  # write back the pruned bucket (fresh list)
        return RateDecision(
            allowed=False,
            hits_in_window=len(in_window),
            remaining=0,
            event={
                "event": EVENT_BLOCKED,
                "tool": tool_n,
                "target": target_n,
                "cap": cap_i,
                "window_seconds": window,
                "hits_in_window": len(in_window),
                "retry_at": retry_at.isoformat(),
                "now": now.isoformat(),
            },
        )
    in_window.append(now)
    store[key] = in_window  # replace the bucket (fresh list, never in place)
    remaining = cap_i - len(in_window)
    return RateDecision(
        allowed=True,
        hits_in_window=len(in_window),
        remaining=remaining,
        event={
            "event": EVENT_ALLOWED,
            "tool": tool_n,
            "target": target_n,
            "cap": cap_i,
            "window_seconds": window,
            "hits_in_window": len(in_window),
            "remaining": remaining,
            "now": now.isoformat(),
        },
    )