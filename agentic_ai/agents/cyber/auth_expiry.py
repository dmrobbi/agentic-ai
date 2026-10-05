"""Engagement authorization expiry (KA-052): a pure expiry sweeper.

Contract:
- `sweep(authorizations, now)` partitions grants into active vs revoked.
- Revocation boundary: a grant is revoked when `now >= expires_at` - "at
  and after expiry" per KA-015. Grants with expires_at=None never expire.
- The clock is INJECTED (`now`): no wall-time reads, no I/O, and no import
  of the agent chassis (planner purity; source-scan pinned in the tests).
- Every revoked grant yields exactly one deterministic audit-event dict,
  in input order:
    {"event": "engagement_authorization_expired", "engagement_id": ...,
     "level": int, "expires_at": iso8601, "revoked_at": iso8601}
- Datetime tz-ness is the CALLER's contract: the module passes timestamps
  through untouched; a naive/aware mix propagates TypeError (pinned).
- Chassis wiring (set_authorization currently DISCARDS expires_at and the
  execution path never consults expiry) is a KA-INT-1/KA-015 decision;
  this module carries the semantics only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

EVENT_KIND = "engagement_authorization_expired"


@dataclass(frozen=True)
class AuthGrant:
    """One engagement authorization with an optional expiry."""

    engagement_id: str
    level: int
    expires_at: Optional[datetime] = None
    granted_at: Optional[datetime] = None


@dataclass(frozen=True)
class SweepResult:
    """Partition outcome; tuples preserve input order.

    Events mirror `revoked` one-to-one (same order) and are pure dicts so
    the chassis audit path can JSON-serialize them unmodified.
    """

    active: Tuple[AuthGrant, ...]
    revoked: Tuple[AuthGrant, ...]
    events: Tuple[Dict[str, Any], ...]


def sweep(
    authorizations: Iterable[AuthGrant],
    now: datetime,
) -> SweepResult:
    """Partition grants at `now`: revoked when expires_at is set and
    now >= expires_at. Pure: input order preserved, no input mutation."""
    active: List[AuthGrant] = []
    revoked: List[AuthGrant] = []
    events: List[Dict[str, Any]] = []
    for grant in authorizations:
        expires_at = grant.expires_at
        if expires_at is not None and now >= expires_at:
            revoked.append(grant)
            events.append({
                "event": EVENT_KIND,
                "engagement_id": grant.engagement_id,
                "level": grant.level,
                "expires_at": expires_at.isoformat(),
                "revoked_at": now.isoformat(),
            })
        else:
            active.append(grant)
    return SweepResult(
        active=tuple(active),
        revoked=tuple(revoked),
        events=tuple(events),
    )
