"""Engagement RBAC roles (KA-051): named engagement roles BEYOND the
numeric authorization levels, consulted through authorize_call. Chassis
wiring (mixins/agents referencing it) happens ONLY in KA-INT-1, per the
todo's exclusive-file rule; until then this is a standalone module.

SEMANTICS (also the helper's documented contract):
- Levels are the chassis's integer values, chassis-agnostically: 0 none,
  1 basic, 2 advanced, 3 critical (the module imports nothing at all).
- A level-0 tool can NEVER run - the tool itself carries no authorization;
  the tool floor denies every role BEFORE the role gate is consulted.
- Roles:
    operator      may run every executable level (1, 2, 3)
    observer_only read/recon only: level 1
    verify_only   executes nothing: no level passes (planning/inspection
                  is unrestricted for every role - see role_can_dry_run)
- authorize_call(tool_name, role, required_level=None, tool_db=None)
  -> (bool, reason) in the house check_authorization tuple shape.
    role            an EngagementRole or a registered name string
    required_level  the tool's level as a plain int; when omitted it is
                    resolved from tool_db[tool_name].authorization.value
                    (duck-typed: anything with an int authorization)
    Both missing -> ValueError. tool_db lookup miss -> ValueError that
    names the tool. Out-of-range levels -> ValueError. When BOTH are
    supplied, required_level takes precedence (documented, pinned).
- Exact reason strings (pinned):
    Authorized: role 'operator' permits level 2 (advanced)
    Denied: tool 'x' carries level 0 (none) - it cannot run
    Denied: role 'observer_only' does not permit level 3 (critical)
- No exec/network/state; pure data + functions (source-scanned)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

LEVEL_NAMES = {0: "none", 1: "basic", 2: "advanced", 3: "critical"}


@dataclass(frozen=True)
class EngagementRole:
    """A named engagement role: the levels it may actually execute."""

    name: str
    allowed_levels: frozenset
    description: str


ENGAGEMENT_ROLES: Dict[str, EngagementRole] = {
    "operator": EngagementRole(
        name="operator",
        allowed_levels=frozenset({1, 2, 3}),
        description="Full engagement operator: may run basic through "
                    "critical-level tools for the engagement."),
    "observer_only": EngagementRole(
        name="observer_only",
        allowed_levels=frozenset({1}),
        description="Observation access: read/recon level tools only; "
                    "no exploitation or post-exploitation execution."),
    "verify_only": EngagementRole(
        name="verify_only",
        allowed_levels=frozenset(),
        description="Verification access: executes nothing; plans and "
                    "dry-run inspection remain unrestricted."),
}

ROLE_NAMES = tuple(sorted(ENGAGEMENT_ROLES))


def _resolve_role(role) -> EngagementRole:
    if isinstance(role, EngagementRole):
        return role
    if isinstance(role, str):
        found = ENGAGEMENT_ROLES.get(role)
        if found is not None:
            return found
        raise ValueError(
            "Unknown engagement role: %r. Known roles: %s"
            % (role, ", ".join(ROLE_NAMES)))
    raise ValueError("role must be an EngagementRole or a role-name "
                     "string, got: %r" % (role,))


def _resolve_level(tool_name: str, required_level, tool_db) -> int:
    if required_level is not None:
        if not isinstance(required_level, int) or not (0 <= required_level <= 3):
            raise ValueError("required_level must be an int in 0..3, "
                             "got: %r" % (required_level,))
        return required_level
    if tool_db is None:
        raise ValueError(
            "authorize_call(%r) needs required_level or a tool_db lookup"
            % (tool_name,))
    if tool_name not in tool_db:
        raise ValueError("tool_db has no entry for %r" % (tool_name,))
    level = getattr(tool_db[tool_name], "authorization")
    value = getattr(level, "value", level)  # enum or plain int both work
    return value


def authorize_call(
    tool_name: str,
    role,
    required_level: Optional[int] = None,
    tool_db: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """The role consulted by an authorize_call helper (see semantics)."""
    resolved = _resolve_role(role)
    level = _resolve_level(tool_name, required_level, tool_db)

    # 1. the tool floor: level-0 tools can never run, for any role
    if level == 0:
        return False, ("Denied: tool '%s' carries level 0 (none) "
                       "- it cannot run" % (tool_name,))
    # 2. the role gate over executable levels
    if level not in resolved.allowed_levels:
        return False, ("Denied: role '%s' does not permit level %d "
                       "(%s)" % (resolved.name, level, LEVEL_NAMES[level]))
    return True, ("Authorized: role '%s' permits level %d (%s)"
                  % (resolved.name, level, LEVEL_NAMES[level]))


def role_can_dry_run(role) -> bool:
    """Planning/inspection is unrestricted: EVERY role may dry-run.

    Roles gate EXECUTION only. The verify_only description says the same
    thing from the other side. (Integrating the dry-run path with this
    helper is a KA-INT-1 wiring decision; the semantic constant is here.)"""
    return True  # documented constant, not a computation
