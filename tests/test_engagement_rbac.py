"""KA-051 tests - engagement RBAC: the role registry, the level matrix
per role (parametrized), the level-0 tool floor, exact reason strings,
name resolution (string == object), the tool_db lookup path (real
KALI_TOOLS_DB rows, duck-typed int fallback), the
required_level-beats-tool_db precedence, out-of-range/missing-lookup
ValueErrors with actionable text, role_can_dry_run's constant, and the
purity scan (the module imports NOTHING from the package). No network."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.engagement_rbac import (
    ENGAGEMENT_ROLES,
    EngagementRole,
    LEVEL_NAMES,
    ROLE_NAMES,
    authorize_call,
    role_can_dry_run,
)
from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB  # test-side only


def test_roles_registry_shape():
    assert ROLE_NAMES == ("observer_only", "operator", "verify_only")
    assert ENGAGEMENT_ROLES["operator"].allowed_levels == frozenset({1, 2, 3})
    assert ENGAGEMENT_ROLES["observer_only"].allowed_levels == frozenset({1})
    assert ENGAGEMENT_ROLES["verify_only"].allowed_levels == frozenset()
    for role in ENGAGEMENT_ROLES.values():
        assert role.description


@pytest.mark.parametrize("level", [1, 2, 3])
def test_operator_permits_every_executable_level(level):
    ok, reason = authorize_call("t", "operator", required_level=level)
    assert ok is True
    assert reason == "Authorized: role 'operator' permits level %d (%s)" % (
        level, LEVEL_NAMES[level])


@pytest.mark.parametrize("role_name", ROLE_NAMES)
def test_tool_floor_denies_level_zero_for_every_role(role_name):
    ok, reason = authorize_call("x", role_name, required_level=0)
    assert ok is False
    assert reason == "Denied: tool 'x' carries level 0 (none) - it cannot run"


@pytest.mark.parametrize("level,outcome", [(1, True), (2, False), (3, False)])
def test_observer_only_level_matrix(level, outcome):
    ok, reason = authorize_call("t", "observer_only", required_level=level)
    assert ok is outcome
    if not outcome:
        assert reason == ("Denied: role 'observer_only' does not permit "
                          "level %d (%s)" % (level, LEVEL_NAMES[level]))


@pytest.mark.parametrize("level", [1, 2, 3])
def test_verify_only_denies_every_execution(level):
    ok, reason = authorize_call("t", "verify_only", required_level=level)
    assert ok is False
    assert "does not permit" in reason


def test_exact_reason_strings_both_branches():
    ok, why_ok = authorize_call("t", EngagementRole(
        name="operator", allowed_levels=frozenset({1, 2, 3}), description="d"),
        required_level=2)
    assert (ok, why_ok) == (
        True, "Authorized: role 'operator' permits level 2 (advanced)")
    ok, why_no = authorize_call("t", "observer_only", required_level=3)
    assert (ok, why_no) == (
        False,
        "Denied: role 'observer_only' does not permit level 3 (critical)")


@pytest.mark.parametrize("level,ok", [(1, True), (2, False)])
def test_string_name_equals_object_semantics(level, ok):
    as_string = authorize_call("t", "observer_only", required_level=level)
    as_object = authorize_call("t", ENGAGEMENT_ROLES["observer_only"],
                               required_level=level)
    assert as_string == as_object


def test_unknown_role_is_actionable():
    with pytest.raises(ValueError) as exc:
        authorize_call("t", "superuser", required_level=1)
    assert "Unknown engagement role: 'superuser'" in str(exc.value)
    assert "Known roles:" in str(exc.value)


def test_tool_db_level_resolution():
    ok, _ = authorize_call("nmap", "operator", tool_db=KALI_TOOLS_DB)
    assert ok is True  # nmap carries BASIC(1): operator runs it
    ok, reason = authorize_call(
        "mimikatz", "observer_only", tool_db=KALI_TOOLS_DB)
    assert ok is False  # mimikatz carries CRITICAL(3)
    assert "level 3 (critical)" in reason


def test_tool_db_unknown_tool_actionable():
    with pytest.raises(ValueError) as exc:
        authorize_call("not_a_tool", "operator", tool_db=KALI_TOOLS_DB)
    assert "no entry for" in str(exc.value)


def test_required_level_overrides_tool_db():
    # both supplied: required_level explicitly wins over the DB row
    ok, reason = authorize_call(
        "mimikatz", "operator", required_level=1, tool_db=KALI_TOOLS_DB)
    assert ok is True
    assert "level 1 (basic)" in reason


@pytest.mark.parametrize("bad", [7, -1, "2", None])
def test_out_of_range_levels_rejected(bad):
    if bad is None:
        # None with no db is the actionable 'needs a level' error, tested
        # separately; here None must not silently pass as a level
        with pytest.raises(ValueError):
            authorize_call("t", "operator", required_level=bad)
    else:
        with pytest.raises(ValueError):
            authorize_call("t", "operator", required_level=bad)


def test_missing_level_and_db_is_actionable():
    with pytest.raises(ValueError) as exc:
        authorize_call("t", "operator")
    assert "needs required_level or a tool_db lookup" in str(exc.value)


@pytest.mark.parametrize("role_name", ROLE_NAMES)
def test_dry_run_unrestricted_for_every_role(role_name):
    assert role_can_dry_run(role_name) is True


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.engagement_rbac")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "agentic_ai" not in source  # stdlib-only module: no imports
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
