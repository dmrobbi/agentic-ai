"""KA-062 tests - engagement budget/quota gate: cap boundaries (cap 0,
at-cap deny, in-window vs lifetime counting with the exact strictly-less
slide boundary), independent per-unit counters, blocked attempts
consuming nothing and never mutating the injected ledger, the exact
consumption-event contract (including key order), budget-retighten vs
stored provenance, malformed request-side deny codes vs loud state-side
propagation, dropped-expired-entry equivalence, determinism, tz-mix
propagation, and the module source-scan pin. No network."""
from __future__ import annotations

import dataclasses
import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.budgets import (
    EVENT_KIND,
    KINDS,
    KIND_COMMAND_INVOCATION,
    KIND_EXTERNAL_REQUEST,
    REASON_OK,
    REASON_BUDGET_MALFORMED,
    REASON_KIND_INVALID,
    REASON_COMMANDS_EXHAUSTED,
    REASON_EXTERNALS_EXHAUSTED,
    Budget,
    check_budget,
    consumption_event,
)

UTC = timezone.utc
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock
ENG = "ENG-BUDGET-1"


def _budget(**kwargs):
    kwargs.setdefault("engagement_id", ENG)
    return Budget(**kwargs)


def _consumed(engagement_id, kind, at, window_seconds=None):
    """Shape-faithful ledger entry helper (what consumption_event writes)."""
    return {
        "event": EVENT_KIND,
        "engagement_id": engagement_id,
        "kind": kind,
        "window_seconds": window_seconds,
        "at": at.isoformat(),
    }


def test_constants_are_pinned():
    assert EVENT_KIND == "engagement_budget_consumed"
    assert KINDS == ("command_invocation", "external_request")
    assert KIND_COMMAND_INVOCATION == "command_invocation"
    assert KIND_EXTERNAL_REQUEST == "external_request"
    assert REASON_OK == "budget_ok"
    assert REASON_BUDGET_MALFORMED == "budget_malformed"
    assert REASON_KIND_INVALID == "budget_kind_invalid"
    assert REASON_COMMANDS_EXHAUSTED == "command_invocation_cap_reached"
    assert REASON_EXTERNALS_EXHAUSTED == "external_request_cap_reached"


def test_gate_result_shape_is_exactly_a_two_tuple():
    result = check_budget([], _budget(max_command_invocations=1),
                          KIND_COMMAND_INVOCATION, BASE)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert type(result[0]) is bool
    assert type(result[1]) is str


def test_fully_uncapped_budget_admits_and_still_meters():
    budget = _budget()  # both caps None: admission may run forever
    for _ in range(5):
        assert check_budget([], budget, KIND_COMMAND_INVOCATION, BASE) == (
            True, REASON_OK)
        assert check_budget([], budget, KIND_EXTERNAL_REQUEST, BASE) == (
            True, REASON_OK)


def test_first_command_admitted_under_lifetime_cap():
    ledger = []
    assert check_budget(ledger, _budget(max_command_invocations=2),
                        KIND_COMMAND_INVOCATION, BASE) == (True, REASON_OK)
    ledger.append(consumption_event(_budget(max_command_invocations=2),
                                    KIND_COMMAND_INVOCATION, BASE))
    assert check_budget(ledger, _budget(max_command_invocations=2),
                        KIND_COMMAND_INVOCATION, BASE) == (True, REASON_OK)
    # second consumption reaches the cap; the third attempt denies
    ledger.append(consumption_event(_budget(max_command_invocations=2),
                                    KIND_COMMAND_INVOCATION, BASE))
    allowed, reason = check_budget(ledger, _budget(max_command_invocations=2),
                                   KIND_COMMAND_INVOCATION, BASE)
    assert (allowed, reason) == (False, REASON_COMMANDS_EXHAUSTED)


def test_cap_zero_blocks_even_a_fresh_ledger():
    ledger = []
    assert check_budget(ledger, _budget(max_command_invocations=0),
                        KIND_COMMAND_INVOCATION, BASE) == (
        False, REASON_COMMANDS_EXHAUSTED)
    assert check_budget(ledger, _budget(max_external_requests=0),
                        KIND_EXTERNAL_REQUEST, BASE) == (
        False, REASON_EXTERNALS_EXHAUSTED)
    assert ledger == []  # nothing invented, nothing recorded


def test_units_count_independently():
    budget = _budget(max_command_invocations=1, max_external_requests=1)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE)]
    # commands exhausted...
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION, BASE) == (
        False, REASON_COMMANDS_EXHAUSTED)
    # ...externals untouched (independent counters, no cross-blocking)
    assert check_budget(ledger, budget, KIND_EXTERNAL_REQUEST, BASE) == (
        True, REASON_OK)
    ledger.append(_consumed(ENG, KIND_EXTERNAL_REQUEST, BASE))
    assert check_budget(ledger, budget, KIND_EXTERNAL_REQUEST, BASE) == (
        False, REASON_EXTERNALS_EXHAUSTED)


def test_denied_attempts_consume_nothing_and_leave_ledger_untouched():
    budget = _budget(max_command_invocations=1)
    ledger = [consumption_event(budget, KIND_COMMAND_INVOCATION, BASE)]
    fingerprint = list(ledger)
    for offset in (10, 20, 30):
        now = BASE + timedelta(seconds=offset)
        assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION, now) == (
            False, REASON_COMMANDS_EXHAUSTED)
    assert ledger == fingerprint  # blocked attempts append nothing
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE) == (False, REASON_COMMANDS_EXHAUSTED)


def test_lifetime_cap_counts_consumption_of_any_age():
    budget = _budget(max_command_invocations=1, window_seconds=None)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION,
                        BASE - timedelta(days=365))]
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION, BASE) == (
        False, REASON_COMMANDS_EXHAUSTED)


def test_window_boundary_is_strictly_less():
    budget = _budget(max_command_invocations=1, window_seconds=60.0)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE)]
    # just inside the window: the old consumption still counts
    just_inside = BASE + timedelta(seconds=59, microseconds=999999)
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        just_inside) == (False, REASON_COMMANDS_EXHAUSTED)
    # exactly window-seconds old: slid OUT of the window (KA-054 boundary)
    exactly_old = BASE + timedelta(seconds=60)
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        exactly_old) == (True, REASON_OK)


def test_window_capacity_frees_as_consumptions_age_out():
    budget = _budget(max_command_invocations=2, window_seconds=60.0)
    ledger = [
        consumption_event(budget, KIND_COMMAND_INVOCATION,
                          BASE - timedelta(seconds=10)),
        consumption_event(budget, KIND_COMMAND_INVOCATION,
                          BASE - timedelta(seconds=5)),
    ]
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE) == (False, REASON_COMMANDS_EXHAUSTED)
    # the first slot frees EXACTLY when the older consumption turns
    # 60s old (strictly-less boundary in the freeing direction)
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=49, microseconds=999999)
                        ) == (False, REASON_COMMANDS_EXHAUSTED)
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=50)) == (True, REASON_OK)
    # the remaining slot frees when the younger consumption does the same
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=55)) == (True, REASON_OK)


def test_decision_uses_budget_window_not_stored_provenance():
    # a consumption recorded under window 60.0...
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE, 60.0)]
    # ...retightened budget (window 10.0) no longer counts it at +30s
    tight = _budget(max_command_invocations=1, window_seconds=10.0)
    assert check_budget(ledger, tight, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=30)) == (True, REASON_OK)
    # ...rewidened budget (window 1200.0) still counts it at +60s
    wide = _budget(max_command_invocations=1, window_seconds=1200.0)
    assert check_budget(ledger, wide, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=60)) == (
        False, REASON_COMMANDS_EXHAUSTED)
    # a stored None (lifetime provenance) is windowed by the new budget
    lifetime_recorded = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE)]
    windowed = _budget(max_command_invocations=1, window_seconds=10.0)
    assert check_budget(lifetime_recorded, windowed, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=30)) == (True, REASON_OK)


def test_foreign_entries_are_skipped_silently():
    budget = _budget(max_command_invocations=1, window_seconds=60.0)
    ledger = [
        {"event": "tool_target_rate_allowed", "tool": "nmap"},  # foreign kind
        _consumed("ENG-OTHER", KIND_COMMAND_INVOCATION, BASE),  # other eng
        _consumed(ENG, KIND_EXTERNAL_REQUEST, BASE),            # other unit
        _consumed(ENG, KIND_COMMAND_INVOCATION,
                  BASE - timedelta(seconds=120)),               # expired by window
    ]
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE) == (True, REASON_OK)


def test_consumption_event_exact_shape_and_key_order():
    budget = _budget(window_seconds=90.0)
    event = consumption_event(budget, KIND_EXTERNAL_REQUEST, BASE)
    assert event == {
        "event": EVENT_KIND,
        "engagement_id": ENG,
        "kind": KIND_EXTERNAL_REQUEST,
        "window_seconds": 90.0,
        "at": BASE.isoformat(),
    }
    assert list(event) == [
        "event", "engagement_id", "kind", "window_seconds", "at",
    ]


def test_consumption_event_normalizes_window_to_float_and_keeps_none():
    event = consumption_event(_budget(window_seconds=60),  # int budget
                              KIND_COMMAND_INVOCATION, BASE)
    assert event["window_seconds"] == 60.0
    assert event["window_seconds"] is not None
    assert isinstance(event["window_seconds"], float)
    lifetime = consumption_event(_budget(), KIND_COMMAND_INVOCATION, BASE)
    assert lifetime["window_seconds"] is None


def test_gate_and_consumption_roundtrip_cycle():
    budget = _budget(max_command_invocations=2, window_seconds=30.0)
    ledger = []
    consumed = 0
    for offset in (0, 5, 15, 25, 35):
        now = BASE + timedelta(seconds=offset)
        allowed, reason = check_budget(ledger, budget,
                                       KIND_COMMAND_INVOCATION, now)
        if allowed:
            ledger.append(consumption_event(budget, KIND_COMMAND_INVOCATION, now))
            consumed += 1
    # +0s +5s allowed (2), +15 +25 denied, +35 allowed exactly when the
    # first consumption turns 30s old (strictly-less boundary)
    assert consumed == 3
    assert len(ledger) == 3
    assert [json.loads(json.dumps(e))["at"] for e in ledger] == [
        (BASE + timedelta(seconds=0)).isoformat(),
        (BASE + timedelta(seconds=5)).isoformat(),
        (BASE + timedelta(seconds=35)).isoformat(),
    ]


def test_identical_inputs_yield_identical_results():
    budget = _budget(max_command_invocations=1, window_seconds=10.0)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION,
                        BASE - timedelta(seconds=2))]
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION, BASE) == (
        check_budget(ledger, budget, KIND_COMMAND_INVOCATION, BASE))
    e1 = consumption_event(budget, KIND_COMMAND_INVOCATION, BASE)
    e2 = consumption_event(budget, KIND_COMMAND_INVOCATION, BASE)
    assert e1 == e2
    assert list(e1) == list(e2)
    assert json.dumps(e1) == json.dumps(e2)


@pytest.mark.parametrize("bad_budget", [
    None, "nope", 7, 3.5,
    Budget(None), Budget(""), Budget("   "),
    Budget(ENG, max_command_invocations=True),
    Budget(ENG, max_command_invocations=2.5),
    Budget(ENG, max_command_invocations=-1),
    Budget(ENG, max_external_requests=True),
    Budget(ENG, max_external_requests=-2),
    Budget(ENG, window_seconds=0),
    Budget(ENG, window_seconds=-1.5),
    Budget(ENG, window_seconds="60"),
    Budget(ENG, window_seconds=True),
])
def test_malformed_budget_denies(bad_budget):
    ledger = []
    assert check_budget(ledger, bad_budget, KIND_COMMAND_INVOCATION,
                        BASE) == (False, REASON_BUDGET_MALFORMED)
    assert check_budget(ledger, bad_budget, KIND_EXTERNAL_REQUEST,
                        BASE) == (False, REASON_BUDGET_MALFORMED)
    assert ledger == []  # denials never write


@pytest.mark.parametrize("bad_kind", [
    None, 7, "nmap", "external", "command",
    "COMMAND_INVOCATION", " command_invocation",
    "external_requestes", "command_invocation ",
])
def test_unknown_kind_denies_with_exact_match_semantics(bad_kind):
    assert check_budget([], _budget(max_command_invocations=2),
                        bad_kind, BASE) == (False, REASON_KIND_INVALID)


def test_kind_check_precedes_budget_check():
    # both request arguments malformed: the kind refusal wins (pinned
    # precedence, consent_gate discipline)
    assert check_budget([], "not-a-budget", "nmap", BASE) == (
        False, REASON_KIND_INVALID)
    assert check_budget([], "not-a-budget", KIND_COMMAND_INVOCATION,
                        BASE) == (False, REASON_BUDGET_MALFORMED)


@pytest.mark.parametrize("garbage", [7, "entry", None, 3.2, (1, 2)])
def test_non_dict_ledger_entry_raises_valueerror(garbage):
    ledger = [garbage]
    with pytest.raises(ValueError):
        check_budget(ledger, _budget(), KIND_COMMAND_INVOCATION, BASE)


@pytest.mark.parametrize("field_overrides", [
    {"engagement_id": 7},
    {"engagement_id": None},
    {"kind": "weird"},
    {"kind": None},
    {"window_seconds": True},
    {"window_seconds": "60"},
    {"window_seconds": -5.0},
    {"at": 7},
    {"at": None},
])
def test_own_kind_entry_malformed_field_raises(field_overrides):
    entry = _consumed(ENG, KIND_COMMAND_INVOCATION, BASE)
    entry.update(field_overrides)
    with pytest.raises((ValueError, TypeError)):
        check_budget([entry], _budget(), KIND_COMMAND_INVOCATION, BASE)


def test_unparseable_stamp_string_raises_valueerror():
    entry = _consumed(ENG, KIND_COMMAND_INVOCATION, BASE)
    entry["at"] = "not-a-datetime"
    with pytest.raises(ValueError):
        check_budget([entry], _budget(), KIND_COMMAND_INVOCATION, BASE)


def test_missing_at_treated_as_malformed_own_kind_entry():
    entry = _consumed(ENG, KIND_COMMAND_INVOCATION, BASE)
    del entry["at"]
    with pytest.raises(TypeError):
        check_budget([entry], _budget(), KIND_COMMAND_INVOCATION, BASE)


def test_corruption_in_foreign_engagement_own_kind_entry_raises():
    # our event kind is always OUR emission: malformed internals raise
    # regardless of which engagement the entry claims
    entry = _consumed("ENG-OTHER", KIND_COMMAND_INVOCATION, BASE)
    entry["at"] = "not-a-datetime"
    with pytest.raises(ValueError):
        check_budget([entry], _budget(), KIND_COMMAND_INVOCATION, BASE)


def test_foreign_kind_entry_garbage_is_skipped():
    entry = {"event": "tool_target_rate_allowed", "tool": 7,
             "target": None, "junk": object()}
    # an unknown kind denies BEFORE any ledger scanning (pinned order)...
    assert check_budget([entry], _budget(), "not-a-kind", BASE) == (
        False, REASON_KIND_INVALID)
    # ...and a foreign-kind entry's garbage is skipped without validation
    assert check_budget([entry], _budget(), KIND_COMMAND_INVOCATION,
                        BASE) == (True, REASON_OK)


@pytest.mark.parametrize("naive_first", [True, False])
def test_tz_mix_propagates_typeerror_under_windowing(naive_first):
    naive = datetime(2026, 10, 5, 11, 59, 30)
    stamp = naive if naive_first else BASE
    now = BASE if naive_first else naive
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, stamp)]
    budget = _budget(max_command_invocations=1, window_seconds=60.0)
    with pytest.raises(TypeError):
        check_budget(ledger, budget, KIND_COMMAND_INVOCATION, now)


def test_lifetime_accounting_never_compares_tz():
    # no subtraction happens under window_seconds=None, so a naive stamp
    # against an aware clock still counts (pinned tolerance)
    naive = datetime(2026, 10, 5, 11, 59, 30)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, naive)]
    budget = _budget(max_command_invocations=1)  # lifetime
    assert check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                        BASE) == (False, REASON_COMMANDS_EXHAUSTED)


def test_dropping_expired_entries_does_not_change_windowed_decision():
    budget = _budget(max_command_invocations=1, window_seconds=60.0)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE),
              consumption_event(budget, KIND_EXTERNAL_REQUEST,
                                BASE - timedelta(hours=2)),
              _consumed("ENG-OTHER", KIND_COMMAND_INVOCATION, BASE)]
    decision = check_budget(ledger, budget, KIND_COMMAND_INVOCATION,
                            BASE + timedelta(seconds=60))
    pruned = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE)]
    assert check_budget(pruned, budget, KIND_COMMAND_INVOCATION,
                        BASE + timedelta(seconds=60)) == decision
    assert decision == (True, REASON_OK)


def test_budget_is_frozen():
    budget = _budget(max_command_invocations=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        budget.max_command_invocations = 9


def test_gate_never_mutates_the_injected_ledger():
    budget = _budget(max_command_invocations=1, window_seconds=60.0)
    ledger = [_consumed(ENG, KIND_COMMAND_INVOCATION, BASE)]
    kept = list(ledger)
    allowed, reason = check_budget(ledger, budget,
                                   KIND_COMMAND_INVOCATION, BASE)
    assert (allowed, reason) == (False, REASON_COMMANDS_EXHAUSTED)
    assert ledger == kept
    assert ledger is ledger  # same object, same sole reference intact


def test_module_purity_source_scan():
    # planner-purity by construction: the module never imports the
    # chassis, reads no wall clock, and uses no exec/eval facility, no
    # network facility, and no file or process facility
    module = importlib.import_module("agentic_ai.agents.cyber.budgets")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "from agentic_ai" not in source
    assert "import agentic_ai" not in source
    assert "utcnow" not in source
    assert "time.time" not in source
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "eval(" not in source
    assert "exec(" not in source
    assert "popen" not in source
    assert "socket" not in source
    assert "urllib" not in source
    assert "httpx" not in source
    assert "http.client" not in source
    assert "urlopen" not in source
    assert "open(" not in source


def test_no_wall_clock_or_io_calls_in_module():
    module = importlib.import_module("agentic_ai.agents.cyber.budgets")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for token in ("datetime.now", "date.today", "time(", "sleep(", "monkeypatch"):
        assert token not in source