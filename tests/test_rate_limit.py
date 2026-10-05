"""KA-054 tests - per-target rate limiting: exact sliding-window
boundaries (in/expired/just-inside), blocked-not-consuming quota,
pruning + caller-bucket non-mutation, per-(tool,target) independence,
the exact allowed + blocked audit-event contracts (including key
order), scrub rejection of hostile tokens (both positions), config
validation, determinism, tz-mix propagation, and a module source-scan
pin (no chassis import, no clock reads, no exec/eval/network
facilities). No network."""
from __future__ import annotations

import dataclasses
import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.rate_limit import (
    DEFAULT_CAP,
    DEFAULT_WINDOW_SECONDS,
    EVENT_ALLOWED,
    EVENT_BLOCKED,
    RateDecision,
    check,
    scrub_token,
)

UTC = timezone.utc
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock
TOOL = "nmap"
TARGET = "10.0.0.5"


def _fresh(hits=None):
    """New caller-owned store; optional pre-seed for the (TOOL, TARGET) key."""
    store = {}
    if hits is not None:
        store[(TOOL, TARGET)] = list(hits)
    return store


def test_constants_are_pinned():
    assert DEFAULT_CAP == 10
    assert DEFAULT_WINDOW_SECONDS == 60.0
    assert EVENT_ALLOWED == "tool_target_rate_allowed"
    assert EVENT_BLOCKED == "tool_target_rate_blocked"


def test_first_hit_on_fresh_key_is_allowed():
    store = _fresh()
    d = check(store, TOOL, TARGET, BASE, cap=1)
    assert d.allowed is True
    assert d.hits_in_window == 1
    assert d.remaining == 0
    assert store[(TOOL, TARGET)] == [BASE]


def test_counts_below_cap_increment_and_fill():
    store = _fresh()
    d1 = check(store, TOOL, TARGET, BASE, cap=3)
    d2 = check(store, TOOL, TARGET, BASE, cap=3)
    assert (d1.allowed, d1.hits_in_window, d1.remaining) == (True, 1, 2)
    assert (d2.allowed, d2.hits_in_window, d2.remaining) == (True, 2, 1)
    assert store[(TOOL, TARGET)] == [BASE, BASE]


def test_capth_hit_allowed_next_blocked():
    store = _fresh()
    for _ in range(4):
        d = check(store, TOOL, TARGET, BASE, cap=3)
    assert d.allowed is False
    assert d.hits_in_window == 3
    assert d.remaining == 0


def test_allowed_event_exact_shape():
    store = _fresh()
    d = check(store, TOOL, TARGET, BASE, cap=2, window_seconds=90.0)
    assert d.event == {
        "event": EVENT_ALLOWED,
        "tool": TOOL,
        "target": TARGET,
        "cap": 2,
        "window_seconds": 90.0,
        "hits_in_window": 1,
        "remaining": 1,
        "now": BASE.isoformat(),
    }


def test_blocked_event_exact_shape():
    # two real hits (BASE-5s, BASE-2s), then a third check at BASE
    store = _fresh()
    check(store, TOOL, TARGET, BASE - timedelta(seconds=5), cap=2)
    check(store, TOOL, TARGET, BASE - timedelta(seconds=2), cap=2)
    d = check(store, TOOL, TARGET, BASE, cap=2)
    assert d.allowed is False
    assert d.event == {
        "event": EVENT_BLOCKED,
        "tool": TOOL,
        "target": TARGET,
        "cap": 2,
        "window_seconds": 60.0,
        "hits_in_window": 2,
        "retry_at": (BASE + timedelta(seconds=55)).isoformat(),
        "now": BASE.isoformat(),
    }


def test_event_key_order_is_deterministic():
    store = _fresh()
    da = check(store, TOOL, TARGET, BASE, cap=2, window_seconds=90.0)
    assert list(da.event) == [
        "event", "tool", "target", "cap", "window_seconds",
        "hits_in_window", "remaining", "now",
    ]
    store = _fresh([BASE - timedelta(seconds=2)])
    db = check(store, TOOL, TARGET, BASE, cap=1)
    assert db.allowed is False
    assert list(db.event) == [
        "event", "tool", "target", "cap", "window_seconds",
        "hits_in_window", "retry_at", "now",
    ]


def test_hit_exactly_window_old_has_slid_out():
    store = _fresh([BASE])
    d = check(store, TOOL, TARGET, BASE + timedelta(seconds=60), cap=1)
    assert d.allowed is True  # old hit expired AT the boundary (strictly less)
    assert d.event["hits_in_window"] == 1  # only the new hit
    assert store[(TOOL, TARGET)] == [BASE + timedelta(seconds=60)]


def test_hit_just_inside_window_still_counts():
    store = _fresh([BASE])
    just_inside = BASE + timedelta(seconds=59, microseconds=999999)
    d = check(store, TOOL, TARGET, just_inside, cap=1)
    assert d.allowed is False
    assert d.hits_in_window == 1  # the recorded hit, not the attempt
    assert store[(TOOL, TARGET)] == [BASE]  # attempt consumed no quota


def test_blocked_attempts_never_extend_the_block():
    store = _fresh()
    check(store, TOOL, TARGET, BASE, cap=1)  # fills the window
    for offset in (10, 20, 30):
        d = check(store, TOOL, TARGET, BASE + timedelta(seconds=offset), cap=1)
        assert d.allowed is False
        assert d.event["retry_at"] == (BASE + timedelta(seconds=60)).isoformat()
    assert store[(TOOL, TARGET)] == [BASE]  # quota untouched by blocks
    d = check(store, TOOL, TARGET, BASE + timedelta(seconds=60), cap=1)
    assert d.allowed is True  # first slot freed exactly at hit+window


def test_retry_at_uses_earliest_hit_not_bucket_order():
    # pre-seed bucket chronologically out of order (caller-owned state)
    store = _fresh([BASE - timedelta(seconds=30), BASE - timedelta(seconds=45)])
    d = check(store, TOOL, TARGET, BASE, cap=1)
    assert d.allowed is False
    assert d.event["retry_at"] == (BASE + timedelta(seconds=15)).isoformat()


def test_expired_hits_pruned_on_allowed_writeback():
    store = _fresh([BASE - timedelta(seconds=120)])
    d = check(store, TOOL, TARGET, BASE, cap=2)
    assert d.allowed is True
    assert d.hits_in_window == 1
    assert store[(TOOL, TARGET)] == [BASE]  # stale hit pruned


def test_expired_hits_pruned_on_blocked_writeback():
    store = _fresh([BASE - timedelta(seconds=120), BASE - timedelta(seconds=30)])
    d = check(store, TOOL, TARGET, BASE, cap=1)
    assert d.allowed is False
    assert d.event["retry_at"] == (BASE + timedelta(seconds=30)).isoformat()
    assert store[(TOOL, TARGET)] == [BASE - timedelta(seconds=30)]


def test_buckets_are_independent_per_tool_and_target():
    store = _fresh()
    assert check(store, "scan", "t1", BASE, cap=1).allowed is True
    assert check(store, "scan", "t1", BASE, cap=1).allowed is False
    assert check(store, "scan", "t2", BASE, cap=1).allowed is True
    assert check(store, "sweep", "t1", BASE, cap=1).allowed is True
    assert sorted(store) == [("scan", "t1"), ("scan", "t2"), ("sweep", "t1")]
    assert all(len(store[k]) == 1 for k in store)


def test_other_keys_and_lists_untouched():
    other_hits = [BASE - timedelta(seconds=10)]
    store = {(TOOL, TARGET): other_hits}
    check(store, "scan", "t2", BASE, cap=2)
    assert store[(TOOL, TARGET)] is other_hits  # same object
    assert other_hits == [BASE - timedelta(seconds=10)]


def test_caller_bucket_never_mutated_in_place():
    original = [BASE - timedelta(seconds=120), BASE - timedelta(seconds=10)]
    kept = list(original)
    store = _fresh(original)
    check(store, TOOL, TARGET, BASE, cap=1)  # blocked; prunes + writes back
    assert store[(TOOL, TARGET)] is not original
    assert store[(TOOL, TARGET)] == [original[1]]
    assert original == kept  # caller's list object untouched
    store = _fresh(original)
    d = check(store, TOOL, TARGET, BASE, cap=2)  # allowed; appends BASE
    assert d.allowed is True  # in-window: BASE-10 only -> below cap 2
    assert d.event["hits_in_window"] == 2  # BASE-10 + the new hit
    assert store[(TOOL, TARGET)] is not original
    assert store[(TOOL, TARGET)] == [BASE - timedelta(seconds=10), BASE]
    assert original == kept  # caller's list object still untouched


def test_preseeded_bucket_restores_persisted_state():
    hits = [BASE - timedelta(seconds=1), BASE - timedelta(seconds=2)]
    store = _fresh(hits)
    d = check(store, TOOL, TARGET, BASE, cap=2)
    assert d.allowed is False
    assert d.event["hits_in_window"] == 2
    assert d.event["retry_at"] == (BASE + timedelta(seconds=58)).isoformat()
    assert store[(TOOL, TARGET)] == hits  # blocked writeback = pruned same


def test_identical_calls_on_identical_state_yield_identical_events():
    def run():
        store = _fresh([BASE - timedelta(seconds=2)])
        return check(store, TOOL, TARGET, BASE, cap=1, window_seconds=30.0).event
    e1, e2 = run(), run()
    assert e1 == e2
    assert json.dumps(e1) == json.dumps(e2)

    store = _fresh()
    e3 = check(store, TOOL, TARGET, BASE, cap=5, window_seconds=30.0).event
    store2 = _fresh()
    e4 = check(store2, TOOL, TARGET, BASE, cap=5, window_seconds=30.0).event
    assert e3 == e4


@pytest.mark.parametrize("evil", [
    "", "   ", None, 7, "a;ls", "a|b", "a&b", "a$(id)", "a`id`", "a\nb",
    "a\rb", "a<b", "a>b", "a'b", 'a"b', "http://a/b..c", "..",
    "a b", "a\tb",
])
def test_scrub_rejects_hostile_tokens_everywhere(evil):
    for (tool, target) in ((evil, "example.com"), ("nmap", evil)):
        store = _fresh()
        with pytest.raises(ValueError):
            check(store, tool, target, BASE)
    assert store == {}  # rejection happens before any store write


def test_scrub_strips_and_normalizes_tokens():
    store = _fresh()
    d = check(store, TOOL, TARGET, BASE)
    assert store[(TOOL, TARGET)] == [BASE]
    assert d.event["tool"] == "nmap" and d.event["target"] == "10.0.0.5"
    store = _fresh()
    d = check(store, " nmap ", " example.com ", BASE)
    assert ("nmap", "example.com") in store


def test_scrub_token_rejects_directly():
    with pytest.raises(ValueError):
        scrub_token(None, "tool")
    with pytest.raises(ValueError):
        scrub_token("", "target")
    assert scrub_token(" nmap ", "tool") == "nmap"


@pytest.mark.parametrize("bad_cap", [0, -3, 2.5, None, "10", True])
def test_invalid_cap_rejected(bad_cap):
    with pytest.raises(ValueError):
        check(_fresh(), TOOL, TARGET, BASE, cap=bad_cap)


@pytest.mark.parametrize("bad_window", [0, -1.0, None, "60", True, 0.0])
def test_invalid_window_rejected(bad_window):
    with pytest.raises(ValueError):
        check(_fresh(), TOOL, TARGET, BASE, window_seconds=bad_window)


@pytest.mark.parametrize("naive_first", [True, False])
def test_tz_mix_propagates_typeerror(naive_first):
    naive = datetime(2026, 10, 5, 11, 59, 30)
    store = _fresh([naive]) if naive_first else _fresh([BASE])
    now = naive if not naive_first else BASE
    with pytest.raises(TypeError):
        check(store, TOOL, TARGET, now, cap=1)


def test_garbage_hit_propagates_typeerror():
    # recorded bucket values are datetimes by contract; garbage raises
    store = _fresh(["not-a-datetime"])
    with pytest.raises(TypeError):
        check(store, TOOL, TARGET, BASE, cap=1)


def test_decision_is_frozen_dataclass():
    store = _fresh()
    d = check(store, TOOL, TARGET, BASE)
    assert isinstance(d, RateDecision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.allowed = False


def test_module_purity_source_scan():
    # planner-purity by construction: the module never imports the
    # chassis, reads no wall clock, and uses no exec/eval/network/IO
    module = importlib.import_module("agentic_ai.agents.cyber.rate_limit")
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
    assert "requests" not in source
    assert "open(" not in source


def test_no_wall_clock_or_io_calls_in_module():
    module = importlib.import_module("agentic_ai.agents.cyber.rate_limit")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for token in ("datetime.now", "date.today", "time(", "sleep(", "monkeypatch"):
        assert token not in source