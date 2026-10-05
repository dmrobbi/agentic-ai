"""KA-058 tests - rollback contract: the pinned fail-closed mutating
classifier, the complete-undo requirement plan-level enforcement,
precise deterministic rejection reasons and house audit-event shapes,
dict-form step/undo equivalence, non-mutation purity, structural
errors, and a module source-scan pin (no chassis import, no clock
reads, no exec/eval facilities, no network markers). No network."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.rollback_plan import (
    CATEGORY_NAMES,
    EVENT_KIND,
    KNOWN_CATEGORIES,
    MUTATING_CATEGORIES,
    READ_ONLY_CATEGORIES,
    PlanStep,
    UndoAction,
    classify_step,
    rollback_report,
    validate_plan,
)

UNDO = UndoAction("restore_user", {"user": "svc-1"}, "id svc-1 exits 2")

_NO_MUTATING_REASONS = ("Rollback contract satisfied: no mutating steps "
                        "(nothing requires undo)")
_ONE_UNDO_REASON = ("Rollback contract satisfied: 1 mutating step(s) "
                    "with declared undo")


# ---------------------------------------------------------------- classifier


@pytest.mark.parametrize("category", sorted(MUTATING_CATEGORIES) + [None])
def test_classify_step_mutating(category):
    assert classify_step(PlanStep("op", category)) is True


@pytest.mark.parametrize("category", sorted(READ_ONLY_CATEGORIES))
def test_classify_step_readonly(category):
    assert classify_step(PlanStep("op", category)) is False


def test_classify_step_accepts_mapping_form():
    assert classify_step({"name": "op", "category": "scan"}) is False
    assert classify_step({"name": "op", "category": "delete"}) is True


def test_undeclared_category_is_mutating_fail_closed():
    # the planner never declared what the op touches -> undo REQUIRED
    ok, reason = validate_plan([PlanStep("mystery_op")])
    assert (ok, reason) == (False, "Rejected: mutating step 0 "
                                   "(mystery_op) requires a declared "
                                   "undo - none present")


def test_unknown_category_is_deterministic_valueerror():
    plan = [PlanStep("op", "teleport")]
    with pytest.raises(ValueError) as first:
        rollback_report(plan)
    message = str(first.value)
    assert "teleport" in message
    assert "known categories" in message
    with pytest.raises(ValueError):
        rollback_report(list(plan))
    assert str(first.value) == message  # deterministic, no set-order drift


@pytest.mark.parametrize("category", sorted(MUTATING_CATEGORIES))
def test_every_mutating_category_requires_undo(category):
    ok, reason = validate_plan([PlanStep("op", category)])
    assert ok is False
    assert reason == ("Rejected: mutating step 0 (op) requires a "
                      "declared undo - none present")


@pytest.mark.parametrize("category", sorted(READ_ONLY_CATEGORIES))
def test_readonly_categories_are_exempt(category):
    ok, reason = validate_plan([PlanStep("op", category)])
    assert (ok, reason) == (True, _NO_MUTATING_REASONS)


def test_category_taxonomy_pinned():
    assert READ_ONLY_CATEGORIES == frozenset(
        {"recon", "scan", "inspect", "read", "verify", "monitor"})
    assert MUTATING_CATEGORIES == frozenset(
        {"execute", "write", "create", "modify", "delete",
         "deploy", "exploit", "persist", "reconfigure"})
    assert KNOWN_CATEGORIES == READ_ONLY_CATEGORIES | MUTATING_CATEGORIES
    assert CATEGORY_NAMES == tuple(sorted(KNOWN_CATEGORIES))


def test_event_kind_pinned():
    assert EVENT_KIND == "rollback_contract_rejected"


# ------------------------------------------------------- the contract


def test_readonly_only_plan_is_accepted():
    steps = [PlanStep("nmap_scan", "scan"), PlanStep("osint_read", "read")]
    ok, reason = validate_plan(steps)
    assert (ok, reason) == (True, _NO_MUTATING_REASONS)
    report = rollback_report(steps)
    assert report["ok"] is True
    assert report["events"] == []
    assert report["steps_total"] == 2
    assert report["mutating_steps"] == 0
    assert set(report) == {"ok", "reason", "events", "steps_total",
                           "mutating_steps"}


def test_mutating_step_without_undo_is_rejected():
    steps = [PlanStep("nmap_scan", "scan"), PlanStep("rm_user", "delete")]
    ok, reason = validate_plan(steps)
    assert (ok, reason) == (False, "Rejected: mutating step 1 (rm_user) "
                                   "requires a declared undo - none "
                                   "present")
    report = rollback_report(steps)
    assert report["events"][0] == {
        "event": EVENT_KIND,
        "engagement_id": None,
        "step_index": 1,
        "step_name": "rm_user",
        "reason": reason,
    }
    assert len(report["events"]) == 1
    assert report["steps_total"] == 2
    assert report["mutating_steps"] == 1


def test_complete_undo_satisfies_contract():
    steps = [
        PlanStep("nmap_scan", "scan"),
        PlanStep("create_user", "modify", undo=UNDO),
        PlanStep("read_state", "read"),
    ]
    ok, reason = validate_plan(steps)
    assert (ok, reason) == (True, _ONE_UNDO_REASON)
    report = rollback_report(steps)
    assert report == {"ok": True, "reason": reason, "events": [],
                      "steps_total": 3, "mutating_steps": 1}


def test_undo_args_may_be_an_empty_mapping():
    # fully declared argless inverse: args={} is complete, NOT incomplete
    undo = UndoAction("restore_default_config", {}, "config diff is empty")
    ok, reason = validate_plan(
        [PlanStep("set_config", "reconfigure", undo=undo)])
    assert (ok, reason) == (True, _ONE_UNDO_REASON)


REJECTION_CASES = [
    ("not_structured", "a bare string is not an undo plan",
     "Rejected: undo for mutating step 0 (rm_user) is not a structured "
     "undo plan"),
    ("no_action", {"args": {"user": "u"}, "verify": "grep"},
     "Rejected: undo for mutating step 0 (rm_user) does not declare an "
     "inverse action"),
    ("blank_action", {"action": "   ", "args": {}, "verify": "grep"},
     "Rejected: undo for mutating step 0 (rm_user) does not declare an "
     "inverse action"),
    ("no_args", {"action": "restore_user", "verify": "grep"},
     "Rejected: undo for mutating step 0 (rm_user) does not declare "
     "inverse arguments"),
    ("args_wrong_type", {"action": "restore_user", "args": ["u"],
                         "verify": "grep"},
     "Rejected: undo for mutating step 0 (rm_user) does not declare "
     "inverse arguments"),
    ("no_verify", {"action": "restore_user", "args": {}},
     "Rejected: undo for mutating step 0 (rm_user) does not declare a "
     "verification check"),
    ("blank_verify", {"action": "restore_user", "args": {},
                      "verify": "  "},
     "Rejected: undo for mutating step 0 (rm_user) does not declare a "
     "verification check"),
]


@pytest.mark.parametrize("label,undo,expected", REJECTION_CASES,
                         ids=[case[0] for case in REJECTION_CASES])
def test_incomplete_undo_has_one_precise_reason(label, undo, expected):
    steps = [PlanStep("rm_user", "delete", undo=undo)]
    ok, reason = validate_plan(steps)
    assert (ok, reason) == (False, expected)
    report = rollback_report(steps)
    assert len(report["events"]) == 1
    assert report["events"][0]["reason"] == expected
    assert report["reason"] == expected


def test_undo_mapping_extra_keys_are_absorbed():
    undo = {"action": "restore_user", "args": {"user": "u"},
            "verify": "id u exits 2", "note": "unknown key absorbed"}
    ok, reason = validate_plan([PlanStep("rm_user", "delete", undo=undo)])
    assert (ok, reason) == (True, _ONE_UNDO_REASON)


def test_step_mapping_extra_keys_are_absorbed():
    steps = [{"name": "rm_user", "category": "delete", "undo": dict(
        action="restore_user", args={}, verify="ok",
        priority="absorbed")}]
    ok, _ = validate_plan(steps)
    assert ok is True


def test_malformed_undo_on_readonly_step_is_not_required_nor_validated():
    # the contract binds mutating steps only
    ok, reason = validate_plan(
        [PlanStep("nmap_scan", "scan", undo="garbage")])
    assert (ok, reason) == (True, _NO_MUTATING_REASONS)


def test_first_violation_is_deterministic_and_each_offender_gets_an_event():
    bad_undo = {"action": "restore_u"}  # incomplete: no args, no verify
    steps = [
        PlanStep("nmap_scan", "scan"),
        PlanStep("op_a", "write"),                         # idx 1: missing
        PlanStep("op_b", "write"),                         # idx 2: missing
        PlanStep("op_c", "write", undo=bad_undo),          # idx 3: partial
        PlanStep("read_state", "read"),
    ]
    ok, reason = validate_plan(steps)
    assert ok is False
    assert reason == ("Rejected: mutating step 1 (op_a) requires a "
                      "declared undo - none present")
    report = rollback_report(steps)
    assert [event["step_index"] for event in report["events"]] == [1, 2, 3]
    assert [event["step_name"] for event in report["events"]] == [
        "op_a", "op_b", "op_c"]
    assert report["events"][2]["reason"] == (
        "Rejected: undo for mutating step 3 (op_c) does not declare "
        "inverse arguments")
    assert report["steps_total"] == 5
    assert report["mutating_steps"] == 3


def test_reason_strings_are_stable_across_calls():
    plan = [PlanStep("op", "delete")]
    assert validate_plan(plan) == validate_plan(list(plan))


# ------------------------------------------------------- dict-form plans


def test_dict_form_steps_and_undo_match_dataclass_form():
    dict_steps = [
        {"name": "nmap_scan", "category": "scan"},
        {"name": "rm_user", "category": "delete",
         "undo": {"action": "restore_user", "args": {"user": "svc-1"},
                  "verify": "id svc-1 exits 2"}},
        {"name": "read_state", "category": "read",
         "note": "unknown key absorbed"},
    ]
    dc_steps = [
        PlanStep("nmap_scan", "scan"),
        PlanStep("rm_user", "delete",
                 undo=UndoAction("restore_user", {"user": "svc-1"},
                                 "id svc-1 exits 2")),
        PlanStep("read_state", "read"),
    ]
    assert validate_plan(dict_steps) == validate_plan(dc_steps)
    assert (validate_plan(dict_steps)
            == (True, _ONE_UNDO_REASON))
    assert rollback_report(dict_steps) == rollback_report(dc_steps)


def test_steps_may_be_a_generator():
    steps = [PlanStep("nmap_scan", "scan")]
    assert validate_plan(iter(steps)) == validate_plan(steps)


def test_empty_plan_is_accepted():
    assert validate_plan([]) == (True, _NO_MUTATING_REASONS)
    assert rollback_report([]) == {
        "ok": True,
        "reason": _NO_MUTATING_REASONS,
        "events": [],
        "steps_total": 0,
        "mutating_steps": 0,
    }


def test_validate_plan_is_the_report_projection():
    plans = [
        [],
        [PlanStep("nmap_scan", "scan")],
        [PlanStep("rm_user", "delete")],
        [PlanStep("rm_user", "delete", undo=UNDO)],
    ]
    for plan in plans:
        report = rollback_report(plan)
        assert validate_plan(plan) == (report["ok"], report["reason"])


def test_event_carries_the_scrubbed_engagement_id():
    report = rollback_report([{"name": "rm_user", "category": "delete"}],
                             engagement_id="  ENG-7  ")
    assert report["events"][0]["engagement_id"] == "ENG-7"


# ------------------------------------------------------------- purity


def test_inputs_are_not_mutated():
    undo = {"action": "restore_user", "args": {"user": "svc-1"},
            "verify": "id svc-1 exits 2"}
    steps = [{"name": "rm_user", "category": "delete", "undo": undo,
              "note": "kept"}]
    snapshot = repr(steps)
    rollback_report(steps, engagement_id="ENG-9")
    assert repr(steps) == snapshot


def test_structural_errors_are_exceptions_not_rejections():
    with pytest.raises(TypeError):
        rollback_report(42)
    with pytest.raises(TypeError):
        rollback_report(["not-a-step"])
    with pytest.raises(TypeError):
        rollback_report([{"name": 123, "category": "delete"}])
    with pytest.raises(ValueError):
        rollback_report([{"category": "delete"}])  # no name declared
    with pytest.raises(ValueError):
        rollback_report([{"name": "   ", "category": "delete"}])
    with pytest.raises(TypeError):
        rollback_report([PlanStep("op", "delete")], engagement_id=5)


def test_module_purity_source_scan():
    # planner-purity by construction: the module never imports the
    # chassis, reads no wall clock, and uses no exec/eval facilities
    # or network surfaces
    module = importlib.import_module("agentic_ai.agents.cyber.rollback_plan")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for marker in (
            "from agentic_ai", "import agentic_ai", "subprocess",
            "os.system", "eval(", "socket", "urllib", "http.client",
            "requests", "utcnow", "time.time", "datetime.now"):
        assert marker not in source, marker