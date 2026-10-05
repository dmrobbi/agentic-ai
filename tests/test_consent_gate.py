"""KA-060 tests - consent gate: dry-run pass-by-design, the
missing/malformed/unsigned/mismatched/expired refusal matrix (exact
reason codes), the KA-015 at-and-after expiry boundary (injected
clock), exact refusal-event dict shapes, event==gate reason
consistency across every branch, JSON-serializability, naive/aware
TypeError propagation, record non-mutation/frozen-ness, and the module
purity source-scan. No network."""
from __future__ import annotations

import dataclasses
import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.consent_gate import (
    EVENT_KIND,
    ConsentRecord,
    consent_gate,
    consent_refusal_event,
)

UTC = timezone.utc
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock

ACTION = "tool:live-scan"


def owner_consent(action=ACTION, engagement_id="ENG-1", signed_by="owner",
                  signed_at=None, expires_at=None):
    """A well-formed owner-signed record; overrides per test."""
    return ConsentRecord(
        engagement_id=engagement_id,
        action=action,
        signed_by=signed_by,
        signed_at=(signed_at if signed_at is not None
                   else BASE - timedelta(days=1)),
        expires_at=expires_at,
    )


# --- the house gate shape: (bool, reason) tuple -------------------------


def test_dry_run_passes_without_consent():
    assert consent_gate(ACTION, True, None, BASE) == (
        True, "dry_run_no_consent_required")


def test_dry_run_is_truthiness_coerced():
    assert consent_gate(ACTION, 1, None, BASE) == (
        True, "dry_run_no_consent_required")


def test_dry_run_ignores_consent_state_entirely():
    # by design: even an EXPIRED record cannot change a dry run
    consent = owner_consent(expires_at=BASE - timedelta(days=1))
    assert consent_gate(ACTION, True, consent, BASE) == (
        True, "dry_run_no_consent_required")


def test_real_execution_demands_consent():
    assert consent_gate(ACTION, False, None, BASE) == (
        False, "consent_missing")


@pytest.mark.parametrize("expires_at", [None, BASE + timedelta(hours=1)])
def test_valid_consent_allows_real_execution(expires_at):
    consent = owner_consent(expires_at=expires_at)
    assert consent_gate(ACTION, False, consent, BASE) == (
        True, "consent_valid")


# --- refusal matrix: exact reason codes ---------------------------------


@pytest.mark.parametrize("signed_by", ["", "   ", "\t\n", None])
def test_unsigned_consent_refused(signed_by):
    consent = owner_consent(signed_by=signed_by)
    assert consent_gate(ACTION, False, consent, BASE) == (
        False, "consent_unsigned")


def test_action_mismatch_refused():
    consent = owner_consent(action="recon:dns")
    assert consent_gate("exploit:privesc", False, consent, BASE) == (
        False, "consent_action_mismatch")


def test_action_match_is_exact_not_normalized():
    consent = owner_consent(action="Recon:dns")
    assert consent_gate("recon:dns", False, consent, BASE) == (
        False, "consent_action_mismatch")
    assert consent_gate(" Recon:dns", False, consent, BASE) == (
        False, "consent_action_mismatch")


def test_expiry_boundary_at_expires_at_is_refused():
    # KA-015 "at and after expiry": refused AT the boundary, not only
    # strictly after it
    consent = owner_consent(expires_at=BASE)
    assert consent_gate(ACTION, False, consent, BASE) == (
        False, "consent_expired")


def test_expiry_past_boundary_is_refused():
    consent = owner_consent(expires_at=BASE - timedelta(seconds=1))
    assert consent_gate(ACTION, False, consent, BASE) == (
        False, "consent_expired")


def test_future_expiry_still_allows():
    consent = owner_consent(expires_at=BASE + timedelta(seconds=1))
    assert consent_gate(ACTION, False, consent, BASE) == (
        True, "consent_valid")


# --- caller-contract guards: refuse-closed ------------------------------


@pytest.mark.parametrize("bad_action", ["", "   ", None, 42])
def test_invalid_action_refused_even_for_dry_runs(bad_action):
    for dry_run in (True, False):
        assert consent_gate(bad_action, dry_run, None, BASE) == (
            False, "action_invalid")


def test_invalid_action_beats_consent_and_dry_run():
    consent = owner_consent()
    assert consent_gate("", True, consent, BASE) == (
        False, "action_invalid")
    assert consent_gate("   ", False, consent, BASE) == (
        False, "action_invalid")


MALFORMED = [
    {},
    "not-a-record",
    42,
    # blank engagement scope
    ConsentRecord(engagement_id="", action=ACTION, signed_by="owner",
                  signed_at=BASE),
    # missing signed_at provenance
    ConsentRecord(engagement_id="ENG-1", action=ACTION, signed_by="owner",
                  signed_at=None),
    # non-datetime provenance stamp
    ConsentRecord(engagement_id="ENG-1", action=ACTION, signed_by="owner",
                  signed_at="last tuesday"),
    # non-datetime expiry stamp
    ConsentRecord(engagement_id="ENG-1", action=ACTION, signed_by="owner",
                  signed_at=BASE, expires_at="soon"),
    # garbage action field
    ConsentRecord(engagement_id="ENG-1", action=42, signed_by="owner",
                  signed_at=BASE),
    # garbage signer type (wrong-type signer = broken record, not merely
    # unsigned)
    ConsentRecord(engagement_id="ENG-1", action=ACTION, signed_by=42,
                  signed_at=BASE),
    # multi-garbage: malformation outranks blank signer (precedence pin)
    ConsentRecord(engagement_id="", action=42, signed_by="",
                  signed_at=BASE),
]


@pytest.mark.parametrize("bad_consent", MALFORMED, ids=range(len(MALFORMED)))
def test_malformed_consent_refused(bad_consent):
    assert consent_gate(ACTION, False, bad_consent, BASE) == (
        False, "consent_malformed")


# --- the record type -----------------------------------------------------


def test_record_requires_signed_at_provenance():
    with pytest.raises(TypeError):
        ConsentRecord(engagement_id="ENG-1", action=ACTION,
                      signed_by="owner")


def test_consent_record_is_frozen():
    consent = owner_consent()
    with pytest.raises(dataclasses.FrozenInstanceError):
        consent.signed_by = "attacker"


def test_gate_does_not_mutate_the_consent():
    consent = owner_consent(expires_at=BASE - timedelta(days=1))
    consent_gate(ACTION, False, consent, BASE)
    consent_gate(ACTION, True, consent, BASE)
    assert consent.engagement_id == "ENG-1"
    assert consent.action == ACTION
    assert consent.signed_by == "owner"
    assert consent.expires_at == BASE - timedelta(days=1)


# --- the refusal, audited ------------------------------------------------


def test_refusal_event_exact_shape_expired():
    consent = owner_consent(expires_at=BASE)
    ok, reason = consent_gate(ACTION, False, consent, BASE)
    assert (ok, reason) == (False, "consent_expired")
    event = consent_refusal_event(ACTION, False, consent, BASE)
    assert event == {
        "event": "execution_consent_refused",
        "action": ACTION,
        "dry_run": False,
        "engagement_id": "ENG-1",
        "signed_by": "owner",
        "signed_at": (BASE - timedelta(days=1)).isoformat(),
        "expires_at": BASE.isoformat(),
        "reason": "consent_expired",
        "checked_at": BASE.isoformat(),
    }


def test_refusal_event_exact_shape_missing_consent():
    ok, reason = consent_gate(ACTION, False, None, BASE)
    assert (ok, reason) == (False, "consent_missing")
    assert consent_refusal_event(ACTION, False, None, BASE) == {
        "event": "execution_consent_refused",
        "action": ACTION,
        "dry_run": False,
        "engagement_id": None,
        "signed_by": None,
        "signed_at": None,
        "expires_at": None,
        "reason": "consent_missing",
        "checked_at": BASE.isoformat(),
    }


def test_refusal_event_exact_shape_unsigned():
    consent = owner_consent(signed_by="")
    assert consent_gate(ACTION, False, consent, BASE) == (
        False, "consent_unsigned")
    assert consent_refusal_event(ACTION, False, consent, BASE) == {
        "event": "execution_consent_refused",
        "action": ACTION,
        "dry_run": False,
        "engagement_id": "ENG-1",
        "signed_by": "",
        "signed_at": (BASE - timedelta(days=1)).isoformat(),
        "expires_at": None,
        "reason": "consent_unsigned",
        "checked_at": BASE.isoformat(),
    }


def test_refusal_event_for_invalid_action_echoes_repr():
    event = consent_refusal_event(42, True, None, BASE)
    assert event == {
        "event": "execution_consent_refused",
        "action": "42",
        "dry_run": True,
        "engagement_id": None,
        "signed_by": None,
        "signed_at": None,
        "expires_at": None,
        "reason": "action_invalid",
        "checked_at": BASE.isoformat(),
    }


def test_refusal_event_never_echoes_malformed_consent():
    consent = {"engagement_id": "ENG-1"}  # dict-shaped "consent"
    event = consent_refusal_event(ACTION, False, consent, BASE)
    assert event["reason"] == "consent_malformed"
    assert event["engagement_id"] is None
    assert event["signed_by"] is None
    assert event["signed_at"] is None
    assert event["expires_at"] is None


def test_allowed_execution_has_no_event():
    assert consent_refusal_event(ACTION, True, None, BASE) is None
    consent = owner_consent(expires_at=BASE + timedelta(days=1))
    assert consent_refusal_event(ACTION, False, consent, BASE) is None


def _refusal_branches():
    """Every refusal branch, one case each (label, action, dry_run,
    consent)."""
    valid = owner_consent()
    unsigned = owner_consent(signed_by="")
    mismatched = owner_consent(action="recon:dns")
    expired = owner_consent(expires_at=BASE - timedelta(hours=1))
    malformed = {"engagement_id": "ENG-1"}
    return [
        ("missing", ACTION, False, None),
        ("malformed", ACTION, False, malformed),
        ("unsigned", ACTION, False, unsigned),
        ("mismatch", "exploit:privesc", False, mismatched),
        ("expired", ACTION, False, expired),
        ("invalid-action", "", False, valid),
        ("invalid-action-dry", "", True, valid),
    ]


@pytest.mark.parametrize("label,action,dry_run,consent", _refusal_branches(),
                         ids=[b[0] for b in _refusal_branches()])
def test_event_reason_and_kind_match_the_gate(label, action, dry_run, consent):
    ok, reason = consent_gate(action, dry_run, consent, BASE)
    assert ok is False  # every listed branch is a refusal
    event = consent_refusal_event(action, dry_run, consent, BASE)
    assert isinstance(event, dict)
    assert event["event"] == EVENT_KIND
    assert event["reason"] == reason
    assert event["action"] == action  # echo of the requested action


@pytest.mark.parametrize("label,action,dry_run,consent", _refusal_branches(),
                         ids=[b[0] for b in _refusal_branches()])
def test_refusal_events_are_json_serializable(label, action, dry_run, consent):
    event = consent_refusal_event(action, dry_run, consent, BASE)
    assert json.dumps(event)  # no TypeError/ValueError raised


# --- injected-clock contract ---------------------------------------------


def test_naive_aware_expiry_mix_propagates_typeerror():
    # documented caller contract (as in auth_expiry): a naive expires_at
    # against an aware `now` raises TypeError straight up
    consent = owner_consent(
        expires_at=datetime(2026, 10, 5, 12, 0, 0))  # naive
    with pytest.raises(TypeError):
        consent_gate(ACTION, False, consent, BASE)  # aware now


# --- planner purity ------------------------------------------------------


def test_module_purity_source_scan():
    # planner purity by construction: no chassis import, no wall clock,
    # no process/eval facilities, no network facilities
    module = importlib.import_module("agentic_ai.agents.cyber.consent_gate")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in ("from agentic_ai", "import agentic_ai",
                      "utcnow", "time.time", "today()",
                      "subprocess", "popen", "os.system",
                      "eval(", "exec(",
                      "urllib", "socket", "requests", "http.client"):
        assert forbidden not in source, forbidden


def test_result_values_survive_json_roundtrip():
    # the gate's own (bool, reason) payload is plain JSON-safe too
    ok, reason = consent_gate(ACTION, False, None, BASE)
    assert json.dumps({"ok": ok, "reason": reason}) == (
        '{"ok": false, "reason": "consent_missing"}')
    ok, reason = consent_gate(ACTION, True, None, BASE)
    assert json.dumps({"ok": ok, "reason": reason}) == (
        '{"ok": true, "reason": "dry_run_no_consent_required"}')