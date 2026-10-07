"""KA-INT-5 wiring: the P5 fleet bridges on both chassis.

Default-OFF: every flagged fleet-bridge op refuses with the flag_off
dict until the environment carries KA_FLEET_BRIDGES=1 (consulted per
call, never cached). With the flag raised the ops are thin
delegations; this file smokes each delegation path with the same
minimal shapes the owning tasks' tests pin, and proves payload
pass-through through the fixture-backed planners.
"""
from datetime import datetime, timezone
from pathlib import Path
import json

import pytest

from agentic_ai.agents.registry import create_agent

FLAG = "KA_FLEET_BRIDGES"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

AGING_REPORT = json.loads(
    (FIXTURES / "scans" / "patch_report_shape.json").read_text(encoding="utf-8")
)["report"]
NEWSROOM_FEED = json.loads(
    (FIXTURES / "scans" / "newsroom_feed.json").read_text(encoding="utf-8")
)["feed"]
LAYA_ROWS = json.loads(
    (FIXTURES / "findings" / "laya_decision_rows.json").read_text(encoding="utf-8")
)["rows"]

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)

ENGAGEMENT = {
    "engagement_id": "ENG-INT5",
    "target": "wks-a01.lab.example",
    "findings": [
        {"id": "F-01", "summary": "SMBv1 enabled on the host",
         "severity": "high"},
    ],
}

FAILURES = [
    {"verification_id": "V-INT5", "host": "lab-a", "control_id": "CTL-1"},
]

SUMMARIES = [
    {
        "tenant_id": "tenant-a",
        "engagement_id": "ENG-INT5",
        "summary": "Pilot engagement delivered and verified",
    },
]

REPORT = {
    "engagement_id": "ENG-INT5",
    "target": "10.44.0.20",
    "title": "Int-5 wiring smoke",
    "findings": [
        {"id": "F-001", "severity": "high",
         "summary": "reflected xss in search"},
    ],
    "notes": "wiring smoke run",
}

BATTERY_RUN = {
    "battery_id": "BAT-INT5",
    "completed": 29,
    "failed": 0,
    "target": "lab-a",
}

OPS = {
    "aging_exploit_queue": (AGING_REPORT,),
    "plan_engagement_tickets": (ENGAGEMENT, NOW),
    "plan_remediation_tickets": (FAILURES, NOW),
    "verify_laya_decisions": (LAYA_ROWS,),
    "build_threat_brief": (NEWSROOM_FEED,),
    "push_soc_memories": (SUMMARIES,),
    "compose_report_email": (REPORT,),
    "compose_battery_notification": (BATTERY_RUN,),
}

OP_NAMES = tuple(OPS)


def refusal(op):
    return {"status": "flag_off", "op": op, "flag": FLAG}


@pytest.fixture(params=["kali", "kali_v2"])
def agent(request):
    return create_agent(request.param)


@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setenv(FLAG, "1")


@pytest.fixture
def flag_off(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


# --- default OFF: every op refuses with the same dict shape ---------------


@pytest.mark.parametrize("op", OP_NAMES)
def test_wiring_default_off(agent, flag_off, op):
    result = getattr(agent, op)(*OPS[op])
    assert result == refusal(op)


# --- the flag is consulted per call, never cached --------------------------


@pytest.mark.parametrize("agent_id", ["kali", "kali_v2"])
def test_flag_is_consulted_per_call(agent_id, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    agent = create_agent(agent_id)
    assert agent.verify_laya_decisions() == refusal("verify_laya_decisions")
    monkeypatch.setenv(FLAG, "1")
    on = agent.verify_laya_decisions()
    assert isinstance(on, dict)
    assert on != refusal("verify_laya_decisions")


# --- flag ON: thin delegation payloads pass through ------------------------


def test_flag_on_aging_queue(agent, flag_on):
    q = agent.aging_exploit_queue(AGING_REPORT)
    assert q["counts"]["unpatched"] == 10
    assert len(q["queue"]) >= 1


def test_flag_on_engagement_tickets(agent, flag_on):
    bundle = agent.plan_engagement_tickets(ENGAGEMENT, NOW)
    assert bundle["summary"] == {
        "total": 1, "tickets": 1, "skipped": 0, "already_resolved": 0}


def test_flag_on_remediation_tickets(agent, flag_on):
    plan = agent.plan_remediation_tickets(FAILURES, NOW)
    assert plan["summary"]["verifications"] == 1


def test_flag_on_laya_verify(agent, flag_on):
    result = agent.verify_laya_decisions(LAYA_ROWS)
    assert isinstance(result, dict)
    assert result != refusal("verify_laya_decisions")


def test_flag_on_threat_brief(agent, flag_on):
    brief = agent.build_threat_brief(NEWSROOM_FEED)
    assert brief["counts"]["usable"] >= 1


def test_flag_on_soc_memories(agent, flag_on):
    pushed = agent.push_soc_memories(SUMMARIES)
    assert pushed["summary"]["built"] == 1


def test_flag_on_report_email(agent, flag_on):
    composed = agent.compose_report_email(
        REPORT, recipient="owner@lab.example")
    assert isinstance(composed, dict)
    assert composed != refusal("compose_report_email")


def test_flag_on_battery_notification(agent, flag_on):
    composed = agent.compose_battery_notification(
        BATTERY_RUN, recipient="owner@lab.example")
    assert isinstance(composed, dict)
    assert composed != refusal("compose_battery_notification")


# --- the wiring adds no execution surface (the ban list holds) --------------


def test_flag_gates_guard_pure_delegation(agent, flag_off):
    # a flag-off op must not even construct module state: refusal only
    from agentic_ai.agents.cyber import laya_verify

    class ExplodingVerifier:
        def __init__(self, *a, **k):
            raise AssertionError("constructed while flag off")

    original = laya_verify.LayaVerifier
    laya_verify.LayaVerifier = ExplodingVerifier
    try:
        assert agent.verify_laya_decisions() == refusal(
            "verify_laya_decisions")
    finally:
        laya_verify.LayaVerifier = original
