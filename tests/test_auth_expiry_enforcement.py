"""KA-015 - authorization-expiry enforcement pins (the INT-1 wiring):

The enforcement exists since KA-INT-1: set_authorization stores
expires_at per engagement, revoke clears it, and check_authorization
sweeps expired engagements with one audit event per revocation. These
pins prove the ENFORCEMENT inside the EXECUTION path with the boundary
times the todo names (at expiry, past, future, never).

Documented quirk (pinned): the GLOBAL authorization level cannot carry
an expiry in v1 - set_authorization accepts expires_at only per
engagement, so a global expiry is silently unused.

No network; the subprocess layer is stubbed like KA-006."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent
from agentic_ai.agents.cyber.consent_gate import ConsentRecord
from agentic_ai.agents.cyber.auth_expiry import EVENT_KIND
from agentic_ai.infrastructure.utils import utcnow

MIMIKATZ_ARGS = {"command": "dump"}
FUTURE = timedelta(seconds=3600)
PAST = timedelta(seconds=-5)


@pytest.fixture()
def agent(tmp_path):
    a = KaliAgent(agent_id="ka015", workspace=str(tmp_path / "ws"),
                  log_dir=str(tmp_path / "logs"))
    a.disable_safe_mode()  # this pins the EXPIRY enforcement, not KA-061
    # KA-INT-4: standing consent + staged posture for these real executions
    a.attach_consent(ConsentRecord(engagement_id="E1", action="mimikatz",
                                   signed_by="owner", signed_at=utcnow()))
    a.lab_staged = True
    a.auth_tags = ("EGRESS-AUTH",)
    return a


def _stub_subprocess(monkeypatch, rc=0, out=b"dumped"):
    class _FakeTimeoutExpired(Exception):
        pass

    class _Proc:
        def __init__(self, cmd_args):
            self.killed = False
            self.returncode = rc

        def communicate(self, timeout=None):
            return out, b""

        def kill(self):
            self.killed = True

    def ctor(cmd_args, **kwargs):
        return _Proc(cmd_args)

    stub = SimpleNamespace(Popen=ctor, TimeoutExpired=_FakeTimeoutExpired,
                           PIPE=None, STDOUT=None, DEVNULL=None)
    monkeypatch.setattr("agentic_ai.agents.cyber.kali.subprocess", stub)
    return None


def _authorize(agent, expires_at):
    ok = agent.set_authorization(
        AuthorizationLevel.CRITICAL, engagement_id="E1", expires_at=expires_at)
    assert ok is True


def test_future_expiry_executes(agent, monkeypatch):
    _stub_subprocess(monkeypatch)
    _authorize(agent, utcnow() + FUTURE)
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "completed"
    assert agent.engagement_authorizations.get("E1") == (
        AuthorizationLevel.CRITICAL)


def test_at_expiry_boundary_revoked_in_execution_path(agent, monkeypatch):
    """Revoked AT expiry (now >= expires_at): the execution path consult
    drops it exactly on the boundary."""
    _stub_subprocess(monkeypatch)
    _authorize(agent, utcnow() + timedelta(hours=1))
    # simulate elapsed time: set_authorization refuses past expiries, so
    # the boundary is exercised by overwriting the stored expiry
    agent.engagement_auth_expiry["E1"] = utcnow()
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "failed"
    assert "Authorization level 3 required, have 0" in result.stderr
    assert "E1" not in agent.engagement_authorizations
    assert "E1" not in agent.engagement_auth_expiry


def test_past_expiry_revoked_in_execution_path(agent, monkeypatch):
    _stub_subprocess(monkeypatch)
    _authorize(agent, utcnow() + timedelta(hours=1))
    agent.engagement_auth_expiry["E1"] = utcnow() + PAST
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "failed"
    assert "E1" not in agent.engagement_authorizations


def test_audit_event_through_execution_path(agent, monkeypatch):
    _stub_subprocess(monkeypatch)
    _authorize(agent, utcnow() + timedelta(hours=1))
    agent.engagement_auth_expiry["E1"] = utcnow() + PAST
    agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    lines = (Path(agent.log_dir) / "audit_log.jsonl").read_text().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["event"] == EVENT_KIND and event["engagement_id"] == "E1"


def test_expired_sibling_survivor_mix(agent, monkeypatch):
    """One expired + one valid CRITICAL engagement: the sweep drops the
    expired one; the survivor keeps the flow authorized."""
    _stub_subprocess(monkeypatch)
    agent.set_authorization(AuthorizationLevel.CRITICAL,
                            engagement_id="E-GONE",
                            expires_at=utcnow() + timedelta(hours=1))
    agent.set_authorization(AuthorizationLevel.CRITICAL,
                            engagement_id="E-KEPT",
                            expires_at=utcnow() + timedelta(hours=2))
    agent.engagement_auth_expiry["E-GONE"] = utcnow() + PAST
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "completed"
    assert "E-GONE" not in agent.engagement_authorizations
    assert agent.engagement_authorizations.get("E-KEPT") == (
        AuthorizationLevel.CRITICAL)


def test_never_expiring_engagement(agent, monkeypatch):
    _stub_subprocess(monkeypatch)
    ok = agent.set_authorization(
        AuthorizationLevel.CRITICAL, engagement_id="E-FOREVER", expires_at=None)
    assert ok is True
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "completed"
    assert "E-FOREVER" in agent.engagement_authorizations


def test_global_authorization_cannot_carry_expiry(agent, monkeypatch):
    """Documented quirk: global expiry is silently unused in v1 - the
    stored expiry dict stays empty and the global level applies."""
    _stub_subprocess(monkeypatch)
    ok = agent.set_authorization(
        AuthorizationLevel.CRITICAL, expires_at=utcnow() + timedelta(hours=1))
    assert ok is True
    assert agent.engagement_auth_expiry == {}  # nothing stored: the quirk
    assert agent.authorization_level == AuthorizationLevel.CRITICAL
    result = agent.execute_tool("mimikatz", dict(MIMIKATZ_ARGS))
    assert result.status == "completed"
