"""KA-061 - safe-mode proof.

The todo's acceptance allows either a green proof or a red test + proposal
when a REAL bug is proven. The proof ran; the bug is proven: the v1 chassis
never reads self.safe_mode during execute_tool (the flag appears exactly
three times in kali.py - its __init__ + the enable/disable toggles), and
ExecutionMode / safe_by_default are equally unconsulted safety signals.

RESOLUTION: KA-INT-1 implemented the gate in kali.py
(SAFE_MODE_BLOCKED_CATEGORIES consulted between authorization and the
target stage; refusal stderr names safe mode; zero process
construction on refusal). The xfail marker is REMOVED - this file now
pins the enforcement as live behavior.

PROPOSAL (a KA-INT-1 decision, not a builder fix):
  Under safe_mode=True, execute_tool MUST refuse mutation-class tools
  BEFORE any process construction - returning a failed ToolExecution whose
  stderr names safe mode. Proposed mutation-class source data (live DB):
  tool category in {POST_EXPLOITATION, EXPLOITATION, MALWARE,
  SOCIAL_ENGINEERING} - 9 of the 52 tools today. Read/scan categories keep
  passing. safe_by_default cannot be the gate: it is uniform True across
  the DB and never read.
  WHEN ENFORCEMENT LANDS (KA-INT-1): remove this xfail marker in the SAME
  commit, and flip test_current_behavior_safe_mode_never_consulted to the
  blocked expectation.

No network; all process layer stubbed like KA-006."""
from __future__ import annotations
import datetime as dt

from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.consent_gate import ConsentRecord
from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KALI_TOOLS_DB,
    KaliAgent,
)

BENIGN_TARGET = "192.0.2.1"
MUTATION_CATEGORIES = {
    "POST_EXPLOITATION",
    "EXPLOITATION",
    "MALWARE",
    "SOCIAL_ENGINEERING",
}


class _FakeTimeoutExpired(Exception):
    pass


def _stub_subprocess(monkeypatch, *, rc=0, out=b"", err=b""):
    calls = []
    procs = []

    class _Proc:
        def __init__(self, cmd_args):
            self._cmd_args = cmd_args
            self.killed = False
            self.returncode = rc

        def communicate(self, timeout=None):
            if out is None and err is None:
                raise _FakeTimeoutExpired()
            return out, err

        def kill(self):
            self.killed = True

    def ctor(cmd_args, **kwargs):
        calls.append(list(cmd_args))
        proc = _Proc(cmd_args)
        procs.append(proc)
        return proc

    stub = SimpleNamespace(
        Popen=ctor,
        TimeoutExpired=_FakeTimeoutExpired,
        PIPE=None, STDOUT=None, DEVNULL=None,
    )
    monkeypatch.setattr("agentic_ai.agents.cyber.kali.subprocess", stub)
    return calls, procs


def _real_agent(tmp_path, level):
    agent = KaliAgent(
        agent_id="ka061-safe-mode",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "logs"),
    )
    agent.set_authorization(level)
    # KA-INT-4: standing consent + egress posture (harmless behind the
    # pre-chain safe-mode wall; lets read/scan flows reach the exec gate)
    agent.lab_staged = True
    agent.auth_tags = ("EGRESS-AUTH",)
    agent.attach_consent(ConsentRecord(engagement_id="e", action="nmap",
                                       signed_by="owner",
                                       signed_at=dt.datetime(2026, 10, 5, 12, 0,
                                       tzinfo=dt.timezone.utc)))
    return agent  # safe_mode defaults True - the state under proof


def test_safe_mode_blocks_before_any_process(tmp_path, monkeypatch):
    # RESOLVED AT KA-INT-1: the gate fires after authorization and
    # before any validation or process construction.
    calls, _procs = _stub_subprocess(monkeypatch)
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    assert agent.safe_mode is True
    result = agent.execute_tool("mimikatz", {"command": "dump"})
    assert result.status == "failed"
    assert "safe mode" in result.stderr.lower()
    assert calls == []                       # zero process construction


def test_proposed_safe_mode_blocks_mutation_class(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch)
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    result = agent.execute_tool("mimikatz", {"command": "dump"})
    assert result.status == "failed"                    # refused
    assert "safe mode" in result.stderr.lower()         # refusal names it
    assert calls == []                                  # before any process


def test_read_scan_class_let_through_under_safe_mode(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch, rc=0, out=b"scan out")
    agent = _real_agent(tmp_path, AuthorizationLevel.BASIC)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"  # scans pass the gate (true today,
    assert len(calls) == 1 and calls[0][0] == "nmap"     # true per proposal)


def test_safe_mode_gate_precedes_target_validation(tmp_path, monkeypatch):
    # the gate is stage 1.5: the safe-mode refusal names itself even
    # when the same call would ALSO fail target validation (bloodhound
    # carries a domain field -> both gates in flight; safe mode wins,
    # which also proves the gate runs BEFORE the target stage).
    _stub_subprocess(monkeypatch)
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    agent.set_ip_whitelist(["192.0.2.1"])
    result = agent.execute_tool(
        "bloodhound",
        {"domain": "192.0.2.66", "username": "x", "password": "x"})
    assert result.status == "failed"
    assert "safe mode" in result.stderr.lower()
    assert "not in whitelist" not in result.stderr


def test_mutation_class_source_data_from_db():
    # the proposal's classification is grounded in the LIVE DB at curation
    mutation = sorted(
        n for n, t in KALI_TOOLS_DB.items()
        if t.category.name in MUTATION_CATEGORIES
    )
    assert len(mutation) == 9, mutation
    known_named = {
        "bloodhound", "empire", "lazagne", "mimikatz",
        "metasploit", "nmap_exploit", "setoolkit",
    }
    assert known_named <= set(mutation)
    # safe_by_default is uniform True across the DB - never a discriminator
    assert all(t.safe_by_default for t in KALI_TOOLS_DB.values())
