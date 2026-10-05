"""KA-061 - safe-mode proof.

The todo's acceptance allows either a green proof or a red test + proposal
when a REAL bug is proven. The proof ran; the bug is proven: the v1 chassis
never reads self.safe_mode during execute_tool (the flag appears exactly
three times in kali.py - its __init__ + the enable/disable toggles), and
ExecutionMode / safe_by_default are equally unconsulted safety signals.

LANDED AS: xfail(strict=True) + the proposal below - the suite stays green
(standing guardrail) while the defect stays loud, and strict=True turns a
post-fix silent xpass into a suite failure, forcing the integration task to
remove this marker.

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

from pathlib import Path
from types import SimpleNamespace

import pytest

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
    return agent  # safe_mode defaults True - the state under proof


def test_current_behavior_safe_mode_never_consulted(tmp_path, monkeypatch):
    # DOCUMENTS THE GAP - RESOLVE AT KA-INT-1 (see module docstring): when
    # enforcement lands, this expectation flips to the blocked shape
    # (status failed + a safe-mode-naming stderr + no process).
    calls, _procs = _stub_subprocess(monkeypatch, rc=0, out=b"dumped")
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    assert agent.safe_mode is True
    result = agent.execute_tool("mimikatz", {"command": "dump"})
    assert result.status == "completed"      # executed DESPITE safe mode
    assert len(calls) == 1 and calls[0][0] == "mimikatz"  # zero resistance


@pytest.mark.xfail(
    strict=True,
    reason="KA-061 proposal: the v1 chassis never reads self.safe_mode "
           "during execute_tool; enforcement is the KA-INT-1 decision "
           "(module docstring carries the full proposal)",
)
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
