"""KA-014 - guardrail integration pins for execute_tool. These pins ARE
the guard contract: pipeline order, short-circuit discipline, and the
zero-process guarantee when any guard blocks.

THE GUARD CONTRACT (the v1 pipeline, in execution order):
  1. auth            check_authorization(tool_name) - blocks unknown tools
                     and insufficient levels; short-circuits EVERYTHING.
  2. target          validate_target() called ONCE PER PRESENT target-ish
                     field of {target, host, url, domain, bssid}; blacklist
                     before whitelist; blocks before argument validation.
  3. args            _validate_arguments(schema, arguments) - required-field
                     presence; blocks before command build.
  4. job-cap         concurrency counter (pinned in KA-006, not re-pinned).
  5. exec-gate       _validate_command_args() AFTER shlex.split - the shell
                     metacharacter wall; raised BEFORE any process
                     construction. REAL PATH ONLY (see 8).
  6. exec            subprocess construction + communicate (stubbed here).
  7. output-post     the parser named by tool.output_parser runs AFTER
                     completion, on the real path only - it is post-hoc
                     observation, not a blocking guard.
  8. dry-run BYPASSES stage 5-6 entirely (pinned fact; a dry run never
     constructs a process, but injection-shaped arguments flow into the
     recorded command string - flagged in the task summary as a proposal).

INVARIANT (pinned three ways): any blocked guardrail prevents subprocess
construction entirely - the process stub records zero ctor calls.

Spy mechanism: instance-level call-through wrappers for the agent's guard
methods, a module-global wrapper for the exec gate, a dict-item wrapper for
the parser - all appending into ONE shared ordered log; per-spy call
counts alongside. No network anywhere."""
from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KaliAgent,
)

BENIGN_TARGET = "192.0.2.1"
MINIMAL_XML = (
    '<run><host><address addr="10.0.0.1"/>'
    "<hostname name=\"host1\"/>"
    '<port portid="80" protocol="tcp">'
    '<state state="open"/><service name="http"/>'
    "</port></host></run>"
)

KALI_MODULE = "agentic_ai.agents.cyber.kali"


class _FakeTimeoutExpired(Exception):
    pass


def _stub_subprocess(monkeypatch, *, rc=0, out=b"", err=b""):
    calls = []

    class _Proc:
        def __init__(self, cmd_args):
            self.killed = False
            self.returncode = rc

        def communicate(self, timeout=None):
            return out, err

        def kill(self):
            self.killed = True

    def ctor(cmd_args, **kwargs):
        calls.append(list(cmd_args))
        return _Proc(cmd_args)

    stub = SimpleNamespace(
        Popen=ctor,
        TimeoutExpired=_FakeTimeoutExpired,
        PIPE=None, STDOUT=None, DEVNULL=None,
    )
    monkeypatch.setattr(KALI_MODULE + ".subprocess", stub)
    return calls


class GuardSpy:
    """Call-through instance-level spy: records + counts, then delegates."""

    def __init__(self, agent, stage, attr, shared_order):
        self.stage = stage
        self.attr = attr
        self.shared_order = shared_order
        self._real = getattr(agent, attr)
        self.n = 0
        self.calls = []

    def install(self, agent, monkeypatch):
        spy = self

        def wrapper(*args, **kwargs):
            spy.n += 1
            spy.calls.append(args)
            spy.shared_order.append(spy.stage)
            return spy._real(*args, **kwargs)

        monkeypatch.setattr(agent, self.attr, wrapper)
        return self


class ModuleGuardSpy:
    """Call-through module-global spy (the exec-gate lives at module level)."""

    def __init__(self, target, stage, shared_order):
        self.target = target
        self.stage = stage
        self.shared_order = shared_order
        self._real = importlib.import_module(  # kali.py's module function
            KALI_MODULE
        )._validate_command_args if target.endswith("_validate_command_args") else None
        self.n = 0

    def install(self, monkeypatch):
        spy = self
        real = self._real

        def wrapper(*args, **kwargs):
            spy.n += 1
            spy.shared_order.append(spy.stage)
            return real(*args, **kwargs)

        monkeypatch.setattr(self.target, wrapper)
        return self


def _real_agent(tmp_path, level):
    agent = KaliAgent(
        agent_id="ka014-guards",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "logs"),
    )
    agent.set_authorization(level)
    return agent


def test_guard_contract_documented():
    text = Path(__file__).read_text(encoding="utf-8")
    for stage in (
        "auth", "target", "args", "exec-gate", "exec", "output-post",
        "dry-run", "INVARIANT",
    ):
        assert stage in text, stage


def test_full_flow_guard_order(tmp_path, monkeypatch):
    calls = _stub_subprocess(monkeypatch, rc=0, out=MINIMAL_XML.encode())
    agent = _real_agent(tmp_path, AuthorizationLevel.BASIC)
    order = []
    auth = GuardSpy(agent, "auth", "check_authorization", order)
    target = GuardSpy(agent, "target", "validate_target", order)
    args = GuardSpy(agent, "args", "_validate_arguments", order)
    gate = ModuleGuardSpy(
        KALI_MODULE + "._validate_command_args", "exec-gate", order)
    real_parser = agent.parsers["nmap_xml"]
    parse_calls = []

    def parse_wrapper(output):
        parse_calls.append(output)
        order.append("output-post")
        return real_parser(output)

    monkeypatch.setitem(agent.parsers, "nmap_xml", parse_wrapper)

    for spy in (auth, target, args):
        spy.install(agent, monkeypatch)
    gate.install(monkeypatch)

    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"
    assert order == ["auth", "target", "args", "exec-gate", "output-post"]
    assert auth.n == 1 and target.n == 1 and args.n == 1 and gate.n == 1
    assert parse_calls == [result.stdout]


def test_blocked_auth_short_circuits_everything(tmp_path, monkeypatch):
    calls = _stub_subprocess(monkeypatch, rc=0)
    agent = _real_agent(tmp_path, AuthorizationLevel.NONE)
    order = []
    auth = GuardSpy(agent, "auth", "check_authorization", order).install(
        agent, monkeypatch)
    target = GuardSpy(agent, "target", "validate_target", order).install(
        agent, monkeypatch)
    args = GuardSpy(agent, "args", "_validate_arguments", order).install(
        agent, monkeypatch)

    result = agent.execute_tool("mimikatz", {"command": "dump"})
    assert result.status == "failed"
    assert "Authorization level 3 required, have 0" in result.stderr
    assert order == ["auth"]          # the wall: nothing past stage 1
    assert target.n == 0 and args.n == 0
    assert calls == []                # INVARIANT: zero process construction


def test_blocked_target_guard_prevents_arguments_and_exec(
        tmp_path, monkeypatch):
    calls = _stub_subprocess(monkeypatch, rc=0)
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    agent.set_ip_whitelist([BENIGN_TARGET])
    order = []
    auth = GuardSpy(agent, "auth", "check_authorization", order).install(
        agent, monkeypatch)
    target = GuardSpy(agent, "target", "validate_target", order).install(
        agent, monkeypatch)
    args = GuardSpy(agent, "args", "_validate_arguments", order).install(
        agent, monkeypatch)

    result = agent.execute_tool("nmap", {"target": "192.0.2.66"})
    assert result.status == "failed"
    assert "Target 192.0.2.66 not in whitelist" in result.stderr
    assert order == ["auth", "target"]   # args stage never reached
    assert target.n == 1 and args.n == 0
    assert calls == []                   # INVARIANT: zero process construction


def test_blocked_arguments_guard_prevents_exec(tmp_path, monkeypatch):
    calls = _stub_subprocess(monkeypatch, rc=0)
    agent = _real_agent(tmp_path, AuthorizationLevel.CRITICAL)
    agent.disable_safe_mode()  # KA-INT-1: the KA-061 gate refuses
    # mutation-class tools; this pin exercises the args guard, so the
    # gate steps aside here
    order = []
    auth = GuardSpy(agent, "auth", "check_authorization", order).install(
        agent, monkeypatch)
    target = GuardSpy(agent, "target", "validate_target", order).install(
        agent, monkeypatch)
    args = GuardSpy(agent, "args", "_validate_arguments", order).install(
        agent, monkeypatch)

    result = agent.execute_tool("mimikatz", {})
    assert result.status == "failed"
    assert "Missing required argument: command" in result.stderr
    assert order == ["auth", "args"]  # no target fields -> skip; args blocks
    assert target.n == 0 and args.n == 1
    assert calls == []                   # INVARIANT: zero process construction


def test_exec_gate_blocks_before_process_construction(tmp_path, monkeypatch):
    calls = _stub_subprocess(monkeypatch, rc=0)
    agent = _real_agent(tmp_path, AuthorizationLevel.BASIC)
    order = []
    auth = GuardSpy(agent, "auth", "check_authorization", order).install(
        agent, monkeypatch)
    target = GuardSpy(agent, "target", "validate_target", order).install(
        agent, monkeypatch)
    args = GuardSpy(agent, "args", "_validate_arguments", order).install(
        agent, monkeypatch)
    gate = ModuleGuardSpy(
        KALI_MODULE + "._validate_command_args", "exec-gate", order).install(
        monkeypatch)

    result = agent.execute_tool(
        "nmap", {"target": BENIGN_TARGET, "extra": "value; with semicolon"})
    assert result.status == "failed"
    assert "Rejected dangerous metacharacter" in result.stderr
    assert order == ["auth", "target", "args", "exec-gate"]
    assert gate.n == 1
    assert calls == []                   # INVARIANT: zero process construction


def test_output_parse_posthoc_and_dry_skips(tmp_path, monkeypatch):
    _stub_subprocess(monkeypatch, rc=0, out=b"not xml")
    agent = _real_agent(tmp_path, AuthorizationLevel.BASIC)
    real_parser = agent.parsers["nmap_xml"]
    parse_calls = []

    def parse_wrapper(output):
        parse_calls.append(output)
        return real_parser(output)

    monkeypatch.setitem(agent.parsers, "nmap_xml", parse_wrapper)

    # real path: parse ATTEMPTED on the completed execution (hostile output
    # -> parser None -> no parsed file), output guard is post-hoc
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"
    assert parse_calls == ["not xml"]

    # dry path: no parse attempt at all
    parse_calls.clear()
    agent.enable_dry_run()
    dry = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert dry.status == "completed"
    assert parse_calls == []


def test_dry_run_bypasses_the_exec_gate(tmp_path, monkeypatch):
    # stage 8 of the contract: dry-run never reaches the metachar wall
    calls = _stub_subprocess(monkeypatch, rc=0)
    agent = _real_agent(tmp_path, AuthorizationLevel.BASIC)
    agent.enable_dry_run()
    order = []
    gate = ModuleGuardSpy(
        KALI_MODULE + "._validate_command_args", "exec-gate", order).install(
        monkeypatch)

    result = agent.execute_tool(
        "nmap", {"target": BENIGN_TARGET, "extra": "value; with semicolon"})
    assert result.status == "completed"  # dry: records the command string
    assert ";" in result.stdout          # injection-shaped text recorded
    assert gate.n == 0
    assert order == []
    assert calls == []                   # still zero process construction
