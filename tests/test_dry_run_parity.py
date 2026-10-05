"""KA-065 - dry-run parity: the dry-recorded output mirrors the would-be
command string EXACTLY (across arg shapes and tools), a dry run writes no
side files or logs, repeats are byte-stable, and the dry-recorded string
parses to the exact argv the real path would present to the process layer
(captured-exec comparison, stubbed). No network."""
from __future__ import annotations

import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KALI_TOOLS_DB,
    KaliAgent,
)

BENIGN_TARGET = "192.0.2.1"

NMAP_SHAPES = [
    {"target": BENIGN_TARGET},
    {"target": BENIGN_TARGET, "ports": "1-1000"},
    {"target": BENIGN_TARGET, "ports": 8080},
    {"target": BENIGN_TARGET, "version_detect": True},
    {"target": BENIGN_TARGET, "os_detect": False},
    {"target": BENIGN_TARGET, "ports": None},
    {"target": BENIGN_TARGET + "'s"},
    {"target": BENIGN_TARGET, "ports": "80,443", "version_detect": True,
     "os_detect": False, "aggressive": False},
]

TOOL_PARAMS = [
    ("nmap", {"target": BENIGN_TARGET}),
    ("nikto", {"host": BENIGN_TARGET, "ssl": True}),
    ("sslscan", {"host": BENIGN_TARGET, "port": 443}),
    ("sqlmap", {"url": "http://192.0.2.1/app"}),
]


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
    monkeypatch.setattr("agentic_ai.agents.cyber.kali.subprocess", stub)
    return calls


def _dry_agent(tmp_path, level=None):
    if level is None:
        level = AuthorizationLevel.CRITICAL  # parity is level-insensitive;
        # CRITICAL clears every tool's gate so tests measure parity, not auth
    agent = KaliAgent(
        agent_id="ka065-parity",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "logs"),
    )
    agent.set_authorization(level)
    agent.enable_dry_run()
    return agent


@pytest.mark.parametrize("args", NMAP_SHAPES)
def test_dry_output_mirrors_built_command_exactly(tmp_path, args):
    agent = _dry_agent(tmp_path)
    result = agent.execute_tool("nmap", args)
    built = agent._build_command(KALI_TOOLS_DB["nmap"], args)
    assert result.stdout == "[DRY-RUN] Command would execute: " + built
    assert result.status == "completed"
    assert result.exit_code == 0
    assert result.output_file is None


@pytest.mark.parametrize("tool_name,args", TOOL_PARAMS)
def test_dry_parity_across_tools(tmp_path, tool_name, args):
    agent = _dry_agent(tmp_path)
    result = agent.execute_tool(tool_name, args)
    built = agent._build_command(KALI_TOOLS_DB[tool_name], args)
    assert result.stdout == "[DRY-RUN] Command would execute: " + built
    assert result.status == "completed"


def test_dry_runs_write_no_side_files(tmp_path):
    agent = _dry_agent(tmp_path)
    for tool_name, args in TOOL_PARAMS + [("nmap", {"target": BENIGN_TARGET})]:
        result = agent.execute_tool(tool_name, args)
        assert result.status == "completed"
        assert result.output_file is None
    assert list(Path(agent.log_dir).iterdir()) == []  # no logs, no parsed,
    # no audit file: enable_audit_logging() only sets a path (KA-006 B29)


def test_dry_run_repeat_is_byte_stable(tmp_path):
    agent = _dry_agent(tmp_path)
    args = {"target": BENIGN_TARGET, "ports": "80,443"}
    first = agent.execute_tool("nmap", args)
    second = agent.execute_tool("nmap", args)
    assert first.stdout == second.stdout  # identical mirror string
    assert first.execution_id != second.execution_id
    assert len(agent.executions) == 2


def test_dry_recorded_string_parses_to_the_real_argv(tmp_path, monkeypatch):
    # the money parity pin: what dry-run records is EXACTLY what the real
    # path would hand to the process layer (captured-exec comparison).
    args = {"target": BENIGN_TARGET, "ports": "80,443",
            "version_detect": True, "os_detect": False}
    dry_agent = _dry_agent(tmp_path)
    dry_record = dry_agent.execute_tool("nmap", args)
    prefix = "[DRY-RUN] Command would execute: "
    assert dry_record.stdout.startswith(prefix)
    recorded_command = dry_record.stdout[len(prefix):]

    calls = _stub_subprocess(monkeypatch, rc=0, out=b"irrelevant")
    real_agent = _dry_agent(tmp_path)
    real_agent.disable_dry_run()
    real_agent.execute_tool("nmap", args)

    assert len(calls) == 1
    assert shlex.split(recorded_command) == calls[0]
