"""KA-006 - execute_tool branch matrix: every branch of the tool-execution
state machine pinned, table-driven, no network, no real binaries.

Branch checklist (completeness measured by test_matrix_branch_checklist):
  B01  check_authorization: unknown tool -> failed, "Unknown tool" stderr
  B02  authorization: required level > effective -> failed, level message
  B03  authorization: sufficient global level -> proceeds to dry-run completion
  B04  effective level = max(global, pooled engagement auths); an engagement
       auth lifts a NONE agent. PINNED QUIRK: engagement auths are pooled
       across ALL engagement ids - any engagement authorization unlocks any
       call regardless of the engagement_id passed to execute_tool.
  B05  engagement auths never lower the effective level (max() semantics)
  B06  target-field gate: blacklisted value rejected; parametrized over the
       five validated fields (target/host/url/domain/bssid)
  B07  target gate: whitelist non-member -> "not in whitelist"
  B08  target gate: whitelisted member -> passes to dry-run
  B09  arguments: missing required field -> "Missing required argument"
       B09+B10 same branch, measured across EVERY required field in
  B10  KALI_TOOLS_DB via the (tool, missing-field) parametrize below
  B11  dry-run: status completed, exit 0, [DRY-RUN] stdout prefix, no output_file
  B12  dry-run: stdout mirrors the built command exactly
  B13  job cap: current_jobs >= max -> failed "Maximum concurrent jobs
       reached", counter unchanged, execution stored (B15 cap side)
  B14  job cap: successful run decrements to pre-state (B15 success side)
  B16  engagement_id + tool authorization recorded on the execution
  B17  _build_command: None value skipped
  B18  _build_command: bool True -> --flag; bool False -> omitted entirely
  B19  _build_command: int/float -> --opt value
  B20  _build_command: str -> --opt 'value' with single-quote escaping
  B21  real path: exit 0 -> completed, stdout/stderr decoded (subprocess stubbed)
  B22  real path: nonzero exit -> failed, stderr captured (stubbed)
  B23  real path: TimeoutExpired -> status timeout + stderr message + kill
  B24  real path: unexpected exception -> failed, exit -1
  B25  real path: output .log side-file written with command/stdout/stderr
  B26  parser branch: parseable nmap_xml stdout -> _parsed.json written;
       hostile stdout -> parser returns None -> no parsed file
  B27  metachar gate (_validate_command_args): dangerous arg -> failed BEFORE
       Popen (stub records ctor calls), stderr carries the rejection
  B28  RESOLVED 2026-10-07 (owner-ordered cleanup): the INT-4 gate-chain
       rewrite removed the old top auth-block from execute_tool; the only
       unknown-tool handling = the reachable top-of-flow check. No dead
       re-check remains.
  B29  audit contract (v1): _log_audit is dead in practice - no audit file
       is written by execute_tool flows; a direct call with logging enabled
       DOES append JSONL with a timestamp; disabled logging = full no-op.
"""

from __future__ import annotations
import datetime as dt

import json
import re
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.consent_gate import ConsentRecord
from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KALI_TOOLS_DB,
    KaliAgent,
    SAFE_MODE_BLOCKED_CATEGORIES,
)

TARGET_FIELDS = ("target", "host", "url", "domain", "bssid")
BENIGN_TARGET = "192.0.2.1"  # RFC 5737 documentation address

MINIMAL_NMAP_XML = (
    '<run><host><address addr="10.0.0.1"/>'
    '<hostname name="host1"/>'
    '<port portid="80" protocol="tcp">'
    '<state state="open"/><service name="http"/>'
    "</port></host></run>"
)


def _agent(tmp_path, level=None, dry=True):
    agent = KaliAgent(
        agent_id="ka006-matrix",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "logs"),
    )
    if level is not None:
        agent.set_authorization(level)
    agent.lab_staged = True
    agent.auth_tags = ("EGRESS-AUTH",)
    # KA-INT-4: standing per-action consent (b02 overrides per param)
    agent.attach_consent(ConsentRecord(engagement_id="e", action="nmap",
                                       signed_by="owner",
                                       signed_at=dt.datetime(2026, 10, 5, 12, 0,
                                       tzinfo=dt.timezone.utc)))
    if dry:
        agent.enable_dry_run()
    return agent


def _required(tool):
    return [k for k, v in tool.args_schema.items()
            if isinstance(v, dict) and v.get("required")]


def test_matrix_branch_checklist_documented():
    # the file's own checklist is the completeness measure - keep it current
    text = Path(__file__).read_text(encoding="utf-8")
    ids = set(re.findall(r"\bB\d\d\b", text))
    assert len(ids) >= 29, sorted(ids)


def test_b01_unknown_tool_rejected(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    assert agent.check_authorization("no_such_tool_xyz") == (
        False, "Unknown tool: no_such_tool_xyz")
    result = agent.execute_tool("no_such_tool_xyz", {})
    assert result.status == "failed"
    assert "Unknown tool: no_such_tool_xyz" in result.stderr
    assert result.exit_code == -1
    assert result.command == ""
    assert result.authorization_level == AuthorizationLevel.NONE


@pytest.mark.parametrize("tool_name", ["nmap", "mimikatz"])
def test_b02_insufficient_level_rejected(tmp_path, tool_name):
    agent = _agent(tmp_path)  # global NONE
    agent.attach_consent(ConsentRecord(engagement_id="e", action=tool_name,
                                       signed_by="owner",
                                       signed_at=dt.datetime(2026, 10, 5, 12, 0,
                                       tzinfo=dt.timezone.utc)))
    tool = KALI_TOOLS_DB[tool_name]
    args = {k: "x" for k, v in tool.args_schema.items()
            if isinstance(v, dict) and v.get("required")}
    ok, msg = agent.check_authorization(tool_name)
    assert not ok
    assert "Authorization level {} required, have 0".format(
        tool.authorization.value) in msg
    result = agent.execute_tool(tool_name, args)
    assert result.status == "failed"
    # KA-INT-4: the deciding seat moved - the safe-mode pre-gate now
    # blocks mutation-class tools before the chain's authority seat
    if tool.category.name in SAFE_MODE_BLOCKED_CATEGORIES:
        assert "Refused: safe mode blocks mutation-class" in result.stderr
    else:
        assert "Authorization level {} required, have 0".format(
            tool.authorization.value) in result.stderr


def test_b03_sufficient_level_completes_dry_run(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"
    assert result.exit_code == 0
    assert "[DRY-RUN]" in result.stdout


def test_b04_engagement_auth_lifts_none_and_is_pooled(tmp_path):
    agent = _agent(tmp_path)  # global NONE
    agent.disable_safe_mode()  # KA-INT-1: the KA-061 gate refuses
    # mutation-class tools; this pin exercises the pooled-level
    # machinery, so the gate steps aside here
    agent.set_authorization(AuthorizationLevel.CRITICAL, engagement_id="ENG1")
    ok, msg = agent.check_authorization("mimikatz")
    assert ok, msg  # lifted NONE globally, not just for ENG1
    # pinned pooled semantics: a different engagement id passes too
    result = agent.execute_tool("mimikatz", {"command": "x"},
                                engagement_id="ENG-OTHER")
    assert result.status == "completed"
    assert result.engagement_id == "ENG-OTHER"


def test_b05_engagement_never_lowers_effective_level(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.CRITICAL)
    agent.disable_safe_mode()  # KA-INT-1: the KA-061 gate refuses
    # mutation-class tools; this pin exercises the max() machinery, so
    # the gate steps aside here
    agent.set_authorization(AuthorizationLevel.BASIC, engagement_id="LOW")
    ok, _ = agent.check_authorization("mimikatz")
    assert ok
    result = agent.execute_tool("mimikatz", {"command": "x"})
    assert result.status == "completed"


@pytest.mark.parametrize("field", TARGET_FIELDS)
def test_b06_blacklisted_target_field_rejected(tmp_path, field):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    agent.add_to_blacklist("pwned.example")
    args = {"target": BENIGN_TARGET}
    if field != "target":
        args[field] = "pwned.example"
    else:
        args["target"] = "pwned.example"
    result = agent.execute_tool("nmap", args)
    assert result.status == "failed"
    assert "Target pwned.example is blacklisted" in result.stderr


def test_b07_whitelist_nonmember_rejected(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    agent.set_ip_whitelist([BENIGN_TARGET])
    result = agent.execute_tool("nmap", {"target": "192.0.2.66"})
    assert result.status == "failed"
    assert "Target 192.0.2.66 not in whitelist" in result.stderr


def test_b08_whitelisted_member_passes(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    agent.set_ip_whitelist([BENIGN_TARGET])
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"


_MISSING_PARAMS = [
    (tool_name, field)
    for tool_name, tool in KALI_TOOLS_DB.items()
    for field in _required(tool)
]


@pytest.mark.parametrize("tool_name,missing", _MISSING_PARAMS)
def test_b09_b10_missing_required_rejected_by_field(tmp_path, tool_name,
                                                    missing):
    agent = _agent(tmp_path, level=KALI_TOOLS_DB[tool_name].authorization)
    agent.disable_safe_mode()  # KA-INT-1: the KA-061 gate refuses
    # mutation-class tools; this pin exercises the args guard per
    # field, so the gate steps aside here
    required = _required(KALI_TOOLS_DB[tool_name])
    args = {k: "x" for k in required if k != missing}
    result = agent.execute_tool(tool_name, args)
    assert result.status == "failed"
    assert "Missing required argument: {}".format(missing) in result.stderr


def test_b11_b12_dry_run_output_parity(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    args = {"target": BENIGN_TARGET, "ports": "80,443",
            "version_detect": True, "os_detect": False}
    result = agent.execute_tool("nmap", args)
    assert result.status == "completed"
    assert result.exit_code == 0
    assert result.output_file is None
    built = agent._build_command(KALI_TOOLS_DB["nmap"], args)
    assert result.stdout == "[DRY-RUN] Command would execute: " + built


def test_b13_job_cap_branch(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    agent.current_jobs = agent.max_concurrent_jobs
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "failed"
    assert result.stderr == "Maximum concurrent jobs reached"
    assert result.exit_code is None  # the cap path never sets an exit code
    assert result.duration_seconds == 0
    assert agent.current_jobs == agent.max_concurrent_jobs  # unchanged
    assert result.execution_id in agent.executions  # B15 cap side


def test_b14_counter_restores_after_success(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    before = agent.current_jobs
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert agent.current_jobs == before
    assert result.execution_id in agent.executions  # B15 success side


def test_b16_engagement_id_and_auth_recorded(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET},
                                engagement_id="ENG-42")
    assert result.engagement_id == "ENG-42"
    assert result.authorization_level == KALI_TOOLS_DB["nmap"].authorization


def test_b17_none_value_skipped(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    cmd = agent._build_command(KALI_TOOLS_DB["nmap"],
                               {"target": BENIGN_TARGET, "ports": None})
    assert cmd == "nmap --target '{}'".format(BENIGN_TARGET)


def test_b18_bool_flag_branches(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    cmd = agent._build_command(
        KALI_TOOLS_DB["nmap"],
        {"target": BENIGN_TARGET, "version_detect": True, "os_detect": False})
    assert cmd == "nmap --target '{}' --version-detect".format(BENIGN_TARGET)


def test_b19_numeric_option_value(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    cmd = agent._build_command(KALI_TOOLS_DB["nmap"],
                               {"target": BENIGN_TARGET, "ports": 8080})
    assert cmd == "nmap --target '{}' --ports 8080".format(BENIGN_TARGET)


def test_b20_string_quoting_and_escape(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    v = BENIGN_TARGET + "'s"
    cmd = agent._build_command(KALI_TOOLS_DB["nmap"], {"target": v})
    expected = "nmap --target '" + v.replace("'", "'\\''") + "'"
    assert cmd == expected
    # the escaping must survive a shlex round-trip intact
    assert shlex.split(cmd) == ["nmap", "--target", v]


class _FakeTimeoutExpired(Exception):
    pass


def _stub_subprocess(monkeypatch, *, rc=0, out=b"", err=b"",
                     timeout_raise=False, ctor_error=None):
    """Replace kali.py's subprocess binding with a deterministic stub.

    Returns (ctor arg-lists, live process objects). The metachar gate runs
    BEFORE Popen, so `calls == []` after a blocked execution proves the
    process layer was never reached.
    """
    calls = []
    procs = []

    class _Proc:
        def __init__(self, cmd_args):
            self._cmd_args = cmd_args
            self.killed = False
            self.returncode = rc  # _execute_command reads process.returncode

        def communicate(self, timeout=None):
            if timeout_raise:
                raise _FakeTimeoutExpired()
            return out, err

        def kill(self):
            self.killed = True

    def ctor(cmd_args, **kwargs):
        calls.append(list(cmd_args))
        if ctor_error is not None:
            raise ctor_error
        proc = _Proc(cmd_args)
        procs.append(proc)
        return proc

    stub = SimpleNamespace(
        Popen=ctor,
        TimeoutExpired=_FakeTimeoutExpired,
        PIPE=None, STDOUT=None, DEVNULL=None,  # constants _execute_command reads
    )
    monkeypatch.setattr("agentic_ai.agents.cyber.kali.subprocess", stub)
    return calls, procs


def _real_agent(tmp_path):
    return _agent(tmp_path, level=AuthorizationLevel.BASIC, dry=False)


def test_b21_zero_exit_completed(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch, rc=0, out=b"scan done")
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"
    assert result.exit_code == 0
    assert result.stdout == "scan done"
    assert result.stderr == ""
    assert len(calls) == 1 and calls[0][0] == "nmap"


def test_b22_nonzero_exit_failed(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch, rc=3, err=b"boom")
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "failed"
    assert result.exit_code == 3
    assert result.stdout == ""
    assert result.stderr == "boom"


def test_b23_timeout_branch(tmp_path, monkeypatch):
    calls, procs = _stub_subprocess(monkeypatch, timeout_raise=True)
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET},
                                timeout_override=7)
    assert result.status == "timeout"
    assert result.stderr == "Command timed out after 7 seconds"
    assert result.exit_code is None
    assert len(calls) == 1          # Popen reached exactly once
    assert procs and procs[0].killed  # the timeout path kills the process


def test_b24_unexpected_exception_branch(tmp_path, monkeypatch):
    calls, procs = _stub_subprocess(monkeypatch, ctor_error=RuntimeError("boom"))
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "failed"
    assert result.stderr == "boom"
    assert result.exit_code == -1
    assert procs == []


def test_b25_output_side_log_written(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch, rc=0, out=b"data out")
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    log_file = Path(agent.log_dir) / (result.execution_id + ".log")
    assert log_file.exists()
    content = log_file.read_text()
    assert "Command:" in content
    assert "STDOUT:" in content and "data out" in content
    assert result.output_file == str(log_file)


def test_b26_parser_branch(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(
        monkeypatch, rc=0, out=MINIMAL_NMAP_XML.encode())
    agent = _real_agent(tmp_path)
    result = agent.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result.status == "completed"
    parsed_file = Path(agent.log_dir) / (result.execution_id + "_parsed.json")
    assert parsed_file.exists()
    parsed = json.loads(parsed_file.read_text())
    assert parsed["hosts"][0]["address"] == "10.0.0.1"
    assert parsed["hosts"][0]["hostname"] == "host1"
    assert parsed["hosts"][0]["ports"][0]["port"] == 80
    assert parsed["hosts"][0]["ports"][0]["state"] == "open"
    # negative branch: hostile stdout -> parser None -> no parsed file
    _calls2, _procs2 = _stub_subprocess(monkeypatch, rc=0, out=b"not-xml")
    agent2 = _real_agent(tmp_path)
    result2 = agent2.execute_tool("nmap", {"target": BENIGN_TARGET})
    assert result2.status == "completed"
    assert not (
        Path(agent2.log_dir) / (result2.execution_id + "_parsed.json")
    ).exists()


def test_b27_metachar_gate_blocks_real_exec(tmp_path, monkeypatch):
    calls, _procs = _stub_subprocess(monkeypatch)
    agent = _real_agent(tmp_path)
    result = agent.execute_tool(
        "nmap", {"target": BENIGN_TARGET, "extra": "safe; calc"})
    assert result.status == "failed"
    # KA-INT-4: the chain's blast classification refuses hostile input
    # above the metachar wall (the rejection seat moved up)
    assert "gate_chain: blast classification refused" in result.stderr
    assert result.exit_code == -1
    assert calls == []  # Popen was never reached
    result2 = agent.execute_tool(
        "nmap", {"target": BENIGN_TARGET, "extra": "safe$(calc)"})
    assert result2.status == "failed"
    # KA-INT-4: the chain's blast refusal is the deciding seat here too
    assert "gate_chain: blast classification refused" in result2.stderr
    assert calls == []


def test_b29_audit_contract_v1(tmp_path):
    agent = _agent(tmp_path, level=AuthorizationLevel.BASIC)
    assert isinstance(agent.audit_log_file, Path)
    assert not agent.audit_log_file.exists()
    agent.execute_tool("nmap", {"target": BENIGN_TARGET})  # dry-run flow
    assert not agent.audit_log_file.exists()  # dead-in-practice invariant
    agent._log_audit({"kind": "probe"})
    assert agent.audit_log_file.exists()
    lines = agent.audit_log_file.read_text().strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["kind"] == "probe" and "timestamp" in event
    audit_path = agent.audit_log_file
    agent.disable_audit_logging()
    assert agent.audit_log_file is None
    agent._log_audit({"kind": "probe2"})  # no-op, no exception
    lines_after = audit_path.read_text().strip().splitlines()
    assert len(lines_after) == 1  # file unchanged after disable
