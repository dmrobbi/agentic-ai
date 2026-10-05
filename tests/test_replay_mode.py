"""KA-026 tests - replay mode: the recording captures planned commands,
the replays re-derive the SAME plans when the agent's behavior is
unchanged (match-true rows), a BEHAVIOR change breaks match cleanly,
and the baseline diff flags exactly the changed fields. Everything
stays dry-run; no execution; no network; the module = pure (scan)."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent
from agentic_ai.agents.cyber.replay_mode import (
    diff_against_baseline,
    record_chain,
    record_to_json,
    replay,
)

BENIGN_TARGET = "192.0.2.1"


@pytest.fixture()
def dry_agent(tmp_path):
    agent = KaliAgent(agent_id="ka026", workspace=str(tmp_path / "ws"),
                      log_dir=str(tmp_path / "logs"))
    agent.set_authorization(AuthorizationLevel.CRITICAL)
    agent.enable_dry_run()
    return agent


ARGUMENT_SETS = [
    {"target": BENIGN_TARGET},
    {"target": BENIGN_TARGET, "ports": "80,443"},
    {"target": BENIGN_TARGET, "ports": "80,443", "version_detect": True},
]


def test_record_captures_planned_steps(dry_agent):
    from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB

    record = record_chain(dry_agent, "nmap", ARGUMENT_SETS, label="ka026")
    assert record["label"] == "ka026"
    assert len(record["steps"]) == 3
    for index, step in enumerate(record["steps"]):
        assert step["tool"] == "nmap"
        assert step["arguments"] == ARGUMENT_SETS[index]
        assert step["status"] == "completed"
        assert step["exit_code"] == 0
        assert step["stderr"] == ""
        built = dry_agent._build_command(KALI_TOOLS_DB["nmap"],
                                         ARGUMENT_SETS[index])
        assert step["command"] == built
    # the serialization is byte-stable for the same record:
    assert record_to_json(record) == record_to_json(record)


def test_replay_matches_current_behavior(dry_agent):
    record = record_chain(dry_agent, "nmap", ARGUMENT_SETS)
    record_json = record_to_json(record)
    outcomes = replay(record_json, dry_agent)
    assert len(outcomes) == 3
    assert all(outcome["match"] is True for outcome in outcomes)
    assert all(outcome["status"] == "completed" for outcome in outcomes)


def test_replay_detects_behavior_change(dry_agent):
    record = record_chain(dry_agent, "nmap", ARGUMENT_SETS)
    record_json = record_to_json(record)
    # change the agent's BEHAVIOR: block the target via whitelisting so
    # the flow takes a different branch (a plan change, not an exec)
    dry_agent.set_ip_whitelist(["203.0.113.9"])
    outcomes = replay(record_json, dry_agent)
    assert len(outcomes) == 3
    assert all(outcome["match"] is False for outcome in outcomes)
    assert all(outcome["status"] == "failed" for outcome in outcomes)


def test_baseline_diff_flags_exact_differences():
    record = {"label": "base", "steps": [
        {"tool": "nmap", "arguments": {"target": "192.0.2.1"},
         "command": "nmap --target '192.0.2.1'", "status": "completed"}]}
    baseline_json = json.dumps(record, sort_keys=True)
    assert diff_against_baseline(baseline_json, baseline_json) == {
        "same": True, "differences": []}
    changed = {"label": "changed", "steps": [
        {"tool": "nmap", "arguments": {"target": "192.0.2.1"},
         "command": "nmap --target '192.0.2.1' --ports 80", "status": "completed"}]}
    diff = diff_against_baseline(json.dumps(changed, sort_keys=True),
                                 baseline_json)
    assert diff["same"] is False
    assert diff["differences"] == [{
        "step": 0, "field": "command",
        "expected": "nmap --target '192.0.2.1'",
        "actual": "nmap --target '192.0.2.1' --ports 80"}]
    # a step-add flags when the RECORD is longer than the baseline:
    added = {"steps": record["steps"] * 2}
    added_diff = diff_against_baseline(json.dumps(added, sort_keys=True),
                                       baseline_json)
    assert added_diff["same"] is False
    assert added_diff["differences"][0]["field"] == "step-added"
    # a step-remove flags when the BASELINE is longer (args in THIS order:
    # record = the new state, baseline = the old state)
    removed_diff = diff_against_baseline(
        json.dumps({"steps": []}, sort_keys=True), baseline_json)
    assert removed_diff["differences"] == [{
        "step": 0, "field": "step-removed", "expected": record["steps"][0],
        "actual": None}]


def test_record_purity_no_execution(dry_agent):
    """Everything stays dry: no side files in the log dir after a
    recording + a replay round trip."""
    record = record_chain(dry_agent, "nmap", ARGUMENT_SETS)
    replay(record_to_json(record), dry_agent)
    assert list(Path(dry_agent.log_dir).iterdir()) == []


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.replay_mode")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
    assert "agentic_ai" not in source  # no chassis import
