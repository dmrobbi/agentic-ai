"""Exploit-test replay mode (KA-026): record a dry-run chain as data,
replay it later, and diff against a BASELINE for regression - pure
recording of PLANNED commands; nothing here executes anything.

CONTRACT:
- record_chain(agent, tool_name, argument_sets) -> ReplayRecord: runs
  execute_tool in the agent's CURRENT mode (the caller decides dry-run)
  and captures per-step: tool, arguments, planned command, status,
  exit_code, error-text. Everything captured is data; no execution adds.
- record_to_json(record) -> str: INSERTION-ORDER STABLE serialization -
  the replay parity re-derives commands from argument order, so dicts
  round-trip in their original order (sort_keys would break parity).
- replay(record_json, agent) -> list of step-outcomes: re-derives the
  plan per step from the recorded arguments and compares against the
  recorded commands; returns [{"step", "tool", "command", "match":
  bool, "expected", "actual"}...].
- diff_against_baseline(record_json, baseline_json) -> {"same": true,
  "differences": []} on the PLANNED commands (a baseline drift = the
  regression alarm; stamps like utcnow are excluded from the comparison
  by design).
- Pure: no network, no process layers (the agent's dry-run flag is not
  FORCED here - the caller's state is the contract; the tests always
  pass a dry agent). No chassis import."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

COMMAND_KEY = "command"


def record_chain(agent, tool_name: str,
                 argument_sets: Iterable[Dict[str, Any]],
                 label: str = "ka-replay") -> Dict[str, Any]:
    """Capture a dry-run chain: per-argument-set the planned command +
    status. NOTHING is executed here beyond the agent's own mode."""
    steps: List[Dict[str, Any]] = []
    for arguments in argument_sets:
        execution = agent.execute_tool(tool_name, dict(arguments))
        steps.append({
            "tool": tool_name,
            "arguments": arguments,
            "command": execution.command,
            "status": execution.status,
            "exit_code": execution.exit_code,
            "stderr": execution.stderr,
        })
    return {"label": label, "steps": steps}


def record_to_json(record: Dict[str, Any]) -> str:
    """Stable INSERTION-ORDER serialization (json is loaded back into
    ordered dicts: the replay parity depends on argument order)."""
    return json.dumps(record, indent=1)


def replay(record_json: str, agent) -> List[Dict[str, Any]]:
    """Re-derive each step's plan from the recorded arguments against the
    agent's CURRENT behavior; compare to the recorded commands."""
    record = json.loads(record_json)
    outcomes: List[Dict[str, Any]] = []
    for index, step in enumerate(record.get("steps", [])):
        tool = step.get("tool", "")
        args = dict(step.get("arguments") or {})
        execution = agent.execute_tool(tool, args)
        outcomes.append({
            "step": index,
            "tool": tool,
            "expected": step.get(COMMAND_KEY, ""),
            "actual": execution.command,
            "match": execution.command == step.get(COMMAND_KEY, ""),
            "status": execution.status,
        })
    return outcomes


def diff_against_baseline(record_json: str, baseline_json: str) -> Dict[str, Any]:
    """Planned-command regression diff (the stamps excluded by design:
    only tool/arguments/command/status are compared)."""
    record = json.loads(record_json)
    baseline = json.loads(baseline_json)
    differences: List[Dict[str, Any]] = []

    base_steps = baseline.get("steps", [])
    for index, step in enumerate(record.get("steps", [])):
        if index >= len(base_steps):
            differences.append({"step": index, "field": "step-added",
                                "expected": None, "actual": step})
            continue
        base = base_steps[index]
        for field in ("tool", "arguments", COMMAND_KEY, "status"):
            if step.get(field) != base.get(field):
                differences.append({
                    "step": index, "field": field,
                    "expected": base.get(field), "actual": step.get(field)})
    for index in range(len(record.get("steps", [])), len(base_steps)):
        differences.append({"step": index, "field": "step-removed",
                            "expected": base_steps[index], "actual": None})
    return {"same": not differences, "differences": differences}
