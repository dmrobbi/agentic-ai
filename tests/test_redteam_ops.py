"""Red-team mixin tests: phase catalogs on the kali agents are safe planners."""
import inspect
import json
import pathlib

import pytest

from agentic_ai.agents.registry import create_agent


def _catalog():
    p = pathlib.Path(inspect.getfile(
        __import__("agentic_ai.agents.cyber.redteam_pentest", fromlist=["x"])))
    data = p.parent / "data" / "redteam_tools.json"
    return p, json.loads(data.read_text())


def test_both_kali_agents_carry_redteam_ops():
    for agent_id in ("kali", "kali_v2"):
        agent = create_agent(agent_id)
        for op in ("plan_redteam", "redteam_phase_tools",
                   "redteam_countermeasures", "redteam_tool_lookup"):
            assert callable(getattr(agent, op, None)), (agent_id, op)


def test_catalog_structure():
    _, cat = _catalog()
    assert cat["meta"]["totals"]["phases"] == 13
    assert cat["meta"]["totals"]["tools"] == 725
    phases = list(cat["phases"])
    for p in ("active-directory", "credential-access", "evasion", "lateral-movement"):
        assert p in phases
    for phase, entry in cat["phases"].items():
        assert entry["sections"], phase
        for tool in entry["tools"]:
            assert tool["url"].startswith("https://")
            assert tool["name"]


def test_plan_redteam_shape():
    agent = create_agent("kali")
    plan = agent.plan_redteam("example.com")
    assert plan["scope"] == "example.com"
    assert len(plan["phases"]) == 13
    ev = [p for p in plan["phases"] if p["phase"] == "evasion"][0]
    assert ev["tool_count"] > 150
    assert ev["goal"]
    assert any(t["purpose"] for t in ev["example_tools"]) or not ev["example_tools"]
    assert "no payloads" in plan["policy"]


def test_phase_tools_and_countermeasures():
    agent = create_agent("kali_v2")
    tools = agent.redteam_phase_tools("lateral-movement")
    assert "Lateral Movement" in tools["sections"]
    assert tools["tools"]
    cm = agent.redteam_countermeasures("evasion")
    joined = " ".join(cm["detection_notes"]).lower()
    assert "amsi" in joined and "etw" in joined
    cm2 = agent.redteam_countermeasures("credential-access")
    assert any("sysmon event 10" in n.lower() for n in cm2["detection_notes"])
    with pytest.raises(ValueError):
        agent.redteam_phase_tools("teleport")
    with pytest.raises(ValueError):
        agent.redteam_countermeasures("nope")


def test_tool_lookup():
    agent = create_agent("kali")
    hits = agent.redteam_tool_lookup("crackmap")
    assert hits["hits"] and not hits["hits"][0]["purpose"] is None
    assert hits["hits"][0]["url"].startswith("https://")
    empty = agent.redteam_tool_lookup("qqqqzzzz")
    assert empty["hits"] == [] and not empty["truncated"]
    with pytest.raises(ValueError):
        agent.redteam_tool_lookup("x")
    with pytest.raises(ValueError):
        agent.redteam_tool_lookup("")


@pytest.mark.parametrize("evil", [
    "example.com; shutdown -h now", "example.com $(curl evil)",
    "example.com\nnewlines", "10.0.0.5 && whoami", "", None,
])
def test_scope_scrub_rejects(evil):
    agent = create_agent("kali")
    with pytest.raises(ValueError):
        agent.plan_redteam(evil)


def test_no_execution_and_no_payload_blobs():
    src, cat = _catalog()

    code = src.read_text()
    assert "subprocess" not in code
    assert "os.system" not in code
    assert "eval(" not in code

    # the data file: names/links/purposes only - nothing blob-length
    longest = 0
    for entry in cat["phases"].values():
        for t in entry["tools"]:
            longest = max(longest, len(t["name"]), len(t["url"]),
                          len(t["purpose"] or ""))
    assert longest < 300, longest

    def check(node):
        if isinstance(node, str):
            return len(node)
        if isinstance(node, dict):
            return max((check(v) for v in node.values()), default=0)
        if isinstance(node, list):
            return max((check(v) for v in node), default=0)
        return 0

    assert check(cat) < 300