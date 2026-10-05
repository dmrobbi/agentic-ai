"""XSS mixin tests: the XSS ops on the kali agents are safe planners."""
import inspect
import json
import pathlib

import pytest

from agentic_ai.agents.registry import create_agent


def _catalog():
    p = pathlib.Path(inspect.getfile(
        __import__("agentic_ai.agents.cyber.xss_exploit", fromlist=["x"])))
    data = p.parent / "data" / "xss_tools.json"
    return p, json.loads(data.read_text())


def test_both_kali_agents_carry_xss_ops():
    for agent_id in ("kali", "kali_v2"):
        agent = create_agent(agent_id)
        for op in ("plan_xss_exploit", "xss_callback_commands",
                   "xss_countermeasures", "xss_filter_strategy",
                   "xss_tool_lookup"):
            assert callable(getattr(agent, op, None)), (agent_id, op)


def test_catalog_structure():
    _, cat = _catalog()
    assert cat["meta"]["totals"]["phases"] == 5
    assert cat["meta"]["totals"]["tools"] == 15
    assert "no payloads" in cat["meta"]["policy"]
    assert "cfd5fadc" in cat["meta"]["source"]
    for phase, entry in cat["phases"].items():
        assert entry["sections"], phase
        for tool in entry["tools"]:
            assert tool["url"].startswith("https://")
            assert tool["name"]
            assert tool["purpose"]
    names = [t["name"] for e in cat["phases"].values() for t in e["tools"]]
    assert len(names) == len(set(names)), "duplicate tool rows"
    for expected in ("Interactsh", "BeEF", "XSStrike", "domloggerpp", "dalfox"):
        assert expected in names


def test_plan_xss_shape():
    agent = create_agent("kali")
    plan = agent.plan_xss_exploit("example.com")
    assert plan["target"] == "example.com"
    phases = [p["phase"] for p in plan["phases"]]
    assert len(phases) == 7
    assert phases[0] == "1-context-discovery"
    assert ("3-collection", "5-evasion-strategy",
            "7-reporting") == (phases[2], phases[4], phases[6])
    for p in plan["phases"]:
        assert p["goal"] and p["activities"]
    # strategy/verification phases carry comment-commands only (no execution)
    strat = [p for p in plan["phases"] if p["phase"] == "5-evasion-strategy"][0]
    assert all(c.startswith("#") for c in strat["sample_commands"])
    # tool phases inject the target and stay tool-only
    strat4 = [p for p in plan["phases"] if p["phase"] == "4-strategy"][0]
    assert any("example.com" in c for c in strat4["sample_commands"])
    assert "no payloads" in plan["policy"]


def test_callback_commands_shape_and_scrub():
    agent = create_agent("kali")
    steps = agent.xss_callback_commands("oob.example.com")
    assert steps["callback"] == "oob.example.com"
    names = [s["step"] for s in steps["steps"]]
    assert ("oob-client", "listener", "https-listener",
            "verification") == tuple(names)
    for s in steps["steps"]:
        for c in s["commands"]:
            assert "oob.example.com" not in c or "<your-oob-host>" not in c
    # the client + probe commands actually reference the scrubbed callback
    by_step = {s["step"]: s["commands"] for s in steps["steps"]}
    assert any("oob.example.com" in c and "-u" in c
               for c in by_step["oob-client"])
    assert any("oob.example.com" in c for c in by_step["verification"])


def test_filter_strategy_no_payload_strings():
    agent = create_agent("kali")
    result = agent.xss_filter_strategy()
    strategies = [s["strategy"] for s in result["strategies"]]
    assert result["policy"] == "methods, not payloads"
    assert len(strategies) >= 5
    for s in result["strategies"]:
        blob = (s["strategy"] + " " + s["note"]).lower()
        assert "<script" not in blob
        assert "onerror" not in blob and "alert(" not in blob
        assert len(blob) < 400


def test_countermeasures_pairing():
    agent = create_agent("kali_v2")
    cm = agent.xss_countermeasures()
    assert cm["prevention"] and cm["detection"]
    joined = " ".join(cm["prevention"]).lower()
    assert "csp" in joined and "encode" in joined
    det = " ".join(cm["detection"]).lower()
    assert "service-worker" in det
    # in-house wording, no payload text
    for line in cm["prevention"] + cm["detection"]:
        assert "<script" not in line.lower()


def test_tool_lookup():
    agent = create_agent("kali")
    hits = agent.xss_tool_lookup("interact")
    assert hits["hits"]
    names = [h["name"] for h in hits["hits"]]
    assert "Interactsh" in names
    assert hits["hits"][0]["url"].startswith("https://")
    empty = agent.xss_tool_lookup("qqqqzzzz")
    assert empty["hits"] == [] and not empty["truncated"]
    with pytest.raises(ValueError):
        agent.xss_tool_lookup("x")
    with pytest.raises(ValueError):
        agent.xss_tool_lookup("")


@pytest.mark.parametrize("evil", [
    "example.com; shutdown -h now", "example.com $(curl evil)",
    "example.com\nnewlines", "10.0.0.5 && whoami", "", None,
])
def test_target_scrub_rejects(evil):
    agent = create_agent("kali")
    with pytest.raises(ValueError):
        agent.plan_xss_exploit(evil)
    with pytest.raises(ValueError):
        agent.xss_callback_commands(evil)


def test_no_execution_and_no_payload_blobs():
    src, cat = _catalog()

    code = src.read_text()
    assert "subprocess" not in code
    assert "os.system" not in code
    assert "eval(" not in code

    longest = 0
    for entry in cat["phases"].values():
        for t in entry["tools"]:
            longest = max(longest, len(t["name"]), len(t["url"]),
                          len(t["purpose"]))
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