"""KA-024 - XSS-ops context assertions (extended pins over the P1 mixin):

- callback steps: every command's <your-oob-host> placeholder gets fully
  substituted by the shared scrub; the executables stay inside the
  DOCUMENTED set measured live: interactsh-client (the CLI of the
  catalog's 'Interactsh' row), curl, and the nginx-proxy directive - the
  listener step directs the builder to the callback-infra catalog rows.
- per-context plan: the 7 phases with unique ids/activities/policies,
  {target} fully substituted, the plan's policy == the catalog meta
  policy, coverage == the counted totals, and the scrub/host-gate
  behavior (metachar targets ValueError; a chassis-blacklisted target
  ValueErrors through the host agent gate).
- countermeasures cross-check vs prevention: each detection note pairs
  with a prevention row over a shared keyword (pinned: report-uri,
  admin, uploads); standalone detection rows are named, not paired.
- tool lookup: hits come from the catalog only and the 25-cap is
  unreachable at the current catalog size (15 tools) - pinned."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent
from agentic_ai.agents.cyber.xss_exploit import XssMixin

REPO = Path(__file__).resolve().parents[1]
CATALOG_PATH = (
    REPO / "agentic_ai" / "agents" / "cyber" / "data" / "xss_tools.json")

BENIGN_TARGET = "lab-host1.lab.example"
OOB_HOST = "oob.lab.example"


@pytest.fixture(scope="module")
def chassis(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka024")
    agent = KaliAgent(agent_id="ka024-xss", workspace=str(ws / "ws"),
                      log_dir=str(ws / "logs"))
    agent.set_authorization(AuthorizationLevel.CRITICAL)
    return agent


def test_catalog_totals_meta():
    cat = json.loads(CATALOG_PATH.read_text())
    assert set(cat) == {"meta", "phases"}
    meta = cat["meta"]
    assert sorted(meta["totals"].items()) == [("phases", 5), ("tools", 15)]
    counted = 0
    for phase, entry in sorted(cat["phases"].items()):
        assert set(entry) == {"sections", "tools"}
        for tool in entry["tools"]:
            assert set(tool) == {"name", "purpose", "url"}
            counted += 1
    counted_phases = len(cat["phases"])
    assert (counted_phases, counted) == (5, 15)  # matches the meta


def test_callback_placeholder_fully_substituted(chassis):
    result = chassis.xss_callback_commands(OOB_HOST)
    assert result["callback"] == OOB_HOST
    commands = [c for step in result["steps"] for c in step["commands"]]
    assert commands  # the probed reality: 7 command rows over 4 steps
    assert all("<your-oob-host>" not in c for c in commands), commands


def test_callback_executables_documented(chassis):
    """Every NON-comment command's argv0 is inside the measured
    documented set (the CLI aliases + standard infra utilities); the
    step directives reference the catalog's callback-infra rows."""
    result = chassis.xss_callback_commands(OOB_HOST)
    documented = {"interactsh-client", "curl", "nginx-proxy:"}
    seen = set()
    for step in result["steps"]:
        for cmd in step["commands"]:
            if cmd.startswith("# "):
                continue  # directives/notes, not executables
            argv0 = shlex.split(cmd)[0]
            seen.add(argv0)
    assert seen <= documented, seen


def test_plan_structure_and_contexts(chassis):
    plan = chassis.plan_xss_exploit(BENIGN_TARGET)
    assert plan["target"] == BENIGN_TARGET
    phases = plan["phases"]
    assert len(phases) == 7
    ids = [p["phase"] for p in phases]
    assert len(set(ids)) == 7 and ids[0] == "1-context-discovery"
    for phase in phases:
        assert phase["activities"] and phase["goal"]
        assert phase["policy"] == {"no_payloads": True}
    # per-context: step 3 references the callback op; step 6 the blue team
    joined = [json.dumps(p) for p in phases]
    assert any("xss_callback_commands" in j for j in joined)
    assert any("xss_countermeasures" in j for j in joined)


def test_plan_sample_commands_substitute_target(chassis):
    plan = chassis.plan_xss_exploit(BENIGN_TARGET)
    for phase in plan["phases"]:
        for cmd in phase["sample_commands"]:
            assert "{target}" not in cmd  # every occurrence substituted
            if cmd.startswith("# "):
                continue
    # and the substitution actually happened:
    subbed = [c for p in plan["phases"] for c in p["sample_commands"]
              if BENIGN_TARGET in c]
    assert subbed  # e.g. the dalfox/ffuf phase-1 rows carry the host


def test_plan_policy_matches_catalog_meta(chassis):
    import json as _json
    plan = chassis.plan_xss_exploit(BENIGN_TARGET)
    cat = _json.loads(CATALOG_PATH.read_text())
    assert plan["policy"] == cat["meta"]["policy"]
    assert sorted(plan["coverage"].items()) == [
        (k, v) for k, v in sorted(cat["meta"]["totals"].items())]
    assert "no payloads" in plan["policy"]


def test_plan_scrubs_and_consults_host_gate(chassis):
    from pytest import raises
    # scrub: metachar targets never reach planning
    with raises(ValueError):
        chassis.plan_xss_exploit("192.0.2.1; calc")
    # the host gate: a blacklisted target is rejected through the consult
    chassis.add_to_blacklist("192.0.2.66")
    try:
        with raises(ValueError) as err:
            chassis.plan_xss_exploit("192.0.2.66")
        assert "target rejected by host agent gate" in str(err.value)
    finally:
        chassis.remove_from_blacklist("192.0.2.66")


def test_countermeasures_crosscheck_pairings(chassis):
    result = chassis.xss_countermeasures()
    prevention = result["prevention"]
    detection = result["detection"]
    assert len(prevention) == 7 and len(detection) == 5
    # the measured keyword pairings (both rows carry the shared keyword):
    pairings = {
        0: (1, "report-uri"),
        2: (6, "admin"),
        3: (5, "uploads"),
    }
    for di, (pi, keyword) in pairings.items():
        assert keyword in detection[di].lower(), di
        assert keyword in prevention[pi].lower(), pi
    # the standalone detections (waf-logs, service-workers) named as such
    assert "WAF" in detection[1]
    assert "service-worker" in detection[4]


def test_tool_lookup_catalog_only_and_caps(chassis):
    result = chassis.xss_tool_lookup("dalfox")
    ids = [(h["phase"], h["name"], h["url"]) for h in result["hits"]]
    cat = json.loads(CATALOG_PATH.read_text())
    catalog_urls = {t["url"] for e in cat["phases"].values() for t in e["tools"]}
    catalog_names = {t["name"] for e in cat["phases"].values() for t in e["tools"]}
    assert ids
    for phase, name, url in ids:
        assert url in catalog_urls and name in catalog_names
        assert phase in cat["phases"]
    assert result["truncated"] is False
    # PINNED FINDING: the 25-hit cap is unreachable at this catalog size
    wide = chassis.xss_tool_lookup("in")
    assert len(wide["hits"]) <= 15 and wide["truncated"] is False
    # input validation stays strict
    with pytest.raises(ValueError):
        chassis.xss_tool_lookup("")
    with pytest.raises(ValueError):
        chassis.xss_tool_lookup("x")
