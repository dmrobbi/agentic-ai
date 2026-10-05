"""KA-032 tests - ADMixin: the lab-only policy tag on EVERY phase and
the module doc, the 6-arc shape/order, the catalog's target/dc
substitution, the detection notes' shapes, the public-domain refusal,
the scrub + host-gate consult (the local composite = the KA-031
pattern), and the never-executes scan. No network; no execution."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent
from agentic_ai.agents.cyber.ad_pentest import ADMixin, LAB_HOOK

BENIGN = "lab-host1.lab.example"
DC = "dc1.lab.example"


@pytest.fixture()
def bare_host():
    return ADMixin()


def test_module_lab_policy_and_hook():
    import agentic_ai.agents.cyber.ad_pentest as mod
    assert mod.PHASE_POLICY == {"lab_only": True}
    assert mod.LAB_HOOK["battery"] == "tests/lab/test_planner_parity.py"
    assert mod.LAB_HOOK["env"] == "KA_LAB_BATTERY"
    doc = (mod.__doc__ or "").lower()
    assert "lab-only" in doc
    index = ADMixin().ad_index()
    assert index["policy"] == {"lab_only": True}


def test_plan_ad_full_arc(bare_host):
    plan = bare_host.plan_ad(BENIGN, dc=DC)
    assert plan["target"] == BENIGN and plan["dc"] == DC
    assert plan["policy"] == {"lab_only": True}
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-enumerate", "3-auth-surface",
                   "4-strategy", "5-evidence", "6-detection"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"lab_only": True}
        assert phase["activities"] and phase["sample_commands"]


def test_catalog_substitutes_both_tokens(bare_host):
    out = bare_host.ad_command_catalog(BENIGN, dc=DC)
    assert out["target"] == BENIGN and out["dc"] == DC
    steps = out["steps"]
    assert steps[0]["step"] == "dc-discovery"
    for step in steps:
        for cmd in step["commands"]:
            assert "{target}" not in cmd and "{dc}" not in cmd
    # a sample row:
    assert any("nltest /dclist:" + BENIGN in step["commands"]
               for step in steps)


def test_plan_refuses_public_domain_scope(bare_host):
    with pytest.raises(ValueError) as err:
        bare_host.plan_ad("corp.example.com")
    assert "lab-only policy" in str(err.value)


def test_guards_and_host_gate_composite(chassis):
    # scrub: metachar scope never reaches planning
    with pytest.raises(ValueError):
        ADMixin().plan_ad("192.0.2.1; calc")
    # the host-gate consult = the composed shape (local composite):
    class HostWithGate(ADMixin):
        def __init__(self, agent):
            self._agent = agent
        def validate_target(self, target):
            return self._agent.validate_target(target)
    host = HostWithGate(chassis)
    chassis.add_to_blacklist("192.0.2.66")
    try:
        with pytest.raises(ValueError) as err:
            host.plan_ad("192.0.2.66")
        assert "target rejected by host agent gate" in str(err.value)
    finally:
        chassis.remove_from_blacklist("192.0.2.66")


def test_detection_notes_shape():
    notes = ADMixin().ad_detection_notes()
    assert [n["ttp"] for n in notes["notes"]] == [
        "kerberoast-attempts", "asrep-roast", "dcsync-patterns",
        "smb-null-sessions"]
    assert all(n["note"] for n in notes["notes"])


@pytest.fixture(scope="module")
def chassis(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka032")
    agent = KaliAgent(agent_id="ka032", workspace=str(ws / "ws"),
                      log_dir=str(ws / "logs"))
    return agent


def test_module_never_executes():
    import agentic_ai.agents.cyber.ad_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
