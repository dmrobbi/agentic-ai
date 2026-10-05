"""KA-050 battery: full_engagement composition contract.

Offline; the mixin is instantiated standalone (the family planners load
committed data only) - chassis wiring belongs to the integration task.

Docstring-claim -> proving-test map (every module-docstring claim gets
a pin; conventions require a test per claim):
- composes ONLY the build-time families, by inheritance
      -> test_composes_exactly_the_build_time_families
- imports only the family modules (same-wave siblings stay out)
      -> test_composes_exactly_the_build_time_families
- core arc = recon, web, xss, privesc in that fixed order
      -> test_core_arc_order_and_ops
- core stages are contract data mirrored by full_engagement_index()
      -> test_full_engagement_index_contract_shape
- shared context: ONE scrubbed target everywhere; re-scrubbing the
  normalized value by each downstream guard is idempotent
      -> test_shared_scrubbed_context
- host validate_target consulted via getattr with a silent fallback
      -> test_host_gate_consulted / test_host_gate_silent_fallback
- knobs (platform, osint_lane) are validated by the consuming family
      -> test_privesc_platform_knob / test_osint_lane_knob
- extensions: a lane-name iterable takes the registry defaults, a
  lane->overrides mapping overrides; unknown lanes, duplicates,
  non-string lanes, non-dict overrides, unknown override keys, and
  unsanitary override strings are refused with ValueError
      -> test_default_extension_lane / test_extension_overrides /
         test_extension_override_scrub / test_extension_bad_shapes
- registry order is the extension stage order (caller order is sorted
  back into registry order)
      -> test_extension_registry_order
- a future family plugs in as ONE registry row; the core arc is pinned
      -> test_extendability_one_row_addition
- every registry row matches its family signature (shared_slot = first
  parameter; shared_slot + extras = the full parameter set)
      -> test_extension_registry_rows_match_family_signatures
- planners never execute: no exec/eval/network tokens in the module
      -> test_purity_source_scan
- planned commands carry no unreplaced injection placeholders; every
  returned string is control-char free and size-capped
      -> test_no_unreplaced_target_placeholders /
         test_strings_clean_and_capped
- composition is deterministic (repeatable planning)
      -> test_composition_is_deterministic
"""
from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import full_engagement as fe_module
from agentic_ai.agents.cyber.full_engagement import (
    CORE_STAGES,
    EXTENSION_LANES,
    POLICY,
    FullEngagementMixin,
)
from agentic_ai.agents.cyber.web_pentest import WebPentestMixin, wp_scrub_target
from agentic_ai.agents.cyber.redteam_pentest import RedTeamMixin
from agentic_ai.agents.cyber.xss_exploit import XssMixin
from agentic_ai.agents.cyber.privesc import PrivescMixin
from agentic_ai.agents.cyber.ad_pentest import ADMixin
from agentic_ai.agents.cyber.cloud_pentest import CloudMixin
from agentic_ai.agents.cyber.container_pentest import ContainerMixin
from agentic_ai.agents.cyber.mobile_pentest import MobileMixin
from agentic_ai.agents.cyber.wireless_pentest import WirelessMixin
from agentic_ai.agents.cyber.osint_pentest import OSINTMixin
from agentic_ai.agents.cyber.forensics_ops import ForensicsMixin

FAMILY_CLASSES = (WebPentestMixin, RedTeamMixin, XssMixin, PrivescMixin,
                  ADMixin, CloudMixin, ContainerMixin, MobileMixin,
                  WirelessMixin, OSINTMixin, ForensicsMixin)
FAMILY_MODULES = ("web_pentest", "redteam_pentest", "xss_exploit", "privesc",
                  "ad_pentest", "cloud_pentest", "container_pentest",
                  "mobile_pentest", "wireless_pentest", "osint_pentest",
                  "forensics_ops")
# siblings landing in the same wave; the composer must not know them
EXCLUDED_WAVE_MODULES = ("malware_ops", "malware", "network_device",
                         "api_pentest", "socialeng_ops", "ics_iot",
                         "postexp", "webauth_ops", "chain_ops")
EXTENSION_LANE_ORDER = ("redteam", "ad", "cloud", "container", "mobile",
                        "wireless", "forensics")
INJECTABLE_SLOTS = ("{target}", "{dc}", "{account_label}", "{apk_label}",
                    "{artifact}", "{interface}", "{context_label}")

CORE_RESULT_KEYS = {"target", "platform", "osint_lane", "policy", "stages"}
CORE_STAGE_KEYS = {"stage", "kind", "order", "ops", "plans"}
EXTENSION_STAGE_KEYS = CORE_STAGE_KEYS | {"policy_note"}


def _agent():
    return FullEngagementMixin()


def _module_source():
    module = importlib.import_module("agentic_ai.agents.cyber.full_engagement")
    return Path(module.__file__).read_text(encoding="utf-8")


def _stage(result, name):
    matches = [s for s in result["stages"] if s["stage"] == name]
    assert len(matches) == 1, (name, [s["stage"] for s in result["stages"]])
    return matches[0]


def _strings(node):
    """Every string leaf of a plan/result dict."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            yield from _strings(value)


# --- composition shape ------------------------------------------------------


def test_composes_exactly_the_build_time_families():
    """The mixin rides on ALL landed families - and only those."""
    assert FullEngagementMixin.__bases__ == FAMILY_CLASSES
    source = _module_source()
    imported = set(re.findall(
        r"^from agentic_ai\.agents\.cyber\.(\w+) import", source, re.M))
    assert imported == set(FAMILY_MODULES)
    for excluded in EXCLUDED_WAVE_MODULES:
        assert excluded not in imported


def test_core_arc_order_and_ops():
    """OPT-50's arc: recon -> web -> xss -> privesc, with the per-stage
    family ops exactly as registered."""
    result = _agent().plan_full_engagement("lab.example")
    assert set(result) == CORE_RESULT_KEYS
    assert result["policy"] == POLICY
    assert result["stages"] and [s["stage"] for s in result["stages"]] == \
        [s for s, _ in CORE_STAGES] == ["recon", "web", "xss", "privesc"]
    assert [s["order"] for s in result["stages"]] == [1, 2, 3, 4]
    for stage, (_, ops) in zip(result["stages"], CORE_STAGES):
        assert set(stage) == CORE_STAGE_KEYS
        assert stage["kind"] == "core"
        assert stage["ops"] == list(ops)
        assert list(stage["plans"]) == list(ops)
        for plan in stage["plans"].values():
            assert isinstance(plan, dict) and "target" in plan
    # each family phase list arrives structured (shape, not prose)
    for stage in result["stages"]:
        for plan in stage["plans"].values():
            if "phases" in plan:
                assert plan["phases"]
                for phase in plan["phases"]:
                    # required composition keys; family extras (xss's
                    # per-phase policy) are the family's own battery's pin
                    assert {"phase", "goal", "activities",
                            "sample_commands"} <= set(phase)
                    assert phase["activities"] and phase["sample_commands"]
            if "steps" in plan:
                assert plan["steps"]
                for step in plan["steps"]:
                    assert set(step) == {"step", "commands"}
                    assert step["commands"]
    # a family's policy dict travels inside its plan (composition behavior;
    # the policy CONTENTS stay the family's own battery's business)
    assert isinstance(_stage(result, "recon")
                      ["plans"]["plan_osint"]["policy"], dict)


def test_shared_scrubbed_context():
    """ONE scrubbed target: normalized once, identical everywhere."""
    result = _agent().plan_full_engagement("  lab.example  ")
    assert result["target"] == "lab.example" == wp_scrub_target(" lab.example ")
    for stage in result["stages"][:4]:
        for plan in stage["plans"].values():
            assert plan["target"] == "lab.example"


def test_composition_is_deterministic():
    """Same call, same plan - planning is repeatable."""
    first = _agent().plan_full_engagement("lab.example")
    second = _agent().plan_full_engagement("lab.example")
    assert first == second


# --- host boundary ----------------------------------------------------------


def test_host_gate_silent_fallback():
    """No chassis gate present: composition still works (silent fallback)."""
    agent = _agent()
    assert not hasattr(agent, "validate_target")
    assert _agent().plan_full_engagement("lab.example")["stages"]


def test_host_gate_consulted():
    """The scrubbed target reaches the host gate; a rejection aborts."""
    agent = _agent()
    seen = []

    def gate(target):
        seen.append(target)
        return (True, "")

    agent.validate_target = gate
    result = agent.plan_full_engagement("  lab.example  ")
    assert seen and seen[0] == "lab.example"
    rejecting = _agent()
    rejecting.validate_target = lambda target: (False, "outside scope")
    with pytest.raises(ValueError) as err:
        rejecting.plan_full_engagement("lab.example")
    assert "host agent gate" in str(err.value)


@pytest.mark.parametrize("evil", [
    "lab.example; shutdown -h now", "lab.example $(curl evil)",
    "lab.example\nnewlines", "10.0.0.5 && whoami", "", "   ", None, 42,
    "lab.example ..//..\\..", 'lab.example "<>;',
])
def test_evil_targets_rejected(evil):
    """House hostile-input sweep: ValueError or clean, never a crash."""
    with pytest.raises(ValueError):
        _agent().plan_full_engagement(evil)


# --- core knobs -------------------------------------------------------------


def test_privesc_platform_knob():
    """Platform is the privesc family's business: canon + aliases + reject."""
    result = _agent().plan_full_engagement("lab.example", platform="windows")
    assert result["platform"] == "windows"
    assert _stage(result, "privesc")["plans"]["plan_privesc"]["platform"] == \
        "windows"
    assert _agent().plan_full_engagement(
        "lab.example", platform="macos")["platform"] == "unix"
    with pytest.raises(ValueError) as err:
        _agent().plan_full_engagement("lab.example", platform="beos")
    assert "known: unix, linux, macos, windows" in str(err.value)


def test_osint_lane_knob():
    """The recon lane is the osint family's business."""
    result = _agent().plan_full_engagement("lab.example", osint_lane="email")
    assert result["osint_lane"] == "email"
    assert _stage(result, "recon")["plans"]["plan_osint"]["lane"] == "email"
    with pytest.raises(ValueError) as err:
        _agent().plan_full_engagement("lab.example", osint_lane="grapevine")
    assert "known: domain, email, persona" in str(err.value)


# --- extension contract -----------------------------------------------------


def test_full_engagement_index_contract_shape():
    """full_engagement_index() mirrors the constants - the contract as data."""
    idx = _agent().full_engagement_index()
    assert set(idx) == {"policy", "core_stages", "extensions"}
    assert idx["policy"] == POLICY
    assert idx["core_stages"] == [
        {"stage": "recon", "kind": "core",
         "ops": ["plan_osint", "web_recon_commands"]},
        {"stage": "web", "kind": "core",
         "ops": ["plan_web_pentest", "web_enum_commands"]},
        {"stage": "xss", "kind": "core", "ops": ["plan_xss_exploit"]},
        {"stage": "privesc", "kind": "core", "ops": ["plan_privesc"]},
    ]
    rows = idx["extensions"]
    assert [row["lane"] for row in rows] == list(EXTENSION_LANE_ORDER)
    for row in rows:
        assert set(row) == {"lane", "planner", "shared_slot", "extra_kwargs",
                            "defaults", "policy_note"}
        assert callable(getattr(FullEngagementMixin, row["planner"]))
        assert row["policy_note"]


def test_extension_registry_rows_match_family_signatures():
    """One row per family: shared_slot = first parameter, and the shared
    slot plus the extras cover the planner's full parameter set."""
    for lane, row in EXTENSION_LANES.items():
        planner = getattr(FullEngagementMixin, row["planner"])
        params = list(inspect.signature(planner).parameters)[1:]  # drop self
        assert params, (lane, row["planner"])
        assert row["shared_slot"] == params[0], (lane, params)
        assert {row["shared_slot"], *row["extra_kwargs"]} == set(params), \
            (lane, params)
        assert len(row["defaults"]) == len(row["extra_kwargs"]), lane


def test_default_extension_lane():
    result = _agent().plan_full_engagement("lab.example",
                                           extensions=("redteam",))
    assert [s["stage"] for s in result["stages"]] == \
        ["recon", "web", "xss", "privesc", "redteam"]
    stage = _stage(result, "redteam")
    assert set(stage) == EXTENSION_STAGE_KEYS
    assert stage["kind"] == "extension" and stage["order"] == 5
    assert stage["ops"] == ["plan_redteam"]
    assert list(stage["plans"]) == ["plan_redteam"]
    assert stage["policy_note"] == EXTENSION_LANES["redteam"]["policy_note"]
    # the shared scrubbed context feeds the extension planner, too
    red_plan = stage["plans"]["plan_redteam"]
    assert red_plan["scope"] == result["target"]
    assert red_plan["phases"]


def test_extension_registry_order():
    """Caller ordering never leaks: stages follow registry order."""
    result = _agent().plan_full_engagement("lab.example",
                                           extensions=("ad", "redteam"))
    assert [(s["stage"], s["order"]) for s in result["stages"][4:]] == \
        [("redteam", 5), ("ad", 6)]


def test_extension_overrides():
    """Mapping overrides reach the family planners (and safe defaults apply)."""
    agent = _agent()
    result = agent.plan_full_engagement(
        "lab.example", extensions={"cloud": {"cloud": "azure"}})
    assert _stage(result, "cloud")["plans"]["plan_cloud"]["cloud"] == "azure"
    result = agent.plan_full_engagement(
        "lab.example", extensions={"ad": {"dc": "dc01.lab.example"}})
    ad_plan = _stage(result, "ad")["plans"]["plan_ad"]
    assert ad_plan["dc"] == "dc01.lab.example"
    result = agent.plan_full_engagement(
        "lab.example", extensions={"redteam": {"scope": "scope.example"}})
    red_plan = _stage(result, "redteam")["plans"]["plan_redteam"]
    assert red_plan["scope"] == "scope.example"
    # registry defaults, applied without overrides
    result = agent.plan_full_engagement("lab.example", extensions=("cloud",))
    assert _stage(result, "cloud")["plans"]["plan_cloud"]["cloud"] == "aws"
    result = agent.plan_full_engagement("lab.example", extensions=("wireless",))
    wireless_plan = _stage(result, "wireless")["plans"]["plan_wireless_capture"]
    assert wireless_plan["channel_note"] == ""


@pytest.mark.parametrize(("lane", "overrides"), [
    ("ad", {"dc": "dc01; rm -rf /"}),
    ("redteam", {"scope": "a\nb"}),
    ("wireless", {"channel": "6 && reboot"}),
    # enum slots skip the scrub but the family alias table refuses junk
    ("cloud", {"cloud": "aws; rm -rf /"}),
])
def test_extension_override_scrub(lane, overrides):
    with pytest.raises(ValueError):
        _agent().plan_full_engagement("lab.example",
                                      extensions={lane: overrides})


@pytest.mark.parametrize("extensions", [
    ("teleport",), {"teleport": {}}, ("ad", "ad"), ("ad", 42), 42, "ad",
    {"ad": 42}, {"ad": {"nope": 1}},
])
def test_extension_bad_shapes(extensions):
    """Unknown lanes, duplicates, wrong lane types, bad override shapes:
    all ValueError, deterministic."""
    with pytest.raises(ValueError):
        _agent().plan_full_engagement("lab.example", extensions=extensions)


def test_extendability_one_row_addition(monkeypatch):
    """The extendability claim: ONE registry row wires a future family in;
    the core arc stands unchanged."""
    registry = dict(EXTENSION_LANES)
    registry["demo"] = {
        "planner": "plan_web_pentest", "shared_slot": "target",
        "extra_kwargs": (), "defaults": (),
        "policy_note": "demo row proving the one-row extension",
    }
    monkeypatch.setattr(fe_module, "EXTENSION_LANES", registry)
    result = _agent().plan_full_engagement("lab.example",
                                           extensions=("demo",))
    stages = result["stages"]
    assert [s["stage"] for s in stages[:4]] == ["recon", "web", "xss", "privesc"]
    assert [s["kind"] for s in stages[:4]] == ["core"] * 4
    assert stages[4]["stage"] == "demo"
    assert stages[4]["kind"] == "extension" and stages[4]["order"] == 5
    demo_plan = stages[4]["plans"]["plan_web_pentest"]
    assert demo_plan["target"] == result["target"]


# --- output hygiene ---------------------------------------------------------


def test_no_unreplaced_target_placeholders():
    """Every injection slot is replaced - nothing raw ever leaves a plan."""
    results = [_agent().plan_full_engagement("lab.example")]
    results.append(_agent().plan_full_engagement(
        "lab.example", extensions=list(EXTENSION_LANE_ORDER)))
    for result in results:
        for text in _strings(result):
            for slot in INJECTABLE_SLOTS:
                assert slot not in text, (slot, text)


def test_strings_clean_and_capped():
    """No control characters; no string outgrows the planning cap."""
    results = [_agent().plan_full_engagement("lab.example")]
    results.append(_agent().plan_full_engagement(
        "lab.example", extensions=list(EXTENSION_LANE_ORDER)))
    for result in results:
        for text in _strings(result):
            assert all(ord(ch) >= 32 for ch in text), repr(text)
            assert len(text) < 500, len(text)


def test_purity_source_scan():
    """Planners never execute: the house banned-token scan, extended."""
    source = _module_source()
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "http.client"):
        assert banned not in source, banned