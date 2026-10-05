"""KA-035 tests - MobileMixin: the apk/ipa arcs (static-first policy on
every phase, dynamic = lab-only labels), the label guard, the
detection notes, the lane separation, and the never-executes scan.
No network; no execution."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.mobile_pentest import MobileMixin


def test_policy_and_lanes():
    mixin = MobileMixin()
    index = mixin.mobile_index()
    assert index["policy"] == {"static_first": True,
                               "dynamic_requires_lab": True}
    assert index["lanes"] == ["apk", "ipa"]


def test_plan_apk_arc_and_substitution():
    plan = MobileMixin().plan_mobile_apk("lab-app-debug.apk")
    assert plan["lane"] == "apk" and plan["label"] == "lab-app-debug.apk"
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-static-structure", "3-static-deep",
                   "4-dynamic-lab", "5-evidence", "6-hardening"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"static_first": True,
                                   "dynamic_requires_lab": True}
        assert "{apk_label}" not in json.dumps(phase)
    # static tools really named:
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("apktool d ") for c in cmds)
    assert any(c.startswith("jadx -d ") for c in cmds)


def test_plan_ipa_arc_and_separation():
    plan = MobileMixin().plan_mobile_ipa("lab-app.ipa")
    assert plan["lane"] == "ipa"
    ids = [p["phase"] for p in plan["phases"]]
    assert ids[1] == "2-static-structure" and ids[3] == "4-dynamic-lab"
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("otool -L ") for c in cmds)
    assert all("{ipa_label}" not in c for c in cmds)
    # apk tools must NOT leak into the ipa plan:
    assert not any("apktool" in c for c in cmds)


def test_label_guard():
    with pytest.raises(ValueError):
        MobileMixin().plan_mobile_apk("")
    with pytest.raises(ValueError):
        MobileMixin().plan_mobile_apk("bad label with spaces")
    with pytest.raises(ValueError):
        MobileMixin().plan_mobile_apk("x" * 100)


def test_detection_notes_shape():
    notes = MobileMixin().mobile_detection_notes()
    assert [n["ttp"] for n in notes["notes"]] == [
        "debuggable-release", "exported-components", "cleartext-traffic",
        "cert-pinning-missing"]


def test_module_never_executes():
    import agentic_ai.agents.cyber.mobile_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "frida."):
        assert banned not in source, banned
