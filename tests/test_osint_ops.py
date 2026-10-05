"""KA-037 tests - OSINTMixin: the lane validation (the aliases + the
unknown + None), the step catalogs per lane (the placeholders IN, the
targets substituted in the plan), the 5-phase arc, the detection notes,
the key-HOLDER placeholders stay literal (no real keys anywhere), and
the never-executes scan. No network; no execution."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.osint_pentest import OSINTMixin


@pytest.mark.parametrize("lane,input_value", [
    ("domain", "domain"), ("email", "email"), ("email", "MAILBOX"),
    ("persona", "persona"), ("persona", "handle"),
])
def test_plan_osint_lanes_and_aliases(lane, input_value):
    plan = OSINTMixin().plan_osint("lab-asset.example", input_value)
    assert plan["lane"] == lane and plan["target"] == "lab-asset.example"
    assert plan["policy"] == {"passive_only": True}
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-catalog", "3-collection", "4-pivot",
                   "5-report"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"passive_only": True}


def test_plan_unknown_lane_refused():
    with pytest.raises(ValueError) as err:
        OSINTMixin().plan_osint("x.example", "blockchain")
    assert "known: domain, email, persona" in str(err.value)


def test_catalog_lane_list_and_steps():
    mixin = OSINTMixin()
    index = mixin.osint_step_catalog()
    assert index["lanes"] == ["domain", "email", "persona"]
    domain = mixin.osint_step_catalog("domain")
    assert domain["steps"][0]["step"] == "registrar"
    assert domain["steps"][0]["commands"] == ["whois lab-asset.example"]
    # the crt.sh row substitutes inside the single-quoted curl:
    ct = domain["steps"][2]["commands"][0]
    assert "crt.sh/?q=%25.lab-asset.example" in ct
    email = mixin.osint_step_catalog("email")
    # the API key = a placeholder, never a real key:
    joined = " ".join(c for s in email["steps"] for c in s["commands"])
    assert "<HBPLACEHOLDER>" in joined and "hbpw-KEY" not in joined


def test_persona_lane_shape():
    persona = OSINTMixin().osint_step_catalog("persona")
    assert any(c.startswith("sherlock ") for s in persona["steps"]
               for c in s["commands"])


def test_detection_notes_shape():
    notes = OSINTMixin().osint_detection_notes()
    assert [n["ttp"] for n in notes["notes"]] == [
        "recon-noise", "exposure-inventory"]


def test_scrub_rejects_hostile_targets():
    with pytest.raises(ValueError):
        OSINTMixin().plan_osint("x.example; calc", "domain")


def test_module_never_executes():
    import agentic_ai.agents.cyber.osint_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "socket", "keychain"):
        assert banned not in source, banned
    # requests/urllib: the catalog COMMANDS mention curl; the MODULE must
    # never import the network libs:
    assert "import requests" not in source
    assert "import urllib" not in source
