"""KA-036 tests - WirelessMixin: the capture arc (the monitor-mode
commands), the rogue-AP play with its RF-lab consent phase, the
detection notes, the interface guard (scrub), the policy on EVERY
phase, and the never-executes scan. No network; no RF anywhere."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.wireless_pentest import WirelessMixin


def test_capture_arc_full_structure():
    plan = WirelessMixin().plan_wireless_capture("wlan0mon")
    assert plan["interface"] == "wlan0mon"
    assert plan["policy"] == {"rf_lab_only": True}
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-monitor-mode", "3-capture",
                   "4-analyze", "5-evidence", "6-hardening"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"rf_lab_only": True}
        assert "{interface}" not in json.dumps(phase)
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("airmon-ng check kill") for c in cmds)
    assert any(c.startswith("airodump-ng wlan0mon") for c in cmds)


def test_channel_note_optional():
    plan = WirelessMixin().plan_wireless_capture("wlan0mon", channel="6")
    assert plan["channel_note"] == '{"channel": "6"}'
    plan2 = WirelessMixin().plan_wireless_capture("wlan0mon")
    assert plan2["channel_note"] == ""


def test_rogue_ap_play_consented_by_design():
    play = WirelessMixin().rogue_ap_playbook("lab-ssid-fixture", "wlan0mon")
    assert play["ssid"] == "lab-ssid-fixture"
    assert play["policy"] == {"rf_lab_only": True}
    ids = [p["phase"] for p in play["phases"]]
    assert ids[0] == "1-consent"
    assert "enclosure" in json.dumps(play["phases"][0])
    cmds = [c for p in play["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("hostapd ") for c in cmds)
    assert all("{interface}" not in c and "{ssid_label}" not in c for c in cmds)


def test_interface_guard_scrubs():
    with pytest.raises(ValueError):
        WirelessMixin().plan_wireless_capture("wlan0; calc")
    with pytest.raises(ValueError):
        WirelessMixin().rogue_ap_playbook("ssid|pipe", "wlan0mon")


def test_detection_notes_shape():
    notes = WirelessMixin().wireless_detection_notes()
    assert [n["ttp"] for n in notes["notes"]] == [
        "rogue-ap", "deauth-storm", "evil-twin"]


def test_module_never_executes():
    import agentic_ai.agents.cyber.wireless_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
