"""KA-043 tests - IcsIoTMixin: the air-gapped-lab refusal (hard policy
on every target-bearing op), the staging vocabulary, the Modbus/S7
read-only arcs, the firmware flow's binwalk tie-in, the raw firmware
templates, the per-protocol catalog's substitution, the unit-id guard,
the scrub + host-gate consult composite, the detection notes, and the
never-executes scan. No network; no execution; the lab only."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.ics_iot import IcsIoTMixin

BENIGN = "lab-plc-01"
IMAGE = "lab-fw-image.bin"
S7_TARGET = "lab-cpu-1512"

MODBUS_PHASE_IDS = ("1-scope", "2-passive", "3-identify", "4-map",
                    "5-evidence", "6-detection")
S7_PHASE_IDS = ("1-scope", "2-passive", "3-identify", "4-map",
                "5-evidence", "6-detection")
FIRMWARE_PHASE_IDS = ("1-acquire", "2-verify", "3-binwalk", "4-unpack",
                      "5-triage", "6-report")

ACCEPTED_STAGING = ("air_gapped_lab", "air-gapped-lab", "airgapped",
                    "air_gapped", "air-gapped", "air_gap", "airgap",
                    "ics_lab", "ics-lab", "ot_lab", "ot-lab")


def test_module_policy_and_doc():
    import agentic_ai.agents.cyber.ics_iot as mod
    assert mod.STAGING_POLICY == {"air_gapped_lab_required": True}
    assert mod.FIRMWARE_POLICY == {"air_gapped_lab_required": True,
                                   "work_on_copies": True,
                                   "static_only": True}
    doc = (mod.__doc__ or "").lower()
    assert "air-gapped" in doc
    assert "binwalk" in doc
    class_doc = (IcsIoTMixin.__doc__ or "").lower()
    assert "no execution" in class_doc
    assert "air-gapped lab" in class_doc
    index = IcsIoTMixin().ics_iot_index()
    assert index["protocols"] == ["modbus", "s7"]
    assert index["policy"] == {"air_gapped_lab_required": True}
    assert index["firmware_policy"] == dict(mod.FIRMWARE_POLICY)
    assert index["staging"]["canonical"] == "air_gapped_lab"
    assert "air_gapped_lab" in index["staging"]["accepted"]


def test_plan_modbus_full_arc():
    plan = IcsIoTMixin().plan_modbus(BENIGN, "air_gapped_lab")
    assert plan["target"] == BENIGN
    assert plan["protocol"] == "modbus"
    assert plan["staging"] == "air_gapped_lab"
    assert plan["policy"] == {"air_gapped_lab_required": True}
    assert tuple(p["phase"] for p in plan["phases"]) == MODBUS_PHASE_IDS
    for phase in plan["phases"]:
        assert phase["policy"] == {"air_gapped_lab_required": True}
        assert phase["activities"] and phase["sample_commands"]
        for cmd in phase["sample_commands"]:
            assert "{target}" not in cmd and "{tap}" not in cmd
            assert "{unit}" not in cmd
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("tcpdump -i tap0 -w lab-modbus-passive.pcap")
               for c in cmds)
    assert any(c.startswith("nmap -sT -p 502 --script modbus-discover "
                            + BENIGN) for c in cmds)
    assert any(c.startswith("mbpoll -m tcp -a 1") for c in cmds)
    assert any("port 502" in c for c in cmds)


@pytest.mark.parametrize("staging", ACCEPTED_STAGING)
def test_plan_modbus_accepts_staging_aliases(staging):
    plan = IcsIoTMixin().plan_modbus(BENIGN, staging)
    assert plan["staging"] == "air_gapped_lab"
    assert plan["policy"] == {"air_gapped_lab_required": True}
    assert plan["target"] == BENIGN


def test_plan_modbus_default_tap_and_unit():
    plan = IcsIoTMixin().plan_modbus(BENIGN, "airgap", unit_id=17,
                                     tap="tap-ics")
    assert plan["unit_id"] == "17"
    assert plan["tap"] == "tap-ics"
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any("-a 17 " in c for c in cmds)
    assert any("tcpdump -i tap-ics" in c for c in cmds)


def test_plan_s7_full_arc():
    plan = IcsIoTMixin().plan_s7(S7_TARGET, "ics-lab")
    assert plan["target"] == S7_TARGET
    assert plan["protocol"] == "s7"
    assert plan["staging"] == "air_gapped_lab"
    assert plan["tap"] == "tap0"
    assert plan["policy"] == {"air_gapped_lab_required": True}
    assert tuple(p["phase"] for p in plan["phases"]) == S7_PHASE_IDS
    for phase in plan["phases"]:
        assert phase["policy"] == {"air_gapped_lab_required": True}
        for cmd in phase["sample_commands"]:
            assert "{target}" not in cmd and "{tap}" not in cmd
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("tcpdump -i tap0 -w lab-s7-passive.pcap "
                            "port 102") for c in cmds)
    assert any(c.startswith("nmap -sT -p 102 --script s7-info "
                            + S7_TARGET) for c in cmds)
    assert not any(c.startswith("mbpoll") for c in cmds)


@pytest.mark.parametrize("staging", ["internet", "production",
                                     "plant-floor", "office", "cloud",
                                     "corp-net", "lab"])
def test_all_planners_refuse_non_lab_staging(staging):
    # plain "lab" refuses too: only an air-gapped-lab claim passes.
    mixin = IcsIoTMixin()
    calls = (lambda: mixin.plan_modbus(BENIGN, staging),
             lambda: mixin.plan_s7(S7_TARGET, staging),
             lambda: mixin.firmware_flow(IMAGE, staging),
             lambda: mixin.protocol_command_catalog("modbus", BENIGN,
                                                    staging))
    for call in calls:
        with pytest.raises(ValueError) as err:
            call()
        assert "air-gapped" in str(err.value)


def test_plan_refuses_empty_staging():
    with pytest.raises(ValueError) as err:
        IcsIoTMixin().plan_modbus(BENIGN, "")
    assert "air-gapped" in str(err.value)
    with pytest.raises(ValueError):
        IcsIoTMixin().plan_s7(S7_TARGET, "   ")


def test_protocol_command_catalog_substitution():
    mixin = IcsIoTMixin()
    catalog = mixin.protocol_command_catalog("modbus_tcp", BENIGN,
                                             "air_gapped_lab")
    assert catalog["protocol"] == "modbus"  # the tcp alias resolves
    assert catalog["target"] == BENIGN and catalog["unit_id"] == "1"
    assert catalog["policy"] == {"air_gapped_lab_required": True}
    steps = catalog["steps"]
    assert [s["step"] for s in steps] == ["discovery", "device-info",
                                          "reads"]
    assert steps[0]["commands"] == ["nmap -sT -Pn -n -p 502 --open "
                                    + BENIGN]
    joined = " ".join(c for s in steps for c in s["commands"])
    assert "mbpoll -m tcp -a 1 -t 3 -r 1 -c 8 -1 " + BENIGN in joined
    assert "mbpoll -m rtu" in joined
    for cmd in joined.split(" "):
        assert cmd != "{target}"

    s7cat = mixin.protocol_command_catalog("siemens", S7_TARGET,
                                           "ics_lab")
    assert s7cat["protocol"] == "s7"
    joined7 = " ".join(c for s in s7cat["steps"] for c in s["commands"])
    assert "s7-info " + S7_TARGET in joined7
    assert "{target}" not in joined7 and "{unit}" not in joined7


@pytest.mark.parametrize("protocol", ["dnp3", "ethernet-ip"])
def test_unknown_protocol_refused(protocol):
    with pytest.raises(ValueError) as err:
        IcsIoTMixin().protocol_command_catalog(protocol, BENIGN,
                                               "air_gapped_lab")
    assert "known: modbus, s7" in str(err.value)


def test_protocol_empty_refused():
    with pytest.raises(ValueError):
        IcsIoTMixin().protocol_command_catalog("", BENIGN,
                                               "air_gapped_lab")


def test_firmware_flow_structure():
    plan = IcsIoTMixin().firmware_flow(IMAGE, "air_gapped_lab")
    assert plan["image"] == IMAGE
    assert plan["staging"] == "air_gapped_lab"
    assert plan["policy"] == {"air_gapped_lab_required": True,
                              "work_on_copies": True,
                              "static_only": True}
    assert tuple(p["phase"] for p in plan["phases"]) == FIRMWARE_PHASE_IDS
    for phase in plan["phases"]:
        assert phase["policy"] == dict(plan["policy"])
        for cmd in phase["sample_commands"]:
            assert "{image}" not in cmd
    binwalk = plan["phases"][2]
    assert binwalk["phase"] == "3-binwalk"
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any(c.startswith("binwalk " + IMAGE) for c in cmds)
    assert any(c.startswith("binwalk -E " + IMAGE) for c in cmds)
    assert any(c.startswith("sha256sum " + IMAGE) for c in cmds)
    assert any(c.startswith("binwalk -e " + IMAGE) for c in cmds)


def test_firmware_step_catalog_raw_templates():
    cat = IcsIoTMixin().firmware_step_catalog()
    assert [s["step"] for s in cat["steps"]] == ["acquire-verify",
                                                "signatures", "unpack",
                                                "triage"]
    assert cat["policy"] == {"air_gapped_lab_required": True,
                             "work_on_copies": True,
                             "static_only": True}
    joined = " ".join(c for s in cat["steps"] for c in s["commands"])
    # the RAW catalog keeps its placeholders (unlike the flow)
    assert "{image}" in joined
    assert "binwalk {image}" in joined and "binwalk -E {image}" in joined
    assert "binwalk -e {image}" in joined


@pytest.mark.parametrize("unit", [0, -1, 256, 999, "abc", "1; calc",
                                  True, 1.5])
def test_unit_id_guard_refuses_bad_values(unit):
    with pytest.raises(ValueError):
        IcsIoTMixin().plan_modbus(BENIGN, "air_gapped_lab", unit_id=unit)


def test_unit_id_good_values_injected():
    mixin = IcsIoTMixin()
    plan = mixin.plan_modbus(BENIGN, "air_gapped_lab", unit_id=3)
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert any("-a 3 -t" in c for c in cmds)
    plan = mixin.plan_modbus(BENIGN, "air_gapped_lab", unit_id="17")
    assert plan["unit_id"] == "17"
    plan = mixin.plan_modbus(BENIGN, "air_gapped_lab", unit_id=255)
    assert plan["unit_id"] == "255"
    catalog = mixin.protocol_command_catalog("modbus", BENIGN,
                                             "air_gapped_lab",
                                             unit_id="7")
    assert catalog["unit_id"] == "7"
    assert any("-a 7 -t" in c for s in catalog["steps"]
               for c in s["commands"])


@pytest.mark.parametrize("target", ["plc-lab; calc", "plc|pipe",
                                    "plc$(id)", "..", " lab plc ", ""])
def test_scrub_rejects_hostile_targets(target):
    with pytest.raises(ValueError):
        IcsIoTMixin().plan_modbus(target, "air_gapped_lab")
    with pytest.raises(ValueError):
        IcsIoTMixin().firmware_flow(target, "air_gapped_lab")


def test_host_gate_consult_composite():
    class GateHost(IcsIoTMixin):
        def validate_target(self, target):
            return False, "not on the lab allowlist"

    with pytest.raises(ValueError) as err:
        GateHost().plan_modbus(BENIGN, "air_gapped_lab")
    assert "target rejected by host agent gate" in str(err.value)

    class OkHost(GateHost):
        def validate_target(self, target):
            return True, "ok"

    plan = OkHost().plan_modbus(BENIGN, "air_gapped_lab")
    assert plan["target"] == BENIGN
    # silent fallback when the host agent provides no gate at all
    bare = IcsIoTMixin().plan_modbus(BENIGN, "air_gapped_lab")
    assert bare["target"] == BENIGN


def test_detection_notes_shape():
    notes = IcsIoTMixin().ics_iot_detection_notes()
    assert [n["ttp"] for n in notes["notes"]] == [
        "modbus-write-class", "unit-id-sweep", "s7-download-attempt",
        "cpu-mode-change", "new-node-on-ot-vlan"]
    assert all(n["note"] for n in notes["notes"])


def test_module_never_executes():
    import agentic_ai.agents.cyber.ics_iot as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned