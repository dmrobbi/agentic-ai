"""IcsIoTMixin (KA-043): ICS/IoT methodology planning - Modbus/S7
enumeration planners + an IoT firmware-analysis flow with a binwalk
tie-in (no execution).

AIR-GAP POLICY: every target-bearing op requires the staging label to
name the AIR-GAPPED lab; non-lab staging is REFUSED with a ValueError
that names the accepted labels (the hard policy behind this [lab]-
tagged mixin). The refusal is planner-level: the arc phases still note
that any later execution stays behind the chassis gates + the owner's
written consent.

Protocols: modbus (aliases incl. the tcp/rtu forms), s7 (aliases
s7comm/siemens). Unknown raises ValueError naming the known protocols.

Firmware: the flow is static-only (work on copies; nothing detonated);
it ties into the static-first discipline of the malware module
(agentic_ai.agents.cyber.malware - pointer-level mention only; no
import here).

Ops:
- ics_iot_index() - protocols, the staging vocabulary, the policies
- plan_modbus(target_label, staging, unit_id=None, tap=None)
  - the 6-phase Modbus TCP+RTU read-only arc
- plan_s7(target_label, staging, tap=None) - the 6-phase S7comm
  read-only arc
- firmware_flow(image_label, staging) - the 6-phase static firmware
  analysis arc (the binwalk tie-in)
- firmware_step_catalog() - the raw firmware templates (placeholders
  kept)
- protocol_command_catalog(protocol, target, staging, unit_id=1) -
  per-protocol read-only command rows (target/unit injected)
- ics_iot_detection_notes() - the SOC pairings
"""

from __future__ import annotations

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

STAGING_POLICY = {"air_gapped_lab_required": True}
FIRMWARE_POLICY = {"air_gapped_lab_required": True, "work_on_copies": True,
                   "static_only": True}

STAGING = {"air_gapped_lab": ("air_gapped_lab", "air-gapped-lab",
                              "air_gapped", "air-gapped", "airgapped",
                              "air_gap", "airgap", "ics_lab", "ics-lab",
                              "ot_lab", "ot-lab")}

PROTOCOLS = {"modbus": ("modbus", "modbus_tcp", "modbus-tcp", "mbtcp",
                        "modbus_rtu", "modbus-rtu"),
             "s7": ("s7", "s7comm", "s7comm_plus", "s7comm-plus",
                    "siemens")}

STAGING_ALIASES = tuple(sorted(STAGING["air_gapped_lab"]))


def _staging_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("staging must be a non-empty air-gapped-lab label")
    form = value.strip().lower().replace("_", "-")
    for canonical, aliases in STAGING.items():
        if form in tuple(a.replace("_", "-") for a in aliases):
            return canonical
    raise ValueError(
        "staging %r refused - the air-gapped lab is required; accepted "
        "staging labels: %s" % (value, ", ".join(STAGING_ALIASES)))


def _protocol_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("protocol must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in PROTOCOLS.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown protocol %r - known: modbus, s7" % (value,))


def _unit_id_guard(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("unit_id must be an int or digit string in 1..255")
    if isinstance(value, str):
        if not value.strip().isdigit():
            raise ValueError("unit_id must be an int or digit string in "
                             "1..255")
        unit = int(value.strip())
    else:
        unit = value
    if not 1 <= unit <= 255:
        raise ValueError("unit_id out of range 1..255: %s" % (value,))
    return str(unit)


MODBUS_PLAN = (
    ("1-scope", "The air-gapped boundary",
     ["Confirm the lab is disconnected from any plant or corporate path.",
      "Inventory the lab PLCs/RTUs and their unit ids."],
     ["# scope: {target}; air-gapped lab only; no plant-side paths"]),

    ("2-passive", "Passive capture before any active probe",
     ["Mirror the lab link (a tap) and record the 502 traffic.",
      "No active traffic before this capture exists."],
     ["tcpdump -i {tap} -w lab-modbus-passive.pcap port 502"]),

    ("3-identify", "Read-only identification of the lab device",
     ["Port + script-based identification; reads only.",
      "Note vendor ids and the device metadata in the log."],
     ["nmap -sT -Pn -n -p 502 --open {target}",
      "nmap -sT -p 502 --script modbus-discover {target}"]),

    ("4-map", "Coil/register mapping with reads only",
     ["Walk coils, discrete inputs, holding and input registers in tiny "
      "counts.",
      "Write-class codes (FC5/FC6/FC15/FC16) stay unplanned."],
     ["mbpoll -m tcp -a {unit} -t 0 -r 1 -c 8 -1 {target}",
      "mbpoll -m tcp -a {unit} -t 3 -r 1 -c 8 -1 {target}",
      "mbpoll -m rtu -b 9600 -P none -a {unit} -1 /dev/ttyUSB0"]),

    ("5-evidence", "Passivity proof alongside the outputs",
     ["The passive pcap + the read log; every command in the log."],
     ["# evidence: the pcap + the read log; scrub before export"]),

    ("6-detection", "The SOC pairings",
     ["Detection notes per step; the retest criteria agreed."],
     ["# op: ics_iot_detection_notes()"]),
)

S7_PLAN = (
    ("1-scope", "The air-gapped boundary",
     ["Confirm the air-gap; inventory the lab CPUs (rack/slot).",
      "Download-class work stays unplanned."],
     ["# scope: {target}; air-gapped lab only; no plant-side paths"]),

    ("2-passive", "Passive capture of the 102 traffic",
     ["Mirror the lab link and record the s7comm traffic.",
      "No traffic generated before this capture exists."],
     ["tcpdump -i {tap} -w lab-s7-passive.pcap port 102"]),

    ("3-identify", "Read-only CPU identification",
     ["The s7comm identification script; module/rack metadata only.",
      "Nothing downloaded, nothing set."],
     ["nmap -sT -Pn -n -p 102 --open {target}",
      "nmap -sT -p 102 --script s7-info {target}"]),

    ("4-map", "Data-block/area map, read-only",
     ["Read-only gets of the CPU metadata and the data-block layout.",
      "Job/download and monitor-mode traffic stay unplanned."],
     ["# snap7 client, read-only gets of the CPU metadata",
      "# s7comm status reads only; job/download classes unplanned"]),

    ("5-evidence", "Passivity proof alongside the outputs",
     ["The passive pcap + the read log; every command in the log."],
     ["# evidence: the pcap + the read log; scrub before export"]),

    ("6-detection", "The SOC pairings",
     ["Detection notes per step; the retest criteria agreed."],
     ["# op: ics_iot_detection_notes()"]),
)

FIRMWARE_PLAN = (
    ("1-acquire", "The image enters off the wire",
     ["Images reach the lab via the offline transfer only.",
      "Record the sha256 before anything else."],
     ["sha256sum {image}",
      "# acquire: the offline transfer only; the original stays sealed"]),

    ("2-verify", "Fingerprint the working copy",
     ["Hash-chain the copy; the file magic decides the unpack route."],
     ["file {image}", "sha256sum {image} > {image}.sha256"]),

    ("3-binwalk", "Signature + entropy scans (the binwalk tie-in)",
     ["The signature scan first, then the entropy view.",
      "Static-first, the same discipline as the malware module's "
      "triage."],
     ["binwalk {image}", "binwalk -E {image}"]),

    ("4-unpack", "Extract the components from a copy",
     ["Work on a copy; the extracted tree stays in the lab workspace.",
      "Nothing extracted is ever run."],
     ["binwalk -e {image}",
      "# unpack: the tree stays in the lab; no execution"]),

    ("5-triage", "Component triage, static-only",
     ["Configs, init scripts, version strings, embedded key material.",
      "YARA over the extracted tree, static matches only."],
     ["strings -n 8 {image} | head -50",
      "# yara over the extracted tree - matches recorded, nothing run"]),

    ("6-report", "Findings + the scrub",
     ["Per finding: the stage, the file/offset, the evidence.",
      "Embedded secrets scrubbed BEFORE anything leaves the air-gap."],
     ["# report: scrub embedded secrets before export"]),
)

PROTOCOL_STEPS = {
    "modbus": (
        ("discovery", ("nmap -sT -Pn -n -p 502 --open {target}",)),
        ("device-info", ("nmap -sT -p 502 --script modbus-discover "
                         "{target}",)),
        ("reads", ("mbpoll -m tcp -a {unit} -t 0 -r 1 -c 8 -1 {target}",
                   "mbpoll -m tcp -a {unit} -t 3 -r 1 -c 8 -1 {target}",
                   "mbpoll -m rtu -b 9600 -P none -a {unit} -1 "
                   "/dev/ttyUSB0")),
    ),
    "s7": (
        ("discovery", ("nmap -sT -Pn -n -p 102 --open {target}",)),
        ("cpu-info", ("nmap -sT -p 102 --script s7-info {target}",)),
        ("reads", ("# snap7 client, read-only gets of the CPU metadata",)),
    ),
}

FIRMWARE_STEPS = (
    ("acquire-verify", ("sha256sum {image}", "file {image}")),
    ("signatures", ("binwalk {image}", "binwalk -E {image}")),
    ("unpack", ("binwalk -e {image}",)),
    ("triage", ("strings -n 8 {image} | head -50",)),
)

OT_DETECTION_NOTE_ROWS = (
    ("modbus-write-class",
     "a write-class function code (FC5/FC6/FC15/FC16) on the passive "
     "span outside a maintenance window = page"),
    ("unit-id-sweep",
     "one source sweeping unit ids or register ranges in bursts = "
     "alert"),
    ("s7-download-attempt",
     "s7comm job/download-class traffic to a CPU outside the change "
     "window = page"),
    ("cpu-mode-change",
     "PLC stop/start or mode-change traffic against an inventoried CPU "
     "= page"),
    ("new-node-on-ot-vlan",
     "an un-inventoried endpoint speaking modbus or s7comm on the lab "
     "VLAN = alert"),
)


class IcsIoTMixin:
    """ICS/IoT planning ops (no execution; the air-gapped lab required)."""

    def ics_iot_index(self) -> dict:
        """The module's own shapes (a stable API for the composer)."""
        return {"protocols": sorted(PROTOCOLS),
                "staging": {"canonical": "air_gapped_lab",
                            "accepted": list(STAGING_ALIASES)},
                "policy": dict(STAGING_POLICY),
                "firmware_policy": dict(FIRMWARE_POLICY)}

    def _ics_iot_guard(self, target):
        """Scrub + consult the host agent's target gate when it has one."""
        t = wp_scrub_target(target)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(t)
            if not ok:
                raise ValueError("target rejected by host agent gate: %s"
                                 % msg)
        return t

    def _tap_guard(self, tap):
        return wp_scrub_target(tap) if tap else "tap0"

    def plan_modbus(self, target_label, staging, unit_id=None, tap=None):
        """The 6-phase read-only Modbus plan; refuses non-lab staging."""
        canonical = _staging_for(staging)
        t = self._ics_iot_guard(target_label)
        tap_label = self._tap_guard(tap)
        unit = _unit_id_guard(1 if unit_id is None else unit_id)
        phases = [{"phase": pid, "goal": goal, "activities": list(acts),
                   "sample_commands": [
                       c.replace("{target}", t)
                        .replace("{tap}", tap_label)
                        .replace("{unit}", unit)
                       for c in cmds],
                   "policy": dict(STAGING_POLICY)}
                  for pid, goal, acts, cmds in MODBUS_PLAN]
        return {"target": t, "protocol": "modbus", "staging": canonical,
                "unit_id": unit, "tap": tap_label,
                "policy": dict(STAGING_POLICY), "phases": phases}

    def plan_s7(self, target_label, staging, tap=None):
        """The 6-phase read-only S7comm plan; refuses non-lab staging."""
        canonical = _staging_for(staging)
        t = self._ics_iot_guard(target_label)
        tap_label = self._tap_guard(tap)
        phases = [{"phase": pid, "goal": goal, "activities": list(acts),
                   "sample_commands": [
                       c.replace("{target}", t)
                        .replace("{tap}", tap_label)
                       for c in cmds],
                   "policy": dict(STAGING_POLICY)}
                  for pid, goal, acts, cmds in S7_PLAN]
        return {"target": t, "protocol": "s7", "staging": canonical,
                "tap": tap_label, "policy": dict(STAGING_POLICY),
                "phases": phases}

    def firmware_flow(self, image_label, staging):
        """The 6-phase static firmware flow; refuses non-lab staging."""
        canonical = _staging_for(staging)
        t = self._ics_iot_guard(image_label)
        phases = [{"phase": pid, "goal": goal, "activities": list(acts),
                   "sample_commands": [c.replace("{image}", t)
                                       for c in cmds],
                   "policy": dict(FIRMWARE_POLICY)}
                  for pid, goal, acts, cmds in FIRMWARE_PLAN]
        return {"image": t, "staging": canonical,
                "policy": dict(FIRMWARE_POLICY), "phases": phases}

    def firmware_step_catalog(self) -> dict:
        """The raw firmware templates (placeholders kept for reuse)."""
        return {"policy": dict(FIRMWARE_POLICY),
                "steps": [{"step": s, "commands": list(cmds)}
                          for s, cmds in FIRMWARE_STEPS]}

    def protocol_command_catalog(self, protocol, target, staging,
                                 unit_id=1):
        """The per-protocol read-only command rows (values injected)."""
        canonical = _protocol_for(protocol)
        canonical_staging = _staging_for(staging)
        t = self._ics_iot_guard(target)
        unit = _unit_id_guard(unit_id)
        return {"protocol": canonical, "target": t, "unit_id": unit,
                "staging": canonical_staging,
                "policy": dict(STAGING_POLICY),
                "steps": [{"step": s, "commands": [
                    c.replace("{target}", t).replace("{unit}", unit)
                    for c in cmds]}
                    for s, cmds in PROTOCOL_STEPS[canonical]]}

    def ics_iot_detection_notes(self) -> dict:
        """The blue-team pairing (TTP-level notes)."""
        return {"notes": [{"ttp": tid, "note": note}
                          for tid, note in OT_DETECTION_NOTE_ROWS]}
