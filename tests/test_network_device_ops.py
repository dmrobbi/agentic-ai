"""KA-040 tests - NetworkDeviceMixin: the router/switch/fw kind enum
(aliases + unknown refusal), the per-kind show-class enum catalogs, the
vendor config-audit rule rows (pinned counts + schema + regex validity),
audit_config over SYNTHETIC configs (weak config hits, hardened config
clean, scrub refusals), the label guard (scrub + host-agent gate with a
silent fallback), and the never-executes source scan. No execution."""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.network_device import (DEVICE_POLICY,
                                                    NetworkDeviceMixin)

EXPECTED_KINDS = ["firewall", "router", "switch"]
EXPECTED_VENDORS = ["cisco-ios", "fortinet-fortigate", "juniper-junos",
                    "paloalto-panos"]
EXPECTED_RULE_COUNTS = {"cisco-ios": 6, "juniper-junos": 5,
                        "paloalto-panos": 4, "fortinet-fortigate": 4}
EXPECTED_RULE_TOTAL = sum(EXPECTED_RULE_COUNTS.values())
EXPECTED_PHASE_IDS = ["1-authorize", "2-enum", "3-capture", "4-audit",
                      "5-remediate", "6-report"]
RULE_SCHEMA = frozenset({"id", "check", "family", "severity", "mode",
                         "match", "finding", "remediation", "detection"})
SEVERITIES = frozenset({"low", "medium", "high"})
MODES = frozenset({"flag", "require"})

WEAK_CISCO = """\
! lab snapshot: dev-lab-r1 (weak baseline)
enable password 7 08224F
ip http server
line vty 0 4
 transport input telnet
snmp-server community public RO
snmp-server community private RW
"""

HARDENED_CISCO = """\
! lab snapshot: dev-lab-r1 (hardened)
enable secret 9 $9$harden
username labadmin secret 9 $9$harden
no ip http server
ip http secure-server
line vty 0 4
 transport input ssh
 exec-timeout 15 0
logging host 10.10.10.9
snmp-server group ka-v3 v3
"""

WEAK_JUNOS = """\
# lab snapshot: dev-lab-sw1 (weak baseline)
set system services telnet
set system services web-management http
set snmp community public
"""


@pytest.mark.parametrize("kind,input_value", [
    ("router", "router"), ("router", "rtr"),
    ("switch", "switch"), ("switch", "sw"),
    ("firewall", "firewall"), ("firewall", "fw"),
    ("firewall", "ngfw"),
])
def test_plan_device_audit_kinds_and_aliases(kind, input_value):
    plan = NetworkDeviceMixin().plan_device_audit("dev-lab-r1",
                                                  input_value)
    assert plan["device"] == "dev-lab-r1"
    assert plan["kind"] == kind
    assert plan["policy"] == DEVICE_POLICY
    assert all(DEVICE_POLICY.values())
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == EXPECTED_PHASE_IDS
    for phase in plan["phases"]:
        assert phase["policy"] == DEVICE_POLICY
        for cmd in phase["sample_commands"]:
            assert "{device_label}" not in cmd
            assert "{kind}" not in cmd


def test_plan_unknown_kind_refused():
    with pytest.raises(ValueError) as err:
        NetworkDeviceMixin().plan_device_audit("dev-lab-r1", "printer")
    assert "known: router, switch, firewall" in str(err.value)


def test_enum_catalog_steps_per_kind():
    mixin = NetworkDeviceMixin()
    router = mixin.device_enum_catalog("router")
    assert router["steps"][0]["commands"] == ["show version"]
    assert any("show ip interface brief" in s["commands"]
               for s in router["steps"])
    switch = mixin.device_enum_catalog("switch")
    flat_switch = [c for s in switch["steps"] for c in s["commands"]]
    assert "show vlan brief" in flat_switch
    assert "show spanning-tree summary" in flat_switch
    fw = mixin.device_enum_catalog("NGFW")
    assert fw["kind"] == "firewall"
    flat_fw = [c for s in fw["steps"] for c in s["commands"]]
    assert "show running-config access-group" in flat_fw
    kinds = mixin.device_enum_catalog()
    assert kinds["kinds"] == EXPECTED_KINDS
    assert kinds["policy"] == DEVICE_POLICY


def test_enum_commands_are_show_class_only():
    mixin = NetworkDeviceMixin()
    for kind in EXPECTED_KINDS:
        catalog = mixin.device_enum_catalog(kind)
        for step in catalog["steps"]:
            for cmd in step["commands"]:
                assert cmd.startswith("show "), (kind, cmd)


def test_enum_unknown_kind_refused():
    with pytest.raises(ValueError) as err:
        NetworkDeviceMixin().device_enum_catalog("load-balancer")
    assert "known: router, switch, firewall" in str(err.value)


@pytest.mark.parametrize("vendor", sorted(EXPECTED_RULE_COUNTS))
def test_config_audit_rules_pinned_counts(vendor):
    rules = NetworkDeviceMixin().config_audit_rules(vendor)
    assert rules["vendor"] == vendor
    assert rules["policy"] == DEVICE_POLICY
    assert len(rules["rules"]) == EXPECTED_RULE_COUNTS[vendor]
    assert all(r["id"].startswith(vendor + "-") for r in rules["rules"])


def test_config_audit_rules_vendor_list():
    listed = NetworkDeviceMixin().config_audit_rules()
    assert listed["vendors"] == EXPECTED_VENDORS
    assert listed["policy"] == DEVICE_POLICY


def test_rule_rows_schema():
    mixin = NetworkDeviceMixin()
    ids = set()
    total = 0
    for vendor in EXPECTED_VENDORS:
        rules = mixin.config_audit_rules(vendor)["rules"]
        assert rules
        for row in rules:
            assert frozenset(row) == RULE_SCHEMA
            assert row["id"] not in ids, row["id"]
            ids.add(row["id"])
            assert row["severity"] in SEVERITIES
            assert row["mode"] in MODES
            assert row["match"] == row["match"].strip().lower()
            re.compile(row["match"])
        total += len(rules)
    assert total == EXPECTED_RULE_TOTAL


def test_audit_config_weak_configs_hit():
    mixin = NetworkDeviceMixin()
    result = mixin.audit_config(WEAK_CISCO, "ios")
    assert result["vendor"] == "cisco-ios"
    assert result["policy"] == DEVICE_POLICY
    assert result["summary"]["rules"] == EXPECTED_RULE_COUNTS["cisco-ios"]
    assert result["summary"]["findings"] == 6
    assert result["summary"]["by_severity"] == {"high": 5, "medium": 1}
    assert result["summary"]["clean"] is False
    flag_hits = [f for f in result["findings"] if f["matches"]]
    require_hits = [f for f in result["findings"] if not f["matches"]]
    assert len(flag_hits) >= 4
    assert len(require_hits) == 2
    assert require_hits[0]["rule_id"] == "cisco-ios-auth-01"
    for f in flag_hits:
        assert f["match_count"] >= 1
        assert f["matches"][0]["line"] >= 1
        assert len(f["matches"][0]["text"]) <= 80

    junos = mixin.audit_config(WEAK_JUNOS, "junos")
    assert junos["vendor"] == "juniper-junos"
    assert junos["summary"]["findings"] == EXPECTED_RULE_COUNTS["juniper-junos"]
    assert junos["summary"]["by_severity"] == {"high": 3, "medium": 2}
    assert junos["summary"]["clean"] is False
    assert {"juniper-junos-auth-01", "juniper-junos-audit-01"} == {
        f["rule_id"] for f in junos["findings"] if not f["matches"]}


def test_audit_config_hardened_config_clean():
    result = NetworkDeviceMixin().audit_config(HARDENED_CISCO, "cisco")
    assert result["summary"]["findings"] == 0
    assert result["summary"]["clean"] is True
    assert result["summary"]["by_severity"] == {}


def test_audit_config_scrub_rejects():
    mixin = NetworkDeviceMixin()
    with pytest.raises(ValueError):
        mixin.audit_config("", "cisco-ios")
    with pytest.raises(ValueError):
        mixin.audit_config("   ", "cisco-ios")
    with pytest.raises(ValueError):
        mixin.audit_config(123, "cisco-ios")
    with pytest.raises(ValueError):
        mixin.audit_config(WEAK_CISCO + "\x00", "cisco-ios")
    with pytest.raises(ValueError):
        mixin.audit_config("a" * 20001, "cisco-ios")
    with pytest.raises(ValueError):
        mixin.audit_config("\n".join("l%d" % i for i in range(2001)),
                           "cisco-ios")
    with pytest.raises(ValueError) as err:
        mixin.audit_config(WEAK_CISCO, "vendor-x")
    assert "known: cisco-ios, fortinet-fortigate, juniper-junos, " \
           "paloalto-panos" in str(err.value)


def test_guard_rejects_hostile_label():
    mixin = NetworkDeviceMixin()
    with pytest.raises(ValueError):
        mixin.plan_device_audit("dev; calc", "router")
    with pytest.raises(ValueError):
        mixin.plan_device_audit("", "router")
    with pytest.raises(ValueError):
        mixin.plan_device_audit(None, "router")


def test_guard_consults_host_agent_gate():
    seen = []

    class _GatedHost(NetworkDeviceMixin):
        def validate_target(self, t):
            seen.append(t)
            return False, "%s not in the lab range" % t

    with pytest.raises(ValueError) as err:
        _GatedHost().plan_device_audit("  dev-lab-fw1  ", "router")
    assert "rejected by host agent gate" in str(err.value)
    assert "not in the lab range" in str(err.value)
    # the gate saw the scrubbed label (stripped), not the raw input
    assert seen == ["dev-lab-fw1"]


def test_index_shape():
    index = NetworkDeviceMixin().device_index()
    assert index["kinds"] == EXPECTED_KINDS
    assert index["vendors"] == EXPECTED_VENDORS
    assert index["policy"] == DEVICE_POLICY
    assert all(DEVICE_POLICY.values())


def test_module_never_executes():
    mod = importlib.import_module("agentic_ai.agents.cyber.network_device")
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "open("):
        assert banned not in source, banned