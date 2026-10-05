"""KA-INT-3 wiring verification: the P3 mixin family (17 modules) composes
onto BOTH chassis; the web catalog extensions landed (12 phases / 20 vuln
classes); the planner gates (sandbox-only detonation, air-gapped ICS,
consent) and the composer ride through the chassis; docs carry the synced
op rows. No network; synthetic inputs only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_ai.agents.registry import create_agent, resolve_agent_class

REPO = Path(__file__).resolve().parents[1]

WOP = {
    "privesc": ("privesc_index", "plan_privesc", "privesc_capability_lookup"),
    "ad_pentest": ("ad_index", "plan_ad", "ad_command_catalog", "ad_detection_notes"),
    "cloud_pentest": ("cloud_index", "plan_cloud", "iam_blast_radius_checklist",
                      "cloud_detection_notes"),
    "container_pentest": ("container_index", "plan_container_escape",
                          "k8s_rbac_checklist", "container_tool_catalog"),
    "mobile_pentest": ("mobile_index", "plan_mobile_apk", "plan_mobile_ipa",
                       "mobile_detection_notes"),
    "wireless_pentest": ("wireless_index", "plan_wireless_capture",
                         "rogue_ap_playbook", "wireless_detection_notes"),
    "osint_pentest": ("osint_index", "osint_step_catalog", "plan_osint",
                      "osint_detection_notes"),
    "forensics_ops": ("forensics_index", "forensics_policy", "forensics_step_catalog",
                      "plan_forensics"),
    "malware_ops": ("malware_index", "malware_policy", "static_step_catalog",
                    "plan_static", "plan_detonation"),
    "network_device": ("audit_config", "config_audit_rules", "device_enum_catalog",
                       "device_index", "plan_device_audit"),
    "api_pentest": ("api_auth_surface_catalog", "api_index", "api_policy",
                    "api_step_catalog", "api_vuln_classes", "api_vuln_commands",
                    "plan_api"),
    "socialeng_ops": ("channel_measurement", "plan_impersonation_exercise",
                      "plan_phishing_simulation", "soc_watch_pairing",
                      "socialeng_index", "socialeng_policy"),
    "ics_iot": ("firmware_flow", "firmware_step_catalog", "ics_iot_detection_notes",
                "ics_iot_index", "plan_modbus", "plan_s7", "protocol_command_catalog"),
    "postexp": ("classify_postexp_command", "plan_postexp", "postexp_arcs",
                "postexp_credential_classes", "postexp_gate", "postexp_policy",
                "postexp_step_catalog"),
    "webauth_ops": ("jwt_analysis", "oauth_flow_catalog", "oauth_grant_assessment",
                    "plan_webauth", "webauth_index", "webauth_policy",
                    "webauth_redirect_checks", "webauth_sso_surface",
                    "webauth_token_storage"),
    "chain_ops": ("analyzer_catalog", "analyzer_lookup", "contract_nets",
                  "contract_policy", "finding_class_catalog", "plan_analyzer_sweep",
                  "plan_contract_audit", "plan_finding_triage", "testnet_gate"),
    "full_engagement": ("full_engagement_index", "plan_full_engagement"),
}
ALL_OPS = tuple(op for ops in WOP.values() for op in ops)
assert len(ALL_OPS) == 88


@pytest.mark.parametrize("agent_id", ["kali", "kali_v2"])
def test_chassis_expose_every_wired_op(agent_id):
    cls = resolve_agent_class(agent_id)
    for op in ALL_OPS:
        assert callable(getattr(cls, op, None)), (agent_id, op)


def test_instances_drive_the_wired_index_surface():
    a = create_agent("kali")
    v2 = create_agent("kali_v2")
    for op in ("malware_index", "device_index", "api_index", "socialeng_index",
               "ics_iot_index", "webauth_token_storage", "contract_nets",
               "full_engagement_index"):
        assert a.__getattribute__(op)() , op  # indexes return data
    assert v2.ics_iot_index() and v2.contract_nets()


def test_web_catalog_extensions_landed_through_chassis():
    a = create_agent("kali")
    plan = a.plan_web_pentest("example.com")
    assert len(plan["phases"]) == 12                       # KA-047 spec landed
    assert plan["phases"][-1]["phase"] == "12-stig-baseline-mapping"
    shape = a.web_vuln_commands("example.com")             # None -> {"target", "classes"}
    classes = shape["classes"]
    assert len(classes) == 20                              # KA-048: 10 + 10
    assert "graphql" in classes
    row = a.web_vuln_commands("example.com", "graphql")    # new class serves
    blob = json.dumps(row)
    assert "example.com" in blob and "graphql" in blob.lower()


def test_gates_ride_through_the_chassis():
    a = create_agent("kali")
    with pytest.raises(ValueError, match="detonation refused"):
        a.plan_detonation("sample.bin", kind="binary")     # no sandbox record
    with pytest.raises(ValueError, match="air-gapped"):
        a.plan_modbus("plc-lab", "production")             # non-lab staging
    with pytest.raises(ValueError):
        a.plan_phishing_simulation(None, "finance")        # no consent record


def test_composer_runs_through_the_chassis():
    a = create_agent("kali")
    plan = a.plan_full_engagement("example.com")
    assert plan["target"] == "example.com"
    blob = json.dumps(plan).lower()
    for stage in ("recon", "web", "xss", "privesc"):
        assert stage in blob, stage                        # the pinned core arc
    with pytest.raises(ValueError):
        a.plan_full_engagement("example.com", platform="not-a-thing")


def test_docs_carry_the_synced_rows():
    role_ops = (REPO / "skills" / "agentic-roles" / "references"
                / "role-ops.md").read_text()
    for op in ALL_OPS:
        assert role_ops.count(f"| `{op}` |") >= 2, op      # kali + kali_v2
    matrix = (REPO / "docs" / "AGENT_MATRIX.md").read_text()
    for op in ("plan_static", "plan_full_engagement", "plan_webauth",
               "plan_contract_audit"):
        assert matrix.count(f"| `{op}` |") >= 2, op        # both chassis sections
