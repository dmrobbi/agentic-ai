"""KA-019 - KALI_TOOLS_DB completeness: every ToolDefinition row is
complete (identity, description, command, dict-shaped schema with known
types, authorization in range, positive timeouts), the category ->
authorization policy table is pinned as observed (2026-10-05 curation),
the name->command divergence map is pinned as the observed real-binary
overrides, and parser references resolve against the v1 parser inventory.
No network."""
from __future__ import annotations

import tempfile
from collections import defaultdict

from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KALI_TOOLS_DB,
    KaliAgent,
)

# observed at 2026-10-05 curation: the authorization values each category
# carries. A drift is the alarm; the outliers are documented inline.
CATEGORY_AUTH_POLICY = {
    "EXPLOITATION": {1, 3},  # metasploit/nmap_exploit CRITICAL; the
    # searchsploit outlier (BASIC) is by design: it is a database search
    "FORENSICS": {1},
    "MALWARE": {1},  # the only row (binwalk): flagged as soft-vs-intent
    "PASSWORD": {1, 2},  # offline makers BASIC; the crackers ADVANCED
    "POST_EXPLOITATION": {3},
    "RECONNAISSANCE": {1},
    "SNIFFING_SPOOFING": {1, 2},
    "SOCIAL_ENGINEERING": {3},
    "VULNERABILITY_ANALYSIS": {1, 2},
    "WEB_APPLICATION": {1, 2},
    "WIRELESS": {1, 2},
}
KNOWN_SCHEMA_TYPES = {"string", "boolean", "integer", "number", "array",
                      "object"}
NAME_OVERRIDES = {  # observed: rows whose NAME field differs from the key
    "recon_ng": "recon-ng",
    "aircrack_ng": "aircrack-ng",
    "nmap_vuln": "nmap-vuln",
    "nmap_exploit": "nmap-exploit",
    "hash_identifier": "hash-identifier",
}
COMMAND_OVERRIDES = {  # the observed name -> real-binary divergences
    "aircrack_ng": "aircrack-ng",
    "bloodhound": "bloodhound-python",
    "hash_identifier": "hash-identifier",
    "metasploit": "msfconsole",
    "nmap_exploit": "nmap",
    "nmap_vuln": "nmap",
    "openvas": "gvm-cli",
    "recon_ng": "recon-ng",
    "sleuthkit": "fls",
    "spiderfoot": "spiderfoot-cli",
    "testssl": "testssl.sh",
    "wireshark": "tshark",
    "zap_cli": "zap-cli",
}
PARSER_INVENTORY = {"nmap_xml", "json", "csv", "nikto", "sqlmap", "gobuster"}


def test_identity_and_completeness():
    assert len(KALI_TOOLS_DB) == 52
    for name, tool in KALI_TOOLS_DB.items():
        # PINNED QUIRK (5 rows): some names carry hyphenated forms;
        # independent of the COMMAND map (nmap_vuln's command = nmap).
        assert tool.name == NAME_OVERRIDES.get(name, name), name
        assert (tool.description or "").strip(), name
        assert (tool.command or "").strip(), name
        assert isinstance(tool.args_schema, dict), name
        for spec in tool.args_schema.values():
            assert isinstance(spec, dict), name
            assert spec.get("type") in KNOWN_SCHEMA_TYPES, (name, dict(spec))
            assert isinstance(spec.get("required"), bool), name


def test_authorization_values_in_range_and_enum():
    for name, tool in KALI_TOOLS_DB.items():
        assert tool.authorization in (
            AuthorizationLevel.NONE, AuthorizationLevel.BASIC,
            AuthorizationLevel.ADVANCED, AuthorizationLevel.CRITICAL), name


def test_category_auth_policy_table():
    seen = defaultdict(set)
    for name, tool in KALI_TOOLS_DB.items():
        cat = tool.category.name
        assert cat in CATEGORY_AUTH_POLICY, cat
        assert tool.authorization.value in CATEGORY_AUTH_POLICY[cat], (
            name, cat, tool.authorization.value)
        seen[cat].add(tool.authorization.value)
    assert dict(seen) == dict(CATEGORY_AUTH_POLICY)  # bidirectional


def test_name_command_divergence_map():
    for name, tool in KALI_TOOLS_DB.items():
        if name in COMMAND_OVERRIDES:
            assert tool.command == COMMAND_OVERRIDES[name], name
        else:
            assert tool.command == name, name


def test_parser_references_resolve():
    for name, tool in KALI_TOOLS_DB.items():
        assert tool.output_parser in (PARSER_INVENTORY | {None}), name


def test_timeouts_and_safe_default():
    for name, tool in KALI_TOOLS_DB.items():
        assert isinstance(tool.timeout_seconds, int)
        assert tool.timeout_seconds > 0, name
        assert tool.safe_by_default is True, name  # uniform at curation


def test_v1_parser_inventory_is_real():
    # the references resolve against KaliAgent's own parsers dict
    with tempfile.TemporaryDirectory() as td:
        agent = KaliAgent(agent_id="ka019",
                          workspace=str(td), log_dir=str(td) + "/logs")
        assert set(agent.parsers) == PARSER_INVENTORY
