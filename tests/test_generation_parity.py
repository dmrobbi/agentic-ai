"""KA-013 - cross-generation op parity: kali (v1) and kali_v2.

Pinned:
- the overlap-presence matrix (semantic ops across the two chassis
  generations);
- v1-vs-v2 list_tools field parity (the shared 4 fields + v2's tags delta);
- the documented divergences (v2 is planner-only: no scan/attack/payload
  path).

History: the third generation (the standalone kali_agent_v4 CLI) was a
print-only simulation facade - its live-probe and static findings were
pinned here in the KA-013 era and reported; the facade was removed from
HEAD on 2026-10-08 (dead-generation cleanup, owner order). That record
lives at git history c965747: no subprocess/os.system/eval/socket in its
CLI, no authorization/dry-run surface, and its scan printed a simulated
result."""
from __future__ import annotations

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent, MetasploitRPC
from agentic_ai.agents.cyber.kali_v2 import KaliAgentV2


@pytest.fixture(scope="module")
def generations(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka013")
    return (
        KaliAgent(agent_id="ka013-v1", workspace=str(ws / "v1"),
                  log_dir=str(ws / "v1-logs")),
        KaliAgentV2(workspace=str(ws / "v2")),
    )


@pytest.mark.parametrize("op", ["list-tools", "authorization", "dry-run",
                                "payload-generation", "scan-execution"])
def test_overlap_presence_matrix(generations, op):
    """Each semantic op's presence pinned per chassis generation - the
    matrix is the drift alarm for the two-generation surface."""
    v1, v2 = generations
    if op == "list-tools":
        assert callable(v1.list_tools) and callable(v2.list_tools)
    elif op == "authorization":
        assert hasattr(v1, "set_authorization") and hasattr(
            v2, "set_authorization")
        assert callable(v1.check_authorization) and callable(
            v2.check_authorization)
    elif op == "dry-run":
        assert hasattr(v1, "enable_dry_run") and hasattr(v2, "enable_dry_run")
    elif op == "payload-generation":
        assert hasattr(MetasploitRPC, "generate_payload")  # v1: on the RPC
        assert not hasattr(v2, "generate_payload")  # v2: planner-only
    elif op == "scan-execution":
        assert hasattr(v1, "nmap_scan") and hasattr(v1, "execute_tool")
        assert not hasattr(v2, "nmap_scan") and not hasattr(v2, "execute_tool")


def test_v1_v2_list_tools_field_parity(generations):
    """The shared inventory fields are identical; v2 adds tags (the
    documented delta; a silent field drift fails here)."""
    v1_rows = generations[0].list_tools()
    v2_rows = generations[1].list_tools()
    assert v1_rows and v2_rows
    v1_keys = set(v1_rows[0])
    v2_keys = set(v2_rows[0])
    assert v1_keys == {"name", "category", "description", "authorization"}
    assert v2_keys == v1_keys | {"tags"}
    for row in v1_rows + v2_rows:
        assert row["name"] and row["category"] and row["description"] is not None


def test_documented_divergences():
    """The delta table the todo asked for: v2 = planner-only - the
    negatives pinned. (The removed third generation's negatives - no
    authorization/dry-run surface, simulated output - live at git
    history c965747.)"""
    for absent in ("execute_tool", "nmap_scan", "enable_safe_mode",
                   "connect_metasploit"):
        assert not hasattr(KaliAgentV2, absent), absent