"""KA-013 - cross-generation op parity: kali (v1), kali_v2, and
kali_agent_v4 (a standalone click-CLI script; READ-ONLY comparisons only).

Pinned:
- the overlap-presence matrix (semantic ops across the three generations);
- v1-vs-v2 list_tools field parity (the shared 4 fields + v2's tags delta);
- the v4 read-only CLI live-probes (version/list/status) through its
  committed venv - all three verified print-only against the source;
- the documented divergences (v2 is planner-only: no scan/attack/payload
  path; v4 carries no authorization/dry-run surface; v4's scan prints a
  SIMULATED result - the static finding pinned here and reported)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent, MetasploitRPC
from agentic_ai.agents.cyber.kali_v2 import KaliAgentV2

REPO = Path(__file__).resolve().parents[1]
V4_CLI = REPO / "kali_agent_v4" / "kaliagent"
V4_PY = REPO / "kali_agent_v4" / "venv" / "bin" / "python"
V4_SOURCE = V4_CLI.read_text(encoding="utf-8")

# verified print-only against the source: the v4 module has NO exec
# facilities anywhere (see test_v4_source_has_no_execution_facilities)
V4_SAFE_COMMANDS = ("version", "list", "status")


@pytest.fixture(scope="module")
def generations(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka013")
    return (
        KaliAgent(agent_id="ka013-v1", workspace=str(ws / "v1"),
                  log_dir=str(ws / "v1-logs")),
        KaliAgentV2(workspace=str(ws / "v2")),
    )


@pytest.mark.parametrize("op,present", [
    ("list-tools", True),           # v1 list_tools / v2 list_tools / v4 def list(
    ("authorization", True),        # v1+v2 set_authorization / v4 absent
    ("dry-run", True),              # v1+v2 toggles / v4 absent
    ("payload-generation", True),   # v1 RPC / v4 generate / v2 PLANNER-ONLY
    ("scan-execution", True),       # v1 nmap_scan / v4 scan / v2 ABSENT
])
def test_overlap_presence_matrix(generations, op, present):
    """Each semantic op's presence pinned per generation - the matrix is
    the drift alarm for the three-generation surface."""
    v1, v2 = generations
    def v4_has(defname):
        return ("def {}(".format(defname)) in V4_SOURCE
    if op == "list-tools":
        assert callable(v1.list_tools) and callable(v2.list_tools)
        assert v4_has("list")
    elif op == "authorization":
        assert hasattr(v1, "set_authorization") and hasattr(v2, "set_authorization")
        assert not v4_has("set_authorization")
        assert callable(v1.check_authorization) and callable(v2.check_authorization)
    elif op == "dry-run":
        assert hasattr(v1, "enable_dry_run") and hasattr(v2, "enable_dry_run")
        assert not v4_has("enable_dry_run")
    elif op == "payload-generation":
        assert hasattr(MetasploitRPC, "generate_payload")  # v1: on the RPC
        assert v4_has("generate")
        assert not hasattr(v2, "generate_payload")  # v2: planner-only
    elif op == "scan-execution":
        assert hasattr(v1, "nmap_scan") and hasattr(v1, "execute_tool")
        assert v4_has("scan")
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


def test_v4_readonly_cli_live(tmp_path):
    """The v4 CLI through its committed venv: every SAFE command exits 0
    with its documented marker. Skips when the venv is absent (a
    documented environment runner, not a unit constraint)."""
    if not (V4_PY.is_file() and V4_CLI.is_file()):
        pytest.skip("kali_agent_v4 venv not present on this checkout")
    # PINNED QUIRK: v4's "list" lives under the c2 group (@c2.command()),
    # so the invocation is "c2 list" - a top-level "list" does not exist.
    for label, args_list, marker in (
        ("version", ("version",), "KaliAgent v4"),
        ("c2 list", ("c2", "list"), "Active C2 Agents"),
        ("status", ("status",), "KaliAgent v4 Status"),
    ):
        proc = subprocess.run(
            [str(V4_PY), str(V4_CLI), *args_list],
            capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (label, proc.stderr[-200:])
        assert marker in proc.stdout, label


def test_v4_source_has_no_execution_facilities():
    """The static safety fact the live probes rely on: the v4 script has
    no subprocess/os.system/eval/socket anywhere - every command is
    print-only simulation (status/list = hardcoded demo data, scan =
    simulated progress, reported)."""
    for banned in ("subprocess", "os.system", "eval(", "socket"):
        assert banned not in V4_SOURCE, banned


def test_documented_divergences():
    """The delta table the todo asks for: v2 = planner-only; v4 = no
    auth/dry-run surface and simulated output."""
    v4_commands = ("scan", "attack", "report", "ai", "dashboard", "doctor",
                   "update", "generate")
    for cmd in v4_commands:
        assert "def {}(".format(cmd) in V4_SOURCE
    # v2 negatives (the planner-only chassis):
    for absent in ("execute_tool", "nmap_scan", "enable_safe_mode",
                   "connect_metasploit"):
        assert not hasattr(KaliAgentV2, absent), absent
    # v4 negatives: no authorization/dry-run surface at all
    for absent in ("set_authorization", "enable_dry_run",
                   "validate_target", "safe_mode"):
        assert absent not in V4_SOURCE, absent
