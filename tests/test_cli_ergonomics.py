"""KA-092 CLI ergonomics: `agenticai kali ...` planner wrappers stay read-only.

Pins (per docs/KA-BUILDING-CONVENTIONS.md):
- the additive `kali` typer group keeps the pre-change root/group command set
  intact (regression constants read from the pre-change structure via typer
  introspection before this change landed);
- new subcommand help + chained handler output shapes;
- planner purity: the additive handlers inspect read-only surfaces and never
  touch an execution path.
No existing test file is edited; no op call, no network, no subprocess.
"""
import importlib
import inspect

import pytest
from typer.testing import CliRunner


# ---------------------------------------------------------------------------
# Pre-change regression constants (derived from agentic_ai.cli BEFORE the
# KA-092 edit: cli.app introspection of registered_commands/registered_groups).
# ---------------------------------------------------------------------------
PREEXISTING_ROOT_COMMANDS = frozenset({"status", "version", "doctor", "logs"})
PREEXISTING_GROUPS = {
    "agent": frozenset({"card", "info", "list", "ops", "run"}),
    "audit": frozenset({"create", "list", "status"}),
    "chaos": frozenset({"experiment", "list", "status", "target"}),
    "cloud": frozenset({"account", "compliance", "finding"}),
    "config": frozenset({"get", "list", "set"}),
    "ml": frozenset({"drift", "experiment", "model"}),
    "vendor": frozenset({"add", "assess", "list", "report"}),
}
KALI_VISIBLE_SUBITEMS = frozenset({"tools", "search"})

# The additive handlers may only plan/inspect - never execute.
BANNED_EXEC_TOKENS = (
    "subprocess",
    "os.system",
    "Popen",
    "eval(",
    "exec(",
    "execute_tool",
    "call_tool",
    "safety_gate_chain",
    "asyncio.run",
    "perform_task",
    "open(",
    "requests",
    "urllib",
)

KALI_PLANNER_FUNCS = (
    "kali_entry",
    "get_kali_agent",
    "_kali_auth_label",
    "_kali_filtered_tools",
    "_kali_op_purposes",
    "kali_tools",
    "kali_search",
    "_kali_tool_glance",
)


@pytest.fixture(scope="module")
def cli():
    return importlib.import_module("agentic_ai.cli")


def _invoke(cli, argv):
    # COLUMNS=200 keeps rich from folding table cells -> stable substring asserts
    return CliRunner().invoke(cli.app, argv, env={"COLUMNS": "200"})


def _group_by_name(cli, name):
    return next(g for g in cli.app.registered_groups if g.name == name)


def _named(sub):
    return {c.name or (c.callback.__name__ if c.callback else "?") for c in sub.registered_commands}


# ---------------------------------------------------------------------------
# Regression pin
# ---------------------------------------------------------------------------
def test_regression_root_and_group_names_unchanged(cli):
    root = set(_named(cli.app))
    assert PREEXISTING_ROOT_COMMANDS <= root
    groups = {g.name for g in cli.app.registered_groups}
    # the top-level ADDITION is exactly the kali group
    assert groups == set(PREEXISTING_GROUPS) | {"kali"}
    for group in cli.app.registered_groups:
        if group.name == "kali":
            continue
        cmds = _named(group.typer_instance)
        assert PREEXISTING_GROUPS[group.name] <= cmds, group.name


def test_kali_subitems_visible_and_tool_keys_hidden(cli):
    res = _invoke(cli, ["kali", "--help"])
    assert res.exit_code == 0
    assert "tools" in res.output
    assert "search" in res.output
    # per-tool glance commands are registered hidden: no clutter in help
    assert "metasploit" not in res.output
    assert "recon-ng" not in res.output
    visible = {
        c.name
        for c in _group_by_name(cli, "kali").typer_instance.registered_commands
        if not getattr(c, "hidden", False)
    }
    assert visible == KALI_VISIBLE_SUBITEMS
    named = _named(_group_by_name(cli, "kali").typer_instance)
    expected_keys = set(cli.KALI_TOOLS_DB)
    dash_aliases = {k.replace("_", "-") for k in expected_keys if k != k.replace("_", "-")}
    assert expected_keys <= named
    assert dash_aliases <= named


# ---------------------------------------------------------------------------
# New subcommand shapes
# ---------------------------------------------------------------------------
def test_kali_bare_invocation_prints_usage(cli):
    res = _invoke(cli, ["kali"])
    assert res.exit_code == 0
    assert "agenticai kali tools [filter]" in res.output
    assert "agenticai kali <tool>" in res.output
    assert "agenticai kali search <query>" in res.output


def test_kali_tools_listing_and_filter(cli):
    res = _invoke(cli, ["kali", "tools"])
    assert res.exit_code == 0
    assert "Kali tool DB" in res.output
    expected_total = len(cli.get_kali_agent().list_tools())
    assert f"{expected_total} tools" in res.output
    assert "nmap" in res.output
    res_f = _invoke(cli, ["kali", "tools", "recon"])
    assert res_f.exit_code == 0
    assert "nmap" in res_f.output
    assert "aircrack" not in res_f.output
    res_e = _invoke(cli, ["kali", "tools", "zzz_nomatch_ka092"])
    assert res_e.exit_code == 0
    assert "0 tools" in res_e.output


def test_kali_tool_glance_shape(cli):
    res = _invoke(cli, ["kali", "nmap"])
    assert res.exit_code == 0
    assert "kali tool card" in res.output
    assert "Field" in res.output and "Value" in res.output
    assert "command" in res.output
    assert "required args" in res.output and "optional args" in res.output
    assert "Related kali ops" in res.output
    assert "nmap_scan" in res.output
    assert "Async" in res.output
    assert "Planner info only" in res.output


def test_kali_tool_glance_dash_alias(cli):
    res = _invoke(cli, ["kali", "recon-ng"])
    assert res.exit_code == 0
    assert "kali tool card" in res.output
    assert "recon-ng" in res.output


def test_kali_search_match_and_no_match(cli):
    res = _invoke(cli, ["kali", "search", "nmap"])
    assert res.exit_code == 0
    assert "cap 25" in res.output
    assert "nmap_scan" in res.output
    res_e = _invoke(cli, ["kali", "search", "zzzq_no_match_ka092"])
    assert res_e.exit_code == 0
    assert "No kali matches" in res_e.output


def test_kali_search_cap_overflow(cli):
    original = cli._KALI_RESULT_CAP
    cli._KALI_RESULT_CAP = 3
    try:
        res = _invoke(cli, ["kali", "search", "nmap"])
    finally:
        cli._KALI_RESULT_CAP = original
    assert res.exit_code == 0
    assert "cap 3" in res.output
    assert "more match(es) hidden" in res.output


def test_kali_unknown_tool_errors_actionable(cli):
    res = _invoke(cli, ["kali", "zzz_not_a_tool_ka092"])
    # click refuses unknown names before the handler could ever run
    assert res.exit_code != 0
    assert "No such command" in res.output


def test_kali_tools_direct_handler_capsys(cli, capsys):
    # house mirror: direct handler call captured with capsys (see test_registry)
    cli.kali_tools("subfinder")
    out = capsys.readouterr().out
    assert "subfinder" in out


# ---------------------------------------------------------------------------
# Planner purity
# ---------------------------------------------------------------------------
def test_kali_wrappers_are_planner_only(cli):
    for name in KALI_PLANNER_FUNCS:
        source = inspect.getsource(getattr(cli, name))
        for token in BANNED_EXEC_TOKENS:
            assert token not in source, (name, token)