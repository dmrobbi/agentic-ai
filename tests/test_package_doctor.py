"""KA-091 tests - the package doctor: exact result shape on the real
catalog, the injected resolver seams (all-present, all-missing, mixed,
raising, hostile returns), the default shutil.which seam, malformed
catalog rows tolerated with warnings, duplicate binaries, mapping-row
acceptance, deterministic reruns, generated_at injection, echo
scrubbing, laziness (the catalog is never bound at module level), and
the purity source-scan (no spawning, no network, no clock.

No network anywhere: every lookup runs through the injected resolver;
the single real-host check pins only the "sh" binary, which is
present on any POSIX host running this suite."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import kali as kali_mod
from agentic_ai.agents.cyber import package_doctor as doctor_mod
from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    ToolCategory,
    ToolDefinition,
)
from agentic_ai.agents.cyber.package_doctor import (
    ROW_KEYS,
    SUMMARY_KEYS,
    package_doctor_rows,
)

CTRL = "\x01\x7f\n\t"


def _td(command: str, name=None) -> ToolDefinition:
    """A synthetic healthy catalog row in the REAL dataclass shape."""
    return ToolDefinition(
        name=name if name is not None else command.replace("-", "_"),
        category=ToolCategory.RECONNAISSANCE,
        description="synthetic",
        command=command,
        args_schema={"target": {"type": "string", "required": True}},
        authorization=AuthorizationLevel.BASIC,
        timeout_seconds=300,
    )


def _two_tool_db():
    return {
        "alpha_tool": _td("alpha-tool"),
        "beta_tool": _td("beta-cmd", name="beta"),
    }


def _with_db(monkeypatch, db):
    """Swap the catalog behind the doctor's LAZY import, auto-restored."""
    monkeypatch.setattr(kali_mod, "KALI_TOOLS_DB", db)
    return db


# --- the real catalog (read-only): shapes only, no host-state pins -------


def test_real_db_shapes_and_count_math():
    result = package_doctor_rows()  # default which-style local lookup
    assert set(result) == {"rows", "summary", "generated_at", "warnings"}
    assert result["generated_at"] is None
    for row in result["rows"]:
        assert set(row) == set(ROW_KEYS)
        assert isinstance(row["present"], bool)
        assert isinstance(row["tool"], str) and row["tool"].strip()
        assert isinstance(row["binary"], str) and row["binary"].strip()
        if row["present"]:
            assert isinstance(row["path"], str) and row["path"].strip()
        else:
            assert row["path"] is None
    summary = result["summary"]
    assert set(summary) == set(SUMMARY_KEYS)
    assert summary["present"] + summary["missing"] == summary["total"]
    assert summary["total"] == len(result["rows"])
    assert result["rows"]  # the catalog is non-empty


def test_real_db_covers_every_catalog_key():
    from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB

    result = package_doctor_rows(lambda binary: None)
    assert {row["tool"] for row in result["rows"]} == set(KALI_TOOLS_DB)
    assert result["summary"]["total"] == len(KALI_TOOLS_DB)
    assert result["summary"]["missing"] == len(KALI_TOOLS_DB)
    assert result["summary"]["present"] == 0
    assert result["warnings"] == []


def test_default_resolver_is_the_which_seam(monkeypatch):
    _with_db(monkeypatch, {"sh_probe": _td("sh")})
    result = package_doctor_rows()
    row = result["rows"][0]
    assert row["tool"] == "sh_probe" and row["binary"] == "sh"
    assert row["present"] is True
    assert isinstance(row["path"], str) and row["path"].endswith("sh")
    assert result["warnings"] == []


# --- injected resolvers ---------------------------------------------------


def test_injected_all_present_and_all_null_resolvers(monkeypatch):
    _with_db(monkeypatch, _two_tool_db())
    up = package_doctor_rows(lambda binary: "/usr/bin/" + binary)
    assert [(row["tool"], row["binary"], row["present"], row["path"])
            for row in up["rows"]] == [
        ("alpha_tool", "alpha-tool", True, "/usr/bin/alpha-tool"),
        ("beta_tool", "beta-cmd", True, "/usr/bin/beta-cmd"),
    ]
    assert up["summary"] == {"present": 2, "missing": 0, "total": 2}
    assert up["warnings"] == []
    down = package_doctor_rows(lambda binary: None)
    assert [(row["tool"], row["present"], row["path"])
            for row in down["rows"]] == [
        ("alpha_tool", False, None),
        ("beta_tool", False, None),
    ]
    assert down["summary"] == {"present": 0, "missing": 2, "total": 2}
    assert down["warnings"] == []


def test_mixed_resolver_rows_are_sorted_with_dup_binaries(monkeypatch):
    _with_db(monkeypatch, {
        "zeta_tool": _td("zeta-tool"),
        "echo_tool": _td("alpha-tool", name="echo"),
        "alpha_tool": _td("alpha-tool"),
        "mike_tool": _td("mike-tool"),
    })
    table = {"zeta-tool": "/bin/zeta", "mike-tool": None,
             "alpha-tool": "/bin/alpha"}
    result = package_doctor_rows(table.get)
    assert [row["tool"] for row in result["rows"]] == [
        "alpha_tool", "echo_tool", "mike_tool", "zeta_tool"]
    assert result["rows"] == [
        {"tool": "alpha_tool", "binary": "alpha-tool", "present": True,
         "path": "/bin/alpha"},
        {"tool": "echo_tool", "binary": "alpha-tool", "present": True,
         "path": "/bin/alpha"},
        {"tool": "mike_tool", "binary": "mike-tool", "present": False,
         "path": None},
        {"tool": "zeta_tool", "binary": "zeta-tool", "present": True,
         "path": "/bin/zeta"},
    ]
    assert result["summary"] == {"present": 3, "missing": 1, "total": 4}
    assert result["warnings"] == []


def test_results_deterministic_across_reruns(monkeypatch):
    _with_db(monkeypatch, _two_tool_db())
    table = {"alpha-tool": "/bin/alpha", "beta-cmd": None}
    one = package_doctor_rows(table.get)
    two = package_doctor_rows(table.get)
    assert one == two
    assert json.loads(json.dumps(one)) == one
    live_one = package_doctor_rows()
    live_two = package_doctor_rows()
    assert live_one == live_two


def test_generated_at_is_injected_verbatim_or_none(monkeypatch):
    _with_db(monkeypatch, _two_tool_db())
    assert package_doctor_rows(lambda b: None)["generated_at"] is None
    stamp = "2026-10-07T20:00:00+00:00"
    assert package_doctor_rows(
        lambda b: None, generated_at=stamp)["generated_at"] == stamp


def test_resolver_raising_is_tolerated_as_missing(monkeypatch):
    _with_db(monkeypatch, _two_tool_db())

    def _boom(binary):
        raise RuntimeError("probe unavailable")

    result = package_doctor_rows(_boom)
    assert all(row["present"] is False and row["path"] is None
               for row in result["rows"])
    assert result["summary"] == {"present": 0, "missing": 2, "total": 2}
    assert len(result["warnings"]) == 2
    joined = "\n".join(result["warnings"])
    assert "resolver raised" in joined
    assert "RuntimeError" in joined
    for row in result["rows"]:
        assert row["tool"] in joined


def test_resolver_receives_each_scrubbed_binary_exactly_once(monkeypatch):
    _with_db(monkeypatch, {
        "a_tool": _td("a-cmd"),
        "b_tool": _td("b\x01cmd"),
    })
    calls = []

    def spy(binary):
        calls.append(binary)
        return "/bin/" + binary

    result = package_doctor_rows(spy)
    assert sorted(calls) == ["a-cmd", "bcmd"]  # scrubbed, one call each
    assert result["summary"] == {"present": 2, "missing": 0, "total": 2}
    assert result["rows"][0]["binary"] == "a-cmd"
    assert result["rows"][1]["binary"] == "bcmd"


def test_mapping_rows_are_accepted(monkeypatch):
    _with_db(monkeypatch, {
        "delta_tool": {"name": "delta", "command": "delta-cmd"},
    })
    result = package_doctor_rows(lambda b: "/bin/" + b)
    assert result["rows"] == [
        {"tool": "delta_tool", "binary": "delta-cmd", "present": True,
         "path": "/bin/delta-cmd"},
    ]
    assert result["summary"] == {"present": 1, "missing": 0, "total": 1}
    assert result["warnings"] == []


# --- tolerance: malformed rows, malformed catalogs, hostile returns -------

MALFORMED_ROWS = [
    ("mapping-without-command", {"name": "x"}),
    ("command-not-a-string", {"name": "x", "command": 123}),
    ("command-blank", {"name": "x", "command": "   "}),
    ("command-control-chars-only", {"name": "x", "command": CTRL}),
    ("plain-string-row", "a bare string, not a row"),
    ("integer-row", 12345),
]


@pytest.mark.parametrize("label,bad_row", MALFORMED_ROWS,
                         ids=[label for label, _ in MALFORMED_ROWS])
def test_malformed_rows_are_skipped_with_a_warning(label, bad_row,
                                                   monkeypatch):
    _with_db(monkeypatch, {"good_tool": _td("good-cmd"), "bad_row": bad_row})
    result = package_doctor_rows(lambda b: None)
    assert result["summary"] == {"present": 0, "missing": 1, "total": 1}
    assert [row["tool"] for row in result["rows"]] == ["good_tool"]
    assert len(result["warnings"]) == 1
    assert result["warnings"][0].strip()
    assert "skipped" in result["warnings"][0]


HOSTILE_RETURNS = [
    (42, True),        # non-string, non-None -> warned missing
    (True, True),
    (["p"], True),
    ("   ", False),    # a blank string resolves silent-missing
]


@pytest.mark.parametrize("bad_return,expect_warning", HOSTILE_RETURNS,
                         ids=["int", "bool", "list", "blank-string"])
def test_hostile_resolver_returns_grade_as_missing(bad_return,
                                                   expect_warning,
                                                   monkeypatch):
    _with_db(monkeypatch, {"lone_tool": _td("lone-cmd")})
    result = package_doctor_rows(lambda b: bad_return)
    row = result["rows"][0]
    assert row["present"] is False and row["path"] is None
    assert result["summary"] == {"present": 0, "missing": 1, "total": 1}
    assert bool(result["warnings"]) == expect_warning
    if expect_warning:
        assert result["warnings"] and all(
            warning.strip() for warning in result["warnings"])
        assert "marked missing" in result["warnings"][0]


@pytest.mark.parametrize("bad_db", [None, 42])
def test_non_mapping_catalog_is_tolerated_with_a_warning(bad_db, monkeypatch):
    _with_db(monkeypatch, bad_db)
    result = package_doctor_rows(lambda b: None)
    assert result["rows"] == []
    assert result["summary"] == {"present": 0, "missing": 0, "total": 0}
    assert len(result["warnings"]) == 1
    assert "not a mapping" in result["warnings"][0]


def test_empty_catalog_renders_an_empty_checkup(monkeypatch):
    _with_db(monkeypatch, {})
    result = package_doctor_rows(lambda b: None)
    assert result == {
        "rows": [],
        "summary": {"present": 0, "missing": 0, "total": 0},
        "generated_at": None,
        "warnings": [],
    }


@pytest.mark.parametrize("bad_resolver", [42, "which", {"a": 1}])
def test_non_callable_resolver_is_refused_closed(bad_resolver):
    with pytest.raises(ValueError) as err:
        package_doctor_rows(resolver=bad_resolver)
    assert "resolver" in str(err.value)


# --- echo hygiene ---------------------------------------------------------


def test_echoes_are_scrubbed_and_json_safe(monkeypatch):
    _with_db(monkeypatch, {"t\x01ool\nX": _td("c\x02md\nX")})
    result = package_doctor_rows(lambda b: "/bin/\x03zed\n" + b)
    row = result["rows"][0]
    assert row == {
        "tool": "toolX", "binary": "cmdX", "present": True,
        "path": "/bin/zedcmdX",
    }
    for field in ("tool", "binary", "path"):  # present is a strict bool
        value = row[field]
        assert isinstance(value, str)
        assert all(ord(char) >= 0x20 for char in value)
    assert json.loads(json.dumps(result)) == result


# --- laziness + purity -----------------------------------------------------


def test_catalog_binding_is_lazy_not_module_level():
    assert "KALI_TOOLS_DB" not in vars(doctor_mod)
    assert "kali" not in vars(doctor_mod)


def test_module_purity_source_scan():
    source = Path(doctor_mod.__file__).read_text(encoding="utf-8")
    for forbidden in (
        # no process spawning or dynamic execution
        "subprocess", "popen", "os.system", "eval(", "exec(",
        # no network facilities
        "urllib", "socket", "requests", "http.client",
        # no clock reads: the stamp arrives by injection
        "utcnow", "time.time", "today(", "gmtime", "localtime",
    ):
        assert forbidden not in source, forbidden
    # the catalog import is lazy: one occurrence, indented (in the op)
    lazy_lines = [line for line in source.splitlines()
                  if "from agentic_ai" in line]
    assert len(lazy_lines) == 1
    assert lazy_lines[0].startswith("    ")
    assert "KALI_TOOLS_DB" in lazy_lines[0]