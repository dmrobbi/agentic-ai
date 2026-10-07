"""KA-079 tests - registry/doc sync checker shape and checks.

Synthetic registry shapes and synthetic AGENT_MATRIX-style text: no repo
imports, no network. Pinned here: every check's finding shape, the report
dict shape, determinism, input validation, the live-loader contract
(stubbed registry module for main(); one direct live_resolver probe),
and module execution purity (source scan). The REAL repo consistency
run is the builder's acceptance evidence, not a unit test.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "ka_doc_sync", _REPO / "scripts" / "ka" / "doc_sync.py")
ds = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ds)

REGISTRY = {
    "base": {"class": "BaseAgent", "module": "pkg.agents.base",
             "category": "Core", "description": "Base agent"},
    "sales": {"class": "SalesAgent", "module": "pkg.agents.sales",
              "category": "Business", "description": "Sales ops"},
}

MATRIX = """# Agent Capability Matrix

## Quick Reference

| ID | Agent | Category | Capabilities | Tests |
|----|-------|----------|--------------|-------|
| `base` | Base Agent | Core | 3 | 5 |
| `sales` | Sales Agent | Business | 4 | 8 |

---

## Core Agents

### Base Agent (`base.py`)

**Purpose**: Foundation agent with core functionality

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `initialize` | Initialize agent state | `config: dict` | `status: bool` |
| `execute` | Execute action | `action: str` | `result: dict` |
| `shutdown` | Graceful shutdown | - | `status: bool` |

**File**: `pkg/agents/base.py`
**Tests**: `tests/test_base_agent.py` (5 tests)

---

## Business Agents

### Sales Agent (`sales.py`)

**Purpose**: Sales operations and lead management

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `create_lead` | Create sales lead | `contact: dict` | `lead: dict` |
| `qualify_lead` | Qualify lead | `lead_id: str` | `lead: dict` |
| `create_opportunity` | Create opportunity | `lead_id: str` | `opp: dict` |
| `generate_proposal` | Generate proposal | `opp_id: str` | `str` |

**File**: `pkg/agents/sales.py`
**Tests**: `tests/test_sales_agent.py` (8 tests)

---

## Test Coverage Summary

| Category | Agents | Tests | Coverage |
|----------|--------|-------|----------|
| Core | 1 | 5 | 100% |
| Business | 1 | 8 | 100% |
| **Total** | **2** | **13** | **100%** |
"""


class _DocBase:
    """Foundation agent with core functionality."""


class _DocSales:
    """Sales operations and lead management."""


class _NoDoc:
    pass


_LongDoc = type("_LongDoc", (), {"__doc__": "L" * 261})


def _resolver(mapping):
    return lambda agent_id: mapping.get(agent_id)


def _swap(text, old, new):
    assert text.count(old) == 1, "anchor not unique: %r" % old
    return text.replace(old, new, 1)


def _checks(report, name):
    return [f for f in report["findings"] if f["check"] == name]


def _report(matrix_text=MATRIX, *, resolver=None, repo_root=None,
            registry=None, card_limit=260):
    return ds.build_report(REGISTRY if registry is None else registry,
                           matrix_text, repo_root=repo_root,
                           resolver=resolver, card_doc_limit=card_limit)


# ---------------------------------------------------------------- shape

def test_clean_baseline_report_is_consistent(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_base_agent.py").write_text("def test_x(): pass\n")
    (tests_dir / "test_sales_agent.py").write_text("def test_x(): pass\n")
    report = _report(resolver=_resolver({"base": _DocBase,
                                         "sales": _DocSales}),
                     repo_root=tmp_path)
    assert report["tool"] == "ka-doc-sync"
    assert report["spec"] == "OPT-79 / KA-079"
    assert report["registry_agents"] == 2
    assert report["matrix_rows"] == 2
    assert report["matrix_sections"] == 2
    assert report["summary_categories"] == 2
    assert report["findings"] == []
    assert report["inconsistencies"] == 0
    assert report["verdict"] == "consistent"
    assert report["checks_skipped"] == []
    assert report["checks_run"] == [
        "card_missing", "card_overlength", "category_mismatch",
        "description_duplicate", "description_missing",
        "file_header_mismatch", "matrix_row_missing", "matrix_row_unknown",
        "registry_class_unresolved", "section_file_missing",
        "section_missing", "section_op_count_mismatch",
        "section_purpose_missing", "section_tests_count_mismatch",
        "section_tests_file_missing", "section_unknown",
        "summary_count_mismatch", "summary_total_mismatch"]


def test_findings_sorted_and_deterministic(tmp_path):
    drifted = _swap(MATRIX, "| `base` | Base Agent | Core | 3 | 5 |\n", "")
    resolver = _resolver({"base": _NoDoc, "sales": _DocSales})
    one = _report(drifted, resolver=resolver)
    two = _report(drifted, resolver=resolver)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
    keys = [(f["check"], f["agent"], f["detail"]) for f in one["findings"]]
    assert keys == sorted(keys)
    assert one["inconsistencies"] == len(one["findings"])
    assert one["verdict"] == "drift"
    assert report_keys_shape(one)


def report_keys_shape(report):
    expected = {"tool", "spec", "registry_agents", "matrix_rows",
                "matrix_sections", "summary_categories", "checks_run",
                "checks_skipped", "findings", "inconsistencies", "verdict"}
    return expected <= set(report)


def test_inputs_are_not_mutated():
    registry = json.loads(json.dumps(REGISTRY))
    matrix_text = MATRIX + "\ntrailing"
    _report(matrix_text, registry=registry, resolver=_resolver(
        {"base": _DocBase, "sales": _DocSales}))
    assert registry == REGISTRY


# ---------------------------------------------------------------- parse

def test_quick_ref_fields_are_pinned():
    rows = ds.parse_quick_ref(MATRIX)
    assert rows == {
        "base": {"agent": "Base Agent", "category": "Core",
                 "caps": 3, "tests": 5},
        "sales": {"agent": "Sales Agent", "category": "Business",
                  "caps": 4, "tests": 8}}


def test_section_parse_wraps_purpose_and_counts_ops():
    wrapped = _swap(
        MATRIX,
        "**Purpose**: Foundation agent with core functionality\n",
        "**Purpose**: Foundation agent with core\nfunctionality and "
        "shared protocol\n")
    sections = ds.parse_sections(wrapped)
    by_file = {s["header_file"]: s for s in sections}
    base = by_file["base.py"]
    assert base["purpose"] == ("Foundation agent with core functionality "
                              "and shared protocol")
    assert base["file_path"] == "pkg/agents/base.py"
    assert base["op_count"] == 3
    assert base["tests_file"] == "tests/test_base_agent.py"
    assert base["tests_count"] == 5
    assert by_file["sales.py"]["op_count"] == 4


def test_summary_parse_categories_and_total():
    summary = ds.parse_summary(MATRIX)
    assert summary == {"categories": {"Core": 1, "Business": 1},
                       "total": 2}


# ------------------------------------------------------------------ id
# coverage / categories / sections vs the registry


def test_matrix_row_missing_flagged():
    drifted = _swap(MATRIX, "| `base` | Base Agent | Core | 3 | 5 |\n", "")
    report = _report(drifted)
    assert _checks(report, "matrix_row_missing") == [{
        "check": "matrix_row_missing", "agent": "base",
        "detail": "registry id has no Quick Reference row"}]


def test_matrix_row_unknown_flagged():
    drifted = _swap(MATRIX, "| `base` | Base Agent | Core | 3 | 5 |",
                    "| `base` | Base Agent | Core | 3 | 5 |\n"
                    "| `ghost` | Ghost Agent | Core | 1 | 2 |")
    report = _report(drifted)
    rows = _checks(report, "matrix_row_unknown")
    assert len(rows) == 1 and rows[0]["agent"] == "ghost"


def test_category_mismatch_flagged():
    drifted = _swap(MATRIX, "Core | 3 | 5", "Securiy | 3 | 5")
    report = _report(drifted)
    rows = _checks(report, "category_mismatch")
    assert len(rows) == 1 and rows[0]["agent"] == "base"
    assert "!= registry 'Core'" in rows[0]["detail"]


BASE_SECTION = """### Base Agent (`base.py`)

**Purpose**: Foundation agent with core functionality

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `initialize` | Initialize agent state | `config: dict` | `status: bool` |
| `execute` | Execute action | `action: str` | `result: dict` |
| `shutdown` | Graceful shutdown | - | `status: bool` |

**File**: `pkg/agents/base.py`
**Tests**: `tests/test_base_agent.py` (5 tests)

---

"""


def test_section_missing_flagged():
    drifted = _swap(MATRIX, BASE_SECTION, "")
    report = _report(drifted)
    rows = _checks(report, "section_missing")
    assert len(rows) == 1 and rows[0]["agent"] == "base"
    assert "no agent-matrix section" in rows[0]["detail"]


def test_section_unknown_flagged():
    drifted = _swap(
        MATRIX,
        "**File**: `pkg/agents/sales.py`",
        "**File**: `pkg/agents/ghost.py`")
    report = _report(drifted)
    rows = _checks(report, "section_unknown")
    assert len(rows) == 1 and "no registry module match" in rows[0]["detail"]


def test_section_file_missing_matches_by_header_name():
    registry = dict(REGISTRY)
    registry["biblical"] = {"class": "BiblicalAgent",
                            "module": "pkg.agents.biblical_scholar",
                            "category": "Specialized",
                            "description": "Biblical research"}
    drifted = MATRIX.replace(
        "## Test Coverage Summary",
        """## Specialized Agents

### Biblical Scholar Agent (`biblical_scholar.py`)

**Purpose**: Cross-tradition scripture research

**Tests**: `tests/test_biblical.py` (4 tests)

---

## Test Coverage Summary""", 1)
    report = _report(drifted, registry=registry)
    missing = _checks(report, "section_file_missing")
    assert missing == [{"check": "section_file_missing", "agent": "biblical",
                        "detail": ("section has no **File** line; matched by "
                                   "header name")}]
    assert all(f["agent"] != "biblical"
               for f in _checks(report, "section_missing"))


def test_file_header_mismatch_flagged():
    drifted = _swap(MATRIX,
                    "### Base Agent (`base.py`)",
                    "### Base Agent (`basex.py`)")
    report = _report(drifted)
    rows = _checks(report, "file_header_mismatch")
    assert len(rows) == 1 and rows[0]["agent"] == "base"


def test_section_purpose_missing_flagged():
    drifted = _swap(MATRIX,
                    "**Purpose**: Foundation agent with core "
                    "functionality\n", "")
    report = _report(drifted)
    rows = _checks(report, "section_purpose_missing")
    assert len(rows) == 1 and rows[0]["agent"] == "base"


# ---------------------------------------------------------------- cards

def test_registry_class_unresolved_findings():
    resolver = _resolver({"sales": _DocSales})      # base -> None
    report = _report(resolver=resolver)
    rows = _checks(report, "registry_class_unresolved")
    assert len(rows) == 1 and rows[0]["agent"] == "base"
    assert "'BaseAgent'" in rows[0]["detail"]


def test_card_missing_findings():
    resolver = _resolver({"base": _NoDoc, "sales": _DocSales})
    report = _report(resolver=resolver)
    rows = _checks(report, "card_missing")
    assert len(rows) == 1 and rows[0]["agent"] == "base"


def test_card_overlength_findings():
    resolver = _resolver({"base": _LongDoc, "sales": _DocSales})
    report = _report(resolver=resolver)
    rows = _checks(report, "card_overlength")
    assert len(rows) == 1 and rows[0]["agent"] == "base"
    assert "261 chars > cap 260" in rows[0]["detail"]


def test_card_doc_at_limit_is_clean():
    _Max = type("_Max", (), {"__doc__": "M" * 260})
    report = _report(resolver=_resolver({"base": _Max, "sales": _DocSales}))
    assert _checks(report, "card_overlength") == []
    assert _checks(report, "card_missing") == []


def test_card_checks_skipped_without_resolver():
    report = _report()
    assert report["checks_skipped"] == [
        "card_missing", "card_overlength", "registry_class_unresolved",
        "section_tests_file_missing"]
    for name in ("card_missing", "card_overlength",
                 "registry_class_unresolved"):
        assert name not in report["checks_run"]
        assert _checks(report, name) == []


# ----------------------------------------------------- registry descs

def test_description_missing_flagged():
    registry = json.loads(json.dumps(REGISTRY))
    registry["base"]["description"] = "   "
    report = _report(registry=registry)
    rows = _checks(report, "description_missing")
    assert len(rows) == 1 and rows[0]["agent"] == "base"


def test_description_duplicate_flagged():
    registry = json.loads(json.dumps(REGISTRY))
    registry["sales"]["description"] = "Base agent"
    report = _report(registry=registry)
    rows = _checks(report, "description_duplicate")
    assert len(rows) == 1
    assert "base, sales" in rows[0]["agent"]
    assert "2 agents share" in rows[0]["detail"]


# -------------------------------------------- section count cross-checks

def test_section_op_count_mismatch_flagged():
    drifted = _swap(MATRIX, "Core | 3 | 5", "Core | 9 | 5")
    report = _report(drifted)
    rows = _checks(report, "section_op_count_mismatch")
    assert len(rows) == 1 and rows[0]["agent"] == "base"
    assert "rows 3 != quick-ref caps 9" in rows[0]["detail"]


def test_section_tests_count_mismatch_flagged():
    drifted = _swap(MATRIX,
                    "**Tests**: `tests/test_base_agent.py` (5 tests)",
                    "**Tests**: `tests/test_base_agent.py` (11 tests)")
    report = _report(drifted)
    rows = _checks(report, "section_tests_count_mismatch")
    assert len(rows) == 1 and rows[0]["agent"] == "base"


def test_section_tests_file_missing_or_skipped(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_base_agent.py").write_text("def test_x(): pass\n")
    # sales tests file deliberately absent under tmp root
    report = _report(repo_root=tmp_path)
    rows = _checks(report, "section_tests_file_missing")
    assert len(rows) == 1 and rows[0]["agent"] == "sales"
    assert "test_sales_agent.py does not exist" in rows[0]["detail"]
    # without a repo root the check is skipped entirely
    report = _report()
    assert _checks(report, "section_tests_file_missing") == []
    assert "section_tests_file_missing" in report["checks_skipped"]


# ------------------------------------------------------------- summary

def test_summary_count_mismatch_flagged():
    drifted = _swap(MATRIX, "| Core | 1 | 5 | 100% |",
                    "| Core | 9 | 5 | 100% |")
    report = _report(drifted)
    rows = _checks(report, "summary_count_mismatch")
    assert len(rows) == 1
    assert "'Core' claims 9 agents; quick-ref has 1" in rows[0]["detail"]


def test_summary_unknown_category_and_total_flagged():
    drifted = _swap(MATRIX, "| Core | 1 | 5 | 100% |",
                    "| Core | 1 | 5 | 100% |\n| Ops | 2 | 9 | 100% |")
    drift2 = _swap(drifted, "| **Total** | **2** | **13** | **100%** |",
                   "| **Total** | **7** | **13** | **100%** |")
    report = _report(drift2)
    unknown = _checks(report, "summary_count_mismatch")
    assert len(unknown) == 1 and "'Ops' claims 2" in unknown[0]["detail"]
    totals = _checks(report, "summary_total_mismatch")
    assert len(totals) == 1 and "7 agents != 2 quick-ref rows" \
        in totals[0]["detail"]


# --------------------------------------------------------------- purity

def test_input_validation_raises():
    with pytest.raises(ValueError):
        ds.build_report(REGISTRY, "   \n")
    with pytest.raises(ValueError):
        ds.build_report({}, MATRIX)
    bad = {"ghost": {"class": "GhostAgent", "module": "pkg.g"}}
    with pytest.raises(ValueError):
        ds.build_report(bad, MATRIX)
    headless = MATRIX.replace("## Quick Reference", "## Rows Removed", 1)
    with pytest.raises(ValueError):
        ds.build_report(REGISTRY, headless)


def test_main_with_stub_registry(tmp_path, monkeypatch, capsys):
    stub = types.ModuleType("agentic_ai.agents.registry")
    stub.AGENT_REGISTRY = {}
    stub.list_agents = lambda: json.loads(json.dumps(REGISTRY))
    monkeypatch.setitem(sys.modules, "agentic_ai.agents.registry", stub)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_base_agent.py").write_text("def test_x(): pass\n")
    (tests_dir / "test_sales_agent.py").write_text("def test_x(): pass\n")
    matrix = tmp_path / "AGENT_MATRIX.md"
    matrix.write_text(MATRIX, encoding="utf-8")
    argv = ["--json", "--matrix", str(matrix), "--repo", str(tmp_path),
            "--no-cards"]
    assert ds.main(argv) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "consistent"
    matrix.write_text(_swap(MATRIX,
                            "| `base` | Base Agent | Core | 3 | 5 |\n", ""),
                      encoding="utf-8")
    assert ds.main([a for a in argv if a != "--json"]) == 1
    printed = capsys.readouterr().out
    assert "drift" in printed and "matrix_row_missing" in printed


def test_live_resolver_contract():
    klass = ds.live_resolver("kali")
    assert klass is not None and klass.__name__ == "KaliAgent"
    assert klass.__doc__ and klass.__doc__.strip()
    assert ds.live_resolver("definitely-not-an-agent-id") is None


def test_module_is_execution_pure():
    source = Path(_SPEC.origin).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "socket", "urllib",
                   "requests."):
        assert banned not in source, banned
    assert not source.lstrip().startswith(("<", "#!bad"))
