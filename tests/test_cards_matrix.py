"""KA-093 tests - cards/matrix sync checker shape and checks.

Synthetic registry dicts + synthetic AGENT_MATRIX-style text: no repo
imports, no network. Pinned here: every diff KIND's finding shape, the
report dict shape, determinism, input validation, op counting (the
`agent ops` class-level surface: exclusions, non-callables), the
docstring-derived purpose rule, the stubbed-registry main() contract,
module execution purity, and a LIVE smoke gate run that only asserts the
checker runs and returns integer counts (no hard pin on live numbers -
the matrix is mid-wave).
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
    "ka_cards_matrix", _REPO / "tools" / "check_cards_matrix.py")
cm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cm)

REG = {
    "base": {"class": "BaseAgent", "module": "pkg.agents.base",
             "category": "Core", "description": "Base agent"},
    "sales": {"class": "SalesAgent", "module": "pkg.agents.sales",
              "category": "Business", "description": "Sales ops"},
}

ROW_BASE = "| `base` | Base Agent | Core | 5 | 8 |\n"
ROW_SALES = "| `sales` | Sales Agent | Business | 4 | 8 |\n"

SECTION_BASE = """### Base Agent (`base.py`)

**Purpose**: Foundation agent with core functionality

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `op_one` | op one | - | `-` |
| `op_two` | op two | - | `-` |
| `op_three` | op three | - | `-` |
| `op_four` | op four | - | `-` |
| `op_five` | op five | - | `-` |

**File**: `pkg/agents/base.py`
**Tests**: `tests/test_base_agent.py` (8 tests)

---

"""

SECTION_SALES = """### Sales Agent (`sales.py`)

**Purpose**: Sales operations and lead management

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `sale_one` | sale one | - | `-` |
| `sale_two` | sale two | - | `-` |
| `sale_three` | sale three | - | `-` |
| `sale_four` | sale four | - | `-` |

**File**: `pkg/agents/sales.py`
**Tests**: `tests/test_sales_agent.py` (8 tests)

---

"""

HEADER = """# Agent Capability Matrix

Complete reference of the Agentic AI agents. Every quick-ref row, agent
section, and Test Coverage Summary counter must be regenerated from the
live registry.

"""

QUICK_REF = """## Quick Reference

| ID | Agent | Category | Capabilities | Tests |
|----|-------|----------|--------------|-------|
""" + ROW_BASE + ROW_SALES + """
---

"""

CORE = "## Core Agents\n\n" + SECTION_BASE
BUSINESS = "## Business Agents\n\n" + SECTION_SALES

SUMMARY = """## Test Coverage Summary

| Category | Agents | Tests | Coverage |
|----------|--------|-------|----------|
| Core | 1 | 8 | 100% |
| Business | 1 | 8 | 100% |
| **Total** | **2** | **16** | **100%** |
"""

MATRIX = HEADER + QUICK_REF + CORE + BUSINESS + SUMMARY

CAPS_TABLE_BASE = "\n".join([
    "| `op_one` | op one | - | `-` |",
    "| `op_two` | op two | - | `-` |",
    "| `op_three` | op three | - | `-` |",
    "| `op_four` | op four | - | `-` |",
    "| `op_five` | op five | - | `-` |",
]) + "\n"


class _BaseCard:
    """Foundation agent with core functionality"""

    def op_one(self):
        return self

    def op_two(self):
        return self

    def op_three(self):
        return self

    def op_four(self):
        return self

    def op_five(self):
        return self


class _SalesCard:
    """Sales operations and lead management"""

    def sale_one(self):
        return self

    def sale_two(self):
        return self

    def sale_three(self):
        return self

    def sale_four(self):
        return self


class _NoDocFiveOps:
    def alpha(self):
        return self

    def beta(self):
        return self

    def gamma(self):
        return self

    def delta(self):
        return self

    def epsilon(self):
        return self


class _MultiLineCard:
    """Sales agent: CRM, BANT/ICP qualification, and pipeline planning.

    Long-form operator guidance follows on later lines and never
    replaces the leading card purpose line.
    """


class _WithExcludedSurface:
    """Excluded-name probe."""

    def agent_id(self):  # noqa - mirrors the chassis name exclusion
        return "x"

    def inference(self):
        return "y"

    def op_only(self):
        return self


_CLASSES = {"base": _BaseCard, "sales": _SalesCard}


def _resolver(mapping):
    return lambda agent_id: mapping.get(agent_id)


_CLEAN_RESOLVER = _resolver(_CLASSES)


def _swap(text, old, new):
    assert text.count(old) == 1, "anchor not unique: %r" % old
    return text.replace(old, new, 1)


def _checks(report, kind):
    return [d for d in report["diffs"] if d["kind"] == kind]


def _report(matrix_text=MATRIX, *, registry=None, resolver=None):
    return cm.build_report(REG if registry is None else registry,
                           matrix_text, resolver=resolver)


# ---------------------------------------------------------------- shape

def test_contract_kinds_and_tool_fields_are_pinned():
    assert cm.DIFF_KINDS == ("missing_row", "extra_row", "count_mismatch",
                             "category_mismatch", "docstring_drift",
                             "capability_line_drift")
    report = _report(resolver=_CLEAN_RESOLVER)
    assert report["tool"] == "ka-cards-matrix"
    assert report["spec"] == "OPT-93 / KA-093"


def test_clean_baseline_report_is_clean():
    report = _report(resolver=_CLEAN_RESOLVER)
    assert report["verdict"] == "clean"
    assert report["diffs"] == []
    assert report["diffs_total"] == 0
    assert report["registry"] == {"agents": 2, "cards": {
        "base": {"category": "Core",
                 "purpose": "Foundation agent with core functionality",
                 "ops": 5},
        "sales": {"category": "Business",
                  "purpose": "Sales operations and lead management",
                  "ops": 4}}}
    assert report["matrix"] == {"rows": 2, "summary": 2}


def test_findings_sorted_and_deterministic():
    drifted = _swap(MATRIX, "Core | 5 | 8", "Core | 9 | 8")
    one = _report(drifted, resolver=_CLEAN_RESOLVER)
    two = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
    keys = [(d["kind"], d["agent"], d["detail"]) for d in one["diffs"]]
    assert keys == sorted(keys)
    assert one["diffs_total"] == len(one["diffs"])
    assert one["verdict"] == "drift"


def test_inputs_are_not_mutated():
    registry = json.loads(json.dumps(REG))
    matrix_text = MATRIX + "\ntrailing"
    _report(matrix_text, registry=registry, resolver=_CLEAN_RESOLVER)
    assert registry == REG
    assert matrix_text == MATRIX + "\ntrailing"


# ------------------------------------------------------------------ id
# coverage, categories, row counters


def test_missing_row_flagged_and_mirrors_summary_layer():
    drifted = _swap(MATRIX, ROW_BASE, "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "missing_row") == [{
        "kind": "missing_row", "agent": "base",
        "detail": "registry id has no Quick Reference row"}]
    # the summary counters mirror the row layer: registry -> rows -> summary
    details = [d["detail"] for d in _checks(report, "count_mismatch")]
    assert "summary Total 2 agents != 1 quick-ref rows" in details
    assert ("summary category 'Core' claims 1 agents; quick-ref has 0"
            in details)


def test_extra_row_flagged():
    drifted = _swap(MATRIX, ROW_BASE, ROW_BASE
                    + "| `ghost` | Ghost Agent | Core | 1 | 2 |\n")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    rows = _checks(report, "extra_row")
    assert len(rows) == 1 and rows[0]["agent"] == "ghost"
    details = [d["detail"] for d in _checks(report, "count_mismatch")]
    assert ("summary category 'Core' claims 1 agents; quick-ref has 2"
            in details)


def test_category_mismatch_flagged():
    drifted = _swap(MATRIX, "Base Agent | Core | 5",
                    "Base Agent | Securiy | 5")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "category_mismatch") == [{
        "kind": "category_mismatch", "agent": "base",
        "detail": "quick-ref category 'Securiy' != registry 'Core'"}]


def test_count_mismatch_caps_flagged():
    drifted = _swap(MATRIX, "Core | 5 | 8", "Core | 9 | 8")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "count_mismatch") == [{
        "kind": "count_mismatch", "agent": "base",
        "detail": "quick-ref caps 9 != live op count 5"}]
    assert report["diffs_total"] == 1


def test_count_mismatch_summary_total_flagged():
    drifted = _swap(MATRIX,
                    "| **Total** | **2** | **16** | **100%** |",
                    "| **Total** | **7** | **16** | **100%** |")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "count_mismatch") == [{
        "kind": "count_mismatch", "agent": None,
        "detail": "summary Total 7 agents != 2 quick-ref rows"}]
    assert report["diffs_total"] == 1


def test_count_mismatch_summary_category_flagged():
    drifted = _swap(MATRIX, "| Core | 1 | 8 | 100% |",
                    "| Core | 9 | 8 | 100% |")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "count_mismatch") == [{
        "kind": "count_mismatch", "agent": None,
        "detail": "summary category 'Core' claims 9 agents; "
                  "quick-ref has 1"}]
    assert report["diffs_total"] == 1


def test_count_mismatch_summary_unknown_category_flagged():
    drifted = _swap(MATRIX, "| Core | 1 | 8 | 100% |",
                    "| Core | 1 | 8 | 100% |\n| Ops | 2 | 9 | 100% |")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "count_mismatch") == [{
        "kind": "count_mismatch", "agent": None,
        "detail": "summary category 'Ops' claims 2 agents; "
                  "quick-ref has 0"}]
    assert report["diffs_total"] == 1


def test_count_mismatch_summary_total_missing_flagged():
    drifted = _swap(MATRIX,
                    "| **Total** | **2** | **16** | **100%** |\n", "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "count_mismatch") == [{
        "kind": "count_mismatch", "agent": None,
        "detail": "summary has no **Total** row"}]
    assert report["diffs_total"] == 1


# ------------------------------------------------------- purpose + lines

def test_docstring_drift_flagged():
    drifted = _swap(
        MATRIX,
        "**Purpose**: Foundation agent with core functionality\n",
        "**Purpose**: Foundation agent with core ops\n")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "docstring_drift") == [{
        "kind": "docstring_drift", "agent": "base",
        "detail": "card purpose 'Foundation agent with core "
                  "functionality' != section purpose 'Foundation agent "
                  "with core ops'"}]
    assert report["diffs_total"] == 1


def test_docstring_purpose_missing_flagged():
    drifted = _swap(
        MATRIX,
        "**Purpose**: Foundation agent with core functionality\n", "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "docstring_drift") == [{
        "kind": "docstring_drift", "agent": "base",
        "detail": "section has no **Purpose** paragraph"}]
    assert report["diffs_total"] == 1


def test_section_missing_fires_both_purpose_and_line_drift():
    drifted = _swap(MATRIX, SECTION_BASE, "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "docstring_drift") == [{
        "kind": "docstring_drift", "agent": "base",
        "detail": "no AGENT_MATRIX section matched module "
                  "'pkg.agents.base'; purpose not shown"}]
    assert _checks(report, "capability_line_drift") == [{
        "kind": "capability_line_drift", "agent": "base",
        "detail": "no AGENT_MATRIX section matched module "
                  "'pkg.agents.base'; capability lines not shown"}]
    assert report["diffs_total"] == 2


def test_capability_line_drift_flagged():
    drifted = _swap(MATRIX, "| `op_five` | op five | - | `-` |\n", "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "capability_line_drift") == [{
        "kind": "capability_line_drift", "agent": "base",
        "detail": "section capability rows 4 != live op count 5"}]
    assert report["diffs_total"] == 1


def test_capability_rows_missing_flagged():
    drifted = _swap(MATRIX, CAPS_TABLE_BASE, "")
    report = _report(drifted, resolver=_CLEAN_RESOLVER)
    assert _checks(report, "capability_line_drift") == [{
        "kind": "capability_line_drift", "agent": "base",
        "detail": "section has no capability rows"}]
    assert report["diffs_total"] == 1


def test_registry_class_unresolved_fires_both_layers():
    report = _report(resolver=_resolver({"sales": _SalesCard}))
    assert _checks(report, "docstring_drift") == [{
        "kind": "docstring_drift", "agent": "base",
        "detail": "class 'BaseAgent' does not import; card purpose "
                  "unknown"}]
    assert _checks(report, "capability_line_drift") == [{
        "kind": "capability_line_drift", "agent": "base",
        "detail": "class 'BaseAgent' does not import; op count unknown"}]
    assert report["diffs_total"] == 2


def test_empty_docstring_drift_flagged():
    report = _report(resolver=_resolver({"base": _NoDocFiveOps,
                                         "sales": _SalesCard}))
    assert _checks(report, "docstring_drift") == [{
        "kind": "docstring_drift", "agent": "base",
        "detail": "class docstring (the /team/ card) is empty"}]
    assert report["diffs_total"] == 1


# ---------------------------------------------------------------- cards

def test_card_purpose_uses_first_docstring_line():
    assert cm.card_purpose(_MultiLineCard) == (
        "Sales agent: CRM, BANT/ICP qualification, and pipeline planning.")
    assert cm.card_purpose(_BaseCard) == (
        "Foundation agent with core functionality")
    assert cm.card_purpose(_NoDocFiveOps) is None


def test_op_count_excludes_chassis_and_noncallables():
    assert cm.class_op_count(_WithExcludedSurface) == 1
    assert cm.class_op_count(_BaseCard) == 5


# ------------------------------------------------------------- validation

def test_input_validation_raises():
    with pytest.raises(ValueError):
        _report("   \n")
    with pytest.raises(ValueError):
        _report(registry={})
    malformed = {"ghost": {"class": "GhostAgent", "module": "pkg.g"}}
    with pytest.raises(ValueError):
        _report(registry=malformed)
    headless = MATRIX.replace("## Quick Reference", "## Rows Removed", 1)
    with pytest.raises(ValueError):
        _report(headless)
    no_sections = _swap(MATRIX, "### Base Agent (`base.py`)", "Base Agent")
    no_sections = _swap(no_sections, "### Sales Agent (`sales.py`)",
                        "Sales Agent")
    with pytest.raises(ValueError):
        _report(no_sections)
    no_summary = MATRIX.replace("## Test Coverage Summary",
                                "## Coverage Removed", 1)
    with pytest.raises(ValueError):
        _report(no_summary)


# ------------------------------------------------------------------- main

def test_main_with_stub_registry(tmp_path, monkeypatch, capsys):
    stub = types.ModuleType("agentic_ai.agents.registry")
    stub.AGENT_REGISTRY = {}
    stub.list_agents = lambda: json.loads(json.dumps(REG))
    stub.resolve_agent_class = lambda agent_id: _CLASSES.get(agent_id)
    monkeypatch.setitem(sys.modules, "agentic_ai.agents.registry", stub)
    matrix = tmp_path / "AGENT_MATRIX.md"
    matrix.write_text(MATRIX, encoding="utf-8")
    assert cm.main(["--json", "--matrix", str(matrix)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "clean"
    assert out["matrix"] == {"rows": 2, "summary": 2}
    matrix.write_text(_swap(MATRIX, ROW_BASE, ""), encoding="utf-8")
    assert cm.main(["--matrix", str(matrix)]) == 1
    printed = capsys.readouterr().out
    assert "drift" in printed and "missing_row" in printed


# ------------------------------------------------------------------ live

def test_live_resolver_contract():
    klass = cm.live_resolver("kali")
    assert klass is not None and klass.__name__ == "KaliAgent"
    assert klass.__doc__ and klass.__doc__.strip()
    assert cm.live_resolver("definitely-not-an-agent-id") is None


def test_live_gate_runs_and_counts_are_integers(capsys):
    live_ids = cm.live_registry()
    rc = cm.main(["--json"])
    out = json.loads(capsys.readouterr().out)
    assert set(out) >= {"registry", "matrix", "diffs", "verdict",
                        "tool", "spec", "diffs_total"}
    # no hard pin on live numbers: the matrix is mid-wave, drift allowed
    assert isinstance(out["registry"]["agents"], int)
    assert out["registry"]["agents"] >= 1
    assert set(out["registry"]["cards"]) == set(live_ids)
    for card in out["registry"]["cards"].values():
        assert set(card) == {"category", "purpose", "ops"}
        assert isinstance(card["category"], str)
        assert card["purpose"] is None or isinstance(card["purpose"], str)
        assert card["ops"] is None or isinstance(card["ops"], int)
    assert isinstance(out["matrix"]["rows"], int)
    assert out["matrix"]["rows"] >= 1
    assert out["matrix"]["summary"] is None or \
        isinstance(out["matrix"]["summary"], int)
    assert out["verdict"] in ("clean", "drift")
    assert rc == (0 if out["verdict"] == "clean" else 1)
    assert rc in (0, 1)
    for diff in out["diffs"]:
        assert set(diff) == {"kind", "agent", "detail"}
        assert diff["kind"] in cm.DIFF_KINDS
        assert diff["agent"] is None or isinstance(diff["agent"], str)
        assert isinstance(diff["detail"], str)
    rc_readable = cm.main([])
    printed = capsys.readouterr().out
    assert rc_readable in (0, 1)
    assert "KA-093 cards/matrix sync:" in printed
    assert f"registry agents={len(live_ids)}" in printed


# ---------------------------------------------------------------- purity

def test_module_is_execution_pure():
    source = Path(_SPEC.origin).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "socket", "urllib",
                   "requests."):
        assert banned not in source, banned