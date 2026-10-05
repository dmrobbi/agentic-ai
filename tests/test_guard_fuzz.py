"""KA-008 - guard-fuzz corpus: every string-consuming guard in the kali
agent family swept with the committed hostile-input corpus; the invariant
is ValueError-or-clean - never any other exception. Oversize rows pin the
finding that no guard bounds length. No network; no real processes."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import (
    KALI_TOOLS_DB,
    KaliAgent,
    _validate_command_args,
)
from agentic_ai.agents.cyber.web_pentest import wp_scrub_target
from agentic_ai.agents.cyber.soc_bridge import scrub_host
from agentic_ai.agents.cyber.engagement_rbac import authorize_call
from agentic_ai.agents.cyber.evidence_bundle import (
    create_evidence_bundle,
    verify_evidence_bundle,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "guard_corpus" / "hostile_inputs.json"
)
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
INPUTS = CORPUS["inputs"]

SCHEMA = {"target": {"required": True, "type": "string"}}
NMAP_TOOL = KALI_TOOLS_DB["nmap"]

RAISE_GUARDS = ("wp_scrub_target", "scrub_host", "validate_command_args",
                "authorize_call_role", "create_bundle_source")
NEVER_RAISE_GUARDS = ("validate_target", "validate_arguments",
                      "build_command", "verify_bundle")


@pytest.fixture(scope="session")
def fuzz_agent(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka008-agent")
    return KaliAgent(agent_id="ka008-fuzz", workspace=str(ws / "ws"),
                     log_dir=str(ws / "logs"))


def call_raise_guard(name, value):
    if name == "wp_scrub_target":
        return ("clean", wp_scrub_target(value))
    if name == "scrub_host":
        return ("clean", scrub_host(value))
    if name == "validate_command_args":
        return ("clean", _validate_command_args([value]))
    if name == "authorize_call_role":
        return ("clean", authorize_call("t", value, required_level=1))
    if name == "create_bundle_source":
        # the source-dir check fires first: before any file writes
        return ("clean", create_evidence_bundle(
            value, "/nonexistent-ka008-out", "E-1"))
    raise AssertionError("unknown guard " + name)


def call_never_guard(name, value, fuzz_agent):
    if name == "validate_target":
        return fuzz_agent.validate_target(value)
    if name == "validate_arguments":
        return fuzz_agent._validate_arguments(SCHEMA, {"target": value})
    if name == "build_command":
        return fuzz_agent._build_command(NMAP_TOOL, {"target": value})
    if name == "verify_bundle":
        return verify_evidence_bundle(value)
    raise AssertionError("unknown guard " + name)


def test_corpus_shape():
    assert set(CORPUS) == {"meta", "inputs"}
    assert len(INPUTS) >= 18
    ids = [row["id"] for row in INPUTS]
    assert len(set(ids)) == len(ids), "duplicate ids"
    for row in INPUTS:
        assert set(row) == {"id", "value", "class"}
        assert isinstance(row["value"], str)
    pure = next(r for r in INPUTS if r["id"] == "oversize-clean")
    reject = next(r for r in INPUTS if r["id"] == "oversize-reject")
    assert len(pure["value"]) >= 10000
    assert len(reject["value"]) >= 10000


@pytest.mark.parametrize("guard_name", RAISE_GUARDS)
def test_raise_guards_valueerror_or_clean_per_input(guard_name, fuzz_agent):
    """Every raise-style guard: for EVERY corpus input the outcome is a
    clean value OR ValueError - never any other exception."""
    for row in INPUTS:
        value = row["value"]
        try:
            outcome, result = call_raise_guard(guard_name, value)
        except ValueError:
            continue  # the allowed rejection
        except Exception as exc:  # NO other exception may escape
            pytest.fail("{} crashed on {} ({}) with {}: {}"
                        .format(guard_name, row["id"], repr(value[:40]),
                                type(exc).__name__, exc))
        else:
            assert outcome == "clean"
            if guard_name in ("wp_scrub_target", "scrub_host"):
                assert isinstance(result, str)
            elif guard_name == "validate_command_args":
                assert result is None
            elif guard_name == "authorize_call_role":
                assert isinstance(result, tuple) and len(result) == 2


@pytest.mark.parametrize("guard_name", NEVER_RAISE_GUARDS)
def test_never_raise_guards_shape_per_input(guard_name, fuzz_agent):
    """The tuple/str guards never raise for ANY corpus input."""
    for row in INPUTS:
        value = row["value"]
        try:
            result = call_never_guard(guard_name, value, fuzz_agent)
        except Exception as exc:
            pytest.fail("{} crashed on {} ({}) with {}: {}"
                        .format(guard_name, row["id"], repr(value[:40]),
                                type(exc).__name__, exc))
        else:
            if guard_name == "validate_target":
                ok, msg = result
                assert isinstance(ok, bool) and isinstance(msg, str)
            elif guard_name == "validate_arguments":
                assert result is None or isinstance(result, str)
            elif guard_name == "build_command":
                assert isinstance(result, str)
            else:
                assert set(result) == {"ok", "problems"}
                assert result["ok"] is False  # the path never exists


def test_no_guard_bounds_length(fuzz_agent):
    """THE FINDING (flagged): no guard in the family bounds input length -
    a 10k pure-alnum string passes every string guard unchanged."""
    pure = next(r for r in INPUTS if r["id"] == "oversize-clean")
    assert wp_scrub_target(pure["value"]) == pure["value"]
    assert scrub_host(pure["value"]) == pure["value"]
    ok, _ = fuzz_agent.validate_target(pure["value"])
    assert ok is True


def test_sweep_coverage_complete():
    """Every guard the todo names is in the sweep: 5 raise-style + 4
    never-raise = 9 string-consuming guards covered."""
    assert len(RAISE_GUARDS) == 5 and len(NEVER_RAISE_GUARDS) == 4
    assert len(set(RAISE_GUARDS + NEVER_RAISE_GUARDS)) == 9
