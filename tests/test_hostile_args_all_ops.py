"""KA-020 - hostile-arg property sweep: the 008 hostile corpus swept
across ALL planner ops of the three mixins + the wired planners on the
registry kali chassis. The invariant: only ValueErrors (or clean dicts)
- never other exceptions, EXCEPT the one measured quirk, pinned and
fixed at KA-INT-2: the report-outline's non-dict findings rows are
skipped; the AttributeError regression pin remains.

Secondary pins (measured 2026-10-05): the scrub-gaps (8 of 23 hostile
rows pass wp_scrub_target unchanged: control chars, DEL, zero-width,
bidi, combining, %-format strings, tilde) - a hardening finding; and
authorize_tool's tool_db gate (hostile tool names = the no-entry
ValueError). No network; no execution; pure planners only."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent
from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

REPO = Path(__file__).resolve().parents[1]
INPUTS = json.loads(
    (REPO / "tests/fixtures/guard_corpus/hostile_inputs.json"
     ).read_text(encoding="utf-8"))["inputs"]

BENIGN_TARGET = "lab-host1.lab.example"
OOB_HOST = "oob.lab.example"

# the scrub's measured pass-set (8 rows): the hardening finding
SCRUB_GAP_IDS = {"ctrl-chars", "del-char", "zero-width", "bidi-override",
                 "combining", "format-string", "tilde", "oversize-clean"}
SCRUB_REJECT_IDS = {r["id"] for r in INPUTS} - SCRUB_GAP_IDS
assert len(SCRUB_REJECT_IDS) == 15


def _first_vuln_class(agent):
    data = agent.web_vuln_commands(BENIGN_TARGET, None)
    first = data["classes"][0]
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        return first.get("class") or first.get("name") or next(iter(first))
    return str(first)


@pytest.fixture(scope="module")
def sweep_agent(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka020")
    return KaliAgent(agent_id="ka020-sweep", workspace=str(ws / "ws"),
                     log_dir=str(ws / "logs"))


@pytest.fixture(scope="module")
def safe_fills(sweep_agent):
    return {
        "plan_web_pentest": {"target": BENIGN_TARGET},
        "web_enum_commands": {"target": BENIGN_TARGET},
        "web_pentest_report_outline": {"target": BENIGN_TARGET,
                                       "findings": []},
        "web_recon_commands": {"target": BENIGN_TARGET},
        "web_vuln_commands": {"target": BENIGN_TARGET,
                              "vuln_class": _first_vuln_class(sweep_agent)},
        "plan_redteam": {"scope": BENIGN_TARGET},
        "redteam_countermeasures": {"phase": "recon-osint"},
        "redteam_phase_tools": {"phase": "recon-osint"},
        "redteam_tool_lookup": {"query": "dalfox"},
        "plan_xss_exploit": {"target": BENIGN_TARGET},
        "xss_callback_commands": {"callback": OOB_HOST},
        "xss_tool_lookup": {"query": "dalfox"},
        "verify_soc_findings": {"findings": []},
        "kevstig_fan_out": {"coverage": {"entries": []}},
        "authorize_tool": {"tool_name": "nmap", "role": "operator",
                           "required_level": 1},
    }


SWEEP_OPS = (
    "plan_web_pentest", "web_enum_commands", "web_pentest_report_outline",
    "web_recon_commands", "web_vuln_commands", "plan_redteam",
    "redteam_countermeasures", "redteam_phase_tools", "redteam_tool_lookup",
    "plan_xss_exploit", "xss_callback_commands", "xss_tool_lookup",
    "verify_soc_findings", "kevstig_fan_out", "authorize_tool",
)


@pytest.mark.parametrize("op_name", SWEEP_OPS)
def test_hostile_args_valueerror_or_clean(op_name, sweep_agent, safe_fills):
    """Per-op sweep: every corpus row at EVERY string-param of the op;
    the outcome is clean-dict or ValueError; the one measured quirk
    (report-outline x findings) is the documented AttributeError-allow."""
    fn = getattr(sweep_agent, op_name)
    relevant = dict(safe_fills[op_name])
    for row in INPUTS:
        for param in relevant:
            hostile = dict(relevant)
            hostile[param] = row["value"]
            try:
                result = fn(**hostile)
            except ValueError:
                continue  # legal rejection
            except AttributeError as exc:
                # the findings-quirk is FIXED at KA-INT-2; any
                # AttributeError here is a regression
                pytest.fail("%s AttributeError on %s@%s: %s"
                            % (op_name, param, row["id"], exc))
            except Exception as exc:
                pytest.fail("%s crashed on %s@%s with %s: %s"
                            % (op_name, param, row["id"],
                               type(exc).__name__, exc))
            else:
                if op_name == "authorize_tool":
                    # the rbac house contract: a (bool, reason) tuple
                    ok_flag, reason = result
                    assert isinstance(ok_flag, bool)
                    assert isinstance(reason, str)
                else:
                    assert isinstance(result, dict), (
                        op_name, row["id"], type(result).__name__)


def test_report_outline_findings_rows_dict_guarded(sweep_agent):
    """FIXED at KA-INT-2 (the non-dict rows skip): a hostile string at
    the findings position = a clean report dict; no AttributeError."""
    fn = sweep_agent.web_pentest_report_outline
    for row in INPUTS:
        result = fn(BENIGN_TARGET, findings=row["value"])
        assert isinstance(result, dict)
        assert result["target"] == BENIGN_TARGET
        assert result["findings"] == []  # the string-rows skipped clean


def test_scrub_gaps_documented(sweep_agent):
    """THE HARDENING FINDING (flagged): the pass-set rows survive the
    shared scrub verbatim - null bytes, DEL, zero-width/bidi/combining,
    %-format strings and ~ never trip wp_scrub_target."""
    for row in INPUTS:
        if row["id"] in SCRUB_GAP_IDS:
            # verbatim pass (the gaps: no metachars, no dot-pairs, no ws)
            assert wp_scrub_target(row["value"]) == row["value"], row["id"]
        else:
            # rejected by raise, not by return
            with pytest.raises(ValueError):
                wp_scrub_target(row["value"])


def test_authorize_tool_gates(sweep_agent):
    """The db-gate: hostile tool names = the no-entry ValueError; a safe
    name with a hostile role = the unknown-role ValueError; both stay
    inside the invariant."""
    from agentic_ai.agents.cyber.engagement_rbac import authorize_call

    for row in INPUTS:
        with pytest.raises(ValueError):
            sweep_agent.authorize_tool(row["value"], "operator")
        with pytest.raises(ValueError):
            sweep_agent.authorize_tool("nmap", row["value"], required_level=1)
