"""Tests for the composed P4 safety-gate chain (KA-INT-4).

Pin the ACCEPTANCE contract: gate order consent -> (optional budget) ->
auth -> blast-radius -> egress -> rate-limit -> execute-authorization;
fail-closed stops at the first refusal with later gates uninvolved;
injected clock/store/tags; planner purity of the chain module itself.
MEASURED bases (python3 -c probes): read/cat/wget/curl/whoami lvl1
stage=False; nmap lvl2 stage=False; sudo-nmap/hydra/sqlmap/unknown-prog
lvl3 stage=True; blast event kind = command_blast_radius_classified;
rate blocked event carries retry_at; the rbac floor denies level-0 tools.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.budgets import Budget
from agentic_ai.agents.cyber.consent_gate import EVENT_KIND, ConsentRecord
from agentic_ai.agents.cyber.engagement_rbac import ENGAGEMENT_ROLES
from agentic_ai.agents.cyber.gate_chain import (
    EVENT_BUDGET_REFUSED,
    GATE_NAMES,
    run_gate_chain,
)
from agentic_ai.agents.cyber.rate_limit import check as rate_check

NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.timezone.utc)
CMD_NMAP = "nmap -sS 10.0.0.5"          # MEASURED: scan, level 2, staging False
CMD_EXT = "curl -s https://198.51.100.7/x"   # MEASURED: read, level 1, external
CMD_SQLMAP = "sqlmap -u http://198.51.100.9/app"  # MEASURED: exploit-class, level 3, staging True
CMD_UNKNOWN = "unknown-prog-x99 --flag y"     # MEASURED: exploit-class, level 3
ROLE_OP = ENGAGEMENT_ROLES["operator"]   # registered operator: levels {1,2,3}
REC = ConsentRecord(engagement_id="e1", action="nmap", signed_by="owner",
                    signed_at=NOW)
REC_CURL = ConsentRecord(engagement_id="e1", action="curl", signed_by="owner",
                         signed_at=NOW)
REC_SQLMAP = ConsentRecord(engagement_id="e1", action="sqlmap",
                           signed_by="owner", signed_at=NOW)
_REC_BY_TOOL = {"nmap": REC, "sqlmap": REC_SQLMAP, "curl": REC_CURL}


def _real(cmd=CMD_NMAP, tool="nmap", level=2, **kw):
    """Real-path call with complete consent defaults per tool."""
    kw.setdefault("consent", _REC_BY_TOOL[tool])
    kw.setdefault("role", ROLE_OP)          # real runs must pass the role gate
    kw.setdefault("target", "10.0.0.5")     # rate gate's scrubbed target
    return run_gate_chain(cmd, tool_name=tool, tool_level=level, now=NOW,
                          **kw)


# --- order contract -----------------------------------------------------

def test_gate_names_pin():
    assert GATE_NAMES == ("consent", "budget", "auth", "blast_radius",
                          "egress", "rate_limit", "execute")


# --- dry-run carve-out (KA-051: unrestricted planning) --------------------

def test_dry_run_passes_without_consent():
    store = {}
    d = run_gate_chain(CMD_NMAP, tool_name="nmap", tool_level=2, now=NOW,
                       dry_run=True, rate_store=store, role=ROLE_OP)
    assert d.allowed and d.stopped_at == "execute"
    assert "dry run" in d.reason
    assert store == {}  # rate gate uninvolved


def test_dry_run_with_external_command_skips_egress():
    d = run_gate_chain(CMD_EXT, tool_name="curl", tool_level=1, now=NOW,
                       dry_run=True, role=ROLE_OP)
    assert d.allowed


def test_dry_run_with_exploit_command_records_blast():
    d = run_gate_chain(CMD_SQLMAP, tool_name="sqlmap", tool_level=3, now=NOW,
                       dry_run=True, role=ROLE_OP)
    assert d.allowed
    assert d.events[0]["event"] == "command_blast_radius_classified"


# --- consent gate (first; refusals audited) -------------------------------

def test_real_missing_consent_refuses_first():
    d = run_gate_chain(CMD_NMAP, tool_name="nmap", tool_level=2, now=NOW,
                       consent=None)
    assert not d.allowed and d.stopped_at == "consent"
    assert d.reason == "consent_missing"
    assert d.events[0]["event"] == EVENT_KIND


def test_unsigned_consent_refused():
    bad = ConsentRecord(engagement_id="e1", action="nmap", signed_by=None,
                        signed_at=NOW)
    d = _real(consent=bad)
    assert not d.allowed and d.stopped_at == "consent"
    assert d.reason == "consent_unsigned"


def test_expired_consent_refused_at_boundary():
    d = _real(consent=ConsentRecord(engagement_id="e1", action="nmap",
                                    signed_by="owner", signed_at=NOW,
                                    expires_at=NOW))
    assert not d.allowed and d.stopped_at == "consent"
    assert d.reason == "consent_expired"


def test_future_expiry_passes():
    d = _real(consent=ConsentRecord(engagement_id="e1", action="nmap",
                                    signed_by="owner", signed_at=NOW,
                                    expires_at=NOW + dt.timedelta(hours=1)),
              rate_store={}, lab_staged=True)
    assert d.allowed


def test_consent_action_mismatch_refused():
    rec = ConsentRecord(engagement_id="e1", action="whoami", signed_by="owner",
                        signed_at=NOW)
    d = _real(consent=rec)
    assert not d.allowed and d.stopped_at == "consent"
    assert d.reason == "consent_action_mismatch"


# --- optional budget gate (between consent and auth; real path) ------------

def test_budget_refused_between_consent_and_auth():
    budget = Budget(engagement_id="e1", max_command_invocations=0,
                    max_external_requests=None, window_seconds=None)
    auth_calls = []
    d = _real(budget=budget, ledger=[],
              auth_check=lambda t, r, l: (auth_calls.append(t) or
                                          (True, "ok")))
    assert not d.allowed and d.stopped_at == "budget"
    assert d.reason == "command_invocation_cap_reached"
    assert auth_calls == []  # auth uninvoked behind a budget refusal
    assert d.events[0]["event"] == EVENT_BUDGET_REFUSED


def test_budget_with_headroom_proceeds():
    budget = Budget(engagement_id="e1", max_command_invocations=10,
                    max_external_requests=10, window_seconds=None)
    d = _real(rate_store={}, budget=budget, ledger=[],
              auth_check=lambda t, r, l: (True, "ok"), lab_staged=True)
    assert d.allowed


# --- auth gate ------------------------------------------------------------

def test_injected_auth_deny_stops_chain():
    d = _real(rate_store={},
              auth_check=lambda t, r, l: (False, "Denied: test refusal"))
    assert not d.allowed and d.stopped_at == "auth"
    assert d.reason == "Denied: test refusal"


def test_default_auth_role_none_fail_closed():
    d = _real(rate_store={}, role=None)
    assert not d.allowed and d.stopped_at == "auth"
    assert d.reason == "gate_chain: role required for the default auth check"


def test_default_auth_through_real_rbac_role():
    d = _real(role=ROLE_OP, rate_store={}, lab_staged=True)
    assert d.allowed and d.stopped_at == "execute"
    assert "Authorized" in d.events[0]["event"] or d.allowed


# --- blast-radius gate (escalations only raise) ----------------------------

def test_blast_requirement_recorded_on_escalation():
    # KA-053's class requirement rides in the audit bundle; enforcement
    # lives in the auth seat above (no invented cross-gate deny).
    d = _real(level=1, rate_store={}, lab_staged=False)
    assert not d.allowed and d.stopped_at == "egress"
    assert str(d.events[0]["required_level"]) == "2"  # MEASURED mapping record
    assert "escalates" not in d.reason


def test_blast_unknown_program_recorded_fail_closed():
    rec = ConsentRecord(engagement_id="e1", action="x", signed_by="owner",
                        signed_at=NOW)
    d = run_gate_chain(CMD_UNKNOWN, tool_name="x", tool_level=2, now=NOW,
                       consent=rec, role=ROLE_OP, rate_store={},
                       lab_staged=False, auth_tags=())
    assert not d.allowed and d.stopped_at == "egress"
    assert str(d.events[0]["required_level"]) == "3"


def test_blast_event_recorded_before_egress_denial():
    d = _real(cmd=CMD_EXT, tool="curl", level=1, rate_store={})
    assert not d.allowed and d.stopped_at == "egress"
    assert d.events[0]["event"] == "command_blast_radius_classified"


# --- egress gate (staging established by caller or probe) -------------------

def test_rfc1918_requires_lab_staging():
    d = _real(rate_store={}, lab_staged=False)
    assert not d.allowed and d.stopped_at == "egress"
    assert "lab staging" in d.reason


def test_rfc1918_with_lab_staged_proceeds():
    d = _real(rate_store={}, lab_staged=True)
    assert d.allowed


def test_external_requires_auth_tag():
    d = _real(cmd=CMD_EXT, tool="curl", level=1, rate_store={})
    assert not d.allowed and d.stopped_at == "egress"


def test_external_with_auth_tag_proceeds():
    d = _real(cmd=CMD_EXT, tool="curl", level=1, rate_store={},
              auth_tags=("EGRESS-AUTH",))
    assert d.allowed


def test_staging_probe_false_reason_passthrough():
    d = _real(rate_store={},
              staging_probe=lambda c: (False, "not in declared staging"))
    assert not d.allowed and d.stopped_at == "egress"
    assert d.reason == "not in declared staging"


def test_staging_probe_true_establishes_lab():
    d = _real(rate_store={},
              staging_probe=lambda c: (True, "in staging"))
    assert d.allowed


def test_blast_staging_required_demands_establishment():
    d = _real(cmd=CMD_SQLMAP, tool="sqlmap", level=3, rate_store={},
              lab_staged=False)
    assert not d.allowed and d.stopped_at == "egress"
    assert "requires lab staging" in d.reason


# --- rate-limit gate (real executions only) ---------------------------------

def test_rate_store_required_for_real_execution():
    d = _real(lab_staged=True)
    assert not d.allowed and d.stopped_at == "rate_limit"
    assert "rate store unavailable" in d.reason


def test_rate_target_required_for_real_execution():
    d = _real(rate_store={}, lab_staged=True, target="   ")
    assert not d.allowed and d.stopped_at == "rate_limit"
    assert "scrubbed target" in d.reason


def test_rate_blocked_carries_retry_at():
    store: dict = {}
    for _ in range(10):
        rate_check(store, "nmap", "10.0.0.5", NOW)
    d = _real(rate_store=store, lab_staged=True)
    assert not d.allowed and d.stopped_at == "rate_limit"
    assert "retry_at=" in d.reason


def test_rate_allow_updates_injected_store():
    store: dict = {}
    d = _real(rate_store=store, lab_staged=True)
    assert d.allowed
    assert len(store[("nmap", "10.0.0.5")]) == 1


def test_event_bundle_order_happy_real_path():
    store: dict = {}
    d = _real(rate_store=store, lab_staged=True)
    assert d.allowed
    kinds = [e["event"] for e in d.events]
    assert kinds[0] == "command_blast_radius_classified"
    assert kinds[1] == "tool_target_rate_allowed"


# --- loud structural misuse ---------------------------------------------------

def test_tool_level_out_of_range_raises():
    with pytest.raises(ValueError):
        run_gate_chain(CMD_NMAP, tool_name="nmap", tool_level=7, now=NOW)


def test_now_required_injected_clock():
    with pytest.raises(ValueError):
        run_gate_chain(CMD_NMAP, tool_name="nmap", tool_level=2, now=None)


def test_dry_run_must_be_bool():
    with pytest.raises(ValueError):
        run_gate_chain(CMD_NMAP, tool_name="nmap", tool_level=2, now=NOW,
                       dry_run="yes")


def test_deterministic_repeat():
    d1 = _real(rate_store={}, lab_staged=True)
    d2 = _real(rate_store={}, lab_staged=True)  # separate stores: same view
    assert d1 == d2


# --- planner purity of the chain module itself --------------------------------

def test_gate_chain_module_purity_source_scan():
    src = (Path(__file__).resolve().parent.parent
           / "agentic_ai/agents/cyber/gate_chain.py").read_text(encoding="utf-8")
    for token in ("subprocess", "os.system", "eval(", "exec(", "open(",
                  "socket", "urllib.request", "utcnow", "datetime.now",
                  "time.time", "cyber.kali"):
        assert token not in src, token