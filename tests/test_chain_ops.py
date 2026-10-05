"""KA-046 tests - ContractAnalysisMixin: the testnet-only gate (the net
vocabulary, the refusals, the address heuristics, the host-gate consult),
the analyzer/flow catalog (shape + counts + leak scan), the finding
taxonomy with its pairing cross-refs, the 7-phase audit arc, the sweep
runsheet, and the triage. No network, no execution."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import agentic_ai.agents.cyber.chain_ops as chain_ops
from agentic_ai.agents.cyber.chain_ops import ContractAnalysisMixin
from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

# ---- pinned constants (the drift alarms) -------------------------------
TESTNET_COUNT = 22
MAINNET_COUNT = 15
ANALYZER_ROW_TOTAL = 17
CLASS_ROW_TOTALS = {"property-fuzzing": 3, "repo-audit-flow": 4,
                    "static-analyzer": 8, "symbolic-execution": 2}
FINDING_TOTAL = 18
PHASE_IDS = ["1-scope", "2-inventory", "3-static-sweep",
             "4-symbolic-invariant", "5-manual-review", "6-report",
             "7-retest"]
STANDARD_SWEEP = ["slither", "solhint", "mythril"]
DEEP_SWEEP = ["slither", "solhint", "mythril", "semgrep-contracts",
              "aderyn", "woke", "manticore"]
POLICY_PIN = {"testnet_only": True, "no_live_rpc": True,
              "planning_only": True, "no_exploit_payloads": True}

ADDR = "0x" + "ab" * 20
SOURCE = "contracts/Token.sol"


# ---- policy + vocabulary ------------------------------------------------
def test_contract_policy_rows():
    assert ContractAnalysisMixin().contract_policy() == POLICY_PIN


def test_contract_nets_exact_vocab():
    nets = ContractAnalysisMixin().contract_nets()
    assert nets["allowed"] == [
        "anvil", "arbitrum-sepolia", "base-sepolia", "bnb-testnet",
        "cosmos-testnet", "dev", "devnet", "fuji", "ganache", "goerli",
        "hardhat", "holesky", "lab", "local-fork", "mock",
        "optimism-sepolia", "polygon-amoy", "polygon-mumbai", "sepolia",
        "solana-devnet", "solana-testnet", "testnet"]
    assert nets["refused"] == [
        "arbitrum-one", "base-mainnet", "bnb-mainnet", "eth", "ethereum",
        "homestead", "live", "livenet", "main", "mainnet",
        "optimism-mainnet", "polygon-mainnet", "prod", "production",
        "solana-mainnet"]
    assert nets["policy"] == POLICY_PIN
    assert not set(nets["allowed"]) & set(nets["refused"])
    assert len(nets["allowed"]) == TESTNET_COUNT
    assert len(nets["refused"]) == MAINNET_COUNT


# ---- the testnet-only gate ------------------------------------------------
@pytest.mark.parametrize("net", ["sepolia", "fuji", "HOLESKY",
                                 "local-fork", "testnet", "Sepolia"])
def test_gate_allows_testnet_labels(net):
    out = ContractAnalysisMixin().testnet_gate(net=net)
    assert out["allowed"] is True
    assert out["net"] == net.strip().lower()
    assert out["address"] is None
    assert out["policy"] == POLICY_PIN


@pytest.mark.parametrize("net", [None, "", "   ", "Mainnet", "ethereum",
                                 "ETH", "prod", "livenet", "homestead",
                                 "mainnet2"])
def test_gate_refuses_missing_mainnet_and_unknown_labels(net):
    with pytest.raises(ValueError):
        ContractAnalysisMixin().testnet_gate(net=net)


def test_gate_error_messages_name_the_policy():
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate()
    assert "testnet-only policy" in str(err.value)
    assert "explicit" in str(err.value)
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate(net="ethereum")
    assert "refused" in str(err.value)
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate(net="mainnet2")
    assert "accepts:" in str(err.value)


def test_gate_address_shape():
    out = ContractAnalysisMixin().testnet_gate(net="sepolia",
                                               address=ADDR)
    assert out == {"policy": POLICY_PIN, "net": "sepolia",
                   "address": ADDR, "target_kind": "address",
                   "annotated": False, "allowed": True}


def test_gate_normalizes_address_to_lowercase():
    out = ContractAnalysisMixin().testnet_gate(net="sepolia",
                                               address=ADDR.upper())
    assert out["address"] == ADDR.lower()


@pytest.mark.parametrize("bad", ["0x1234", "0x" + "ab" * 19,
                                 "0x" + "ab" * 20 + "a",
                                 "0x" + "z" * 40])
def test_gate_refuses_malformed_evm_addresses(bad):
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate(net="sepolia", address=bad)
    assert "40-hex" in str(err.value)


def test_gate_refuses_mainnet_annotation_even_with_testnet_net():
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate(net="sepolia",
                                             address=ADDR + "@mainnet")
    assert "mainnet" in str(err.value)


def test_gate_refuses_network_mismatch():
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().testnet_gate(net="sepolia",
                                             address=ADDR + "@fuji")
    assert "mismatch" in str(err.value)


def test_gate_accepts_matching_testnet_annotation():
    out = ContractAnalysisMixin().testnet_gate(net="fuji",
                                               address=ADDR + "@fuji")
    assert out["allowed"] is True
    assert out["annotated"] is True
    assert out["address"] == ADDR


def test_gate_refuses_mainnet_hint_words_in_any_target():
    mixin = ContractAnalysisMixin()
    with pytest.raises(ValueError):
        mixin.testnet_gate(net="sepolia", address=ADDR + "-mainnet-copy")
    with pytest.raises(ValueError):
        mixin.testnet_gate(net="sepolia", address="docs/livenet-notes")


def test_gate_refuses_malformed_annotations():
    mixin = ContractAnalysisMixin()
    with pytest.raises(ValueError):
        mixin.testnet_gate(net="sepolia", address=ADDR + "@fuji@sepolia")
    with pytest.raises(ValueError):
        mixin.testnet_gate(net="sepolia", address="@sepolia")
    # annotated with a different testnet = mismatch, refused too
    with pytest.raises(ValueError):
        mixin.testnet_gate(net="sepolia", address=SOURCE + "@fuji")


class _GatedMixin(ContractAnalysisMixin):
    """Host-agent stand-in: supplies validate_target like the chassis."""

    def __init__(self, verdict):
        self._verdict = verdict

    def validate_target(self, target):
        return self._verdict


def test_plan_consults_host_agent_gate():
    # the chassis stand-in supplies validate_target like the real host
    plan = _GatedMixin((True, "")).plan_contract_audit(SOURCE, "sepolia")
    assert plan["target"] == SOURCE
    with pytest.raises(ValueError) as err:
        _GatedMixin((False, "out of scope")).plan_contract_audit(
            SOURCE, "sepolia")
    assert "host agent gate" in str(err.value)


def test_mixin_without_host_gate_falls_back_silently():
    # ContractAnalysisMixin itself carries no validate_target: the
    # getattr fallback must be silent and the plan must proceed.
    plan = ContractAnalysisMixin().plan_contract_audit(SOURCE, "sepolia")
    assert plan["target"] == SOURCE


# ---- the 7-phase audit arc ------------------------------------------------
def test_plan_contract_audit_standard_shape():
    plan = ContractAnalysisMixin().plan_contract_audit(SOURCE, "sepolia")
    assert plan["depth"] == "standard"
    assert plan["policy"] == POLICY_PIN
    assert plan["target_kind"] == "source"
    assert plan["suggested_sweep"] == STANDARD_SWEEP
    assert [p["phase"] for p in plan["phases"]] == PHASE_IDS
    for phase in plan["phases"]:
        assert phase["policy"] == POLICY_PIN
        blob = str(phase["activities"]) + str(phase["sample_commands"])
        assert "{target}" not in blob and "{net}" not in blob \
            and "{depth}" not in blob


def test_plan_contract_audit_renders_target_and_net():
    plan = ContractAnalysisMixin().plan_contract_audit(ADDR + "@fuji",
                                                       "fuji")
    assert plan["target"] == ADDR
    assert plan["net"] == "fuji"
    assert plan["annotated"] is True
    assert plan["target_kind"] == "address"
    boundary = plan["phases"][0]["sample_commands"][0]
    assert boundary == "# boundary: net=fuji is the only network this " \
        "plan touches"
    assert "slither 0xabab" in plan["phases"][2]["sample_commands"][1]


def test_plan_contract_audit_deep_widens_the_sweep():
    plan = ContractAnalysisMixin().plan_contract_audit(SOURCE, "sepolia",
                                                       depth="deep")
    assert plan["suggested_sweep"] == DEEP_SWEEP
    assert len(plan["suggested_sweep"]) > len(STANDARD_SWEEP)
    assert set(STANDARD_SWEEP) <= set(DEEP_SWEEP)


def test_plan_depth_is_pinned():
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().plan_contract_audit(SOURCE, "sepolia",
                                                    depth="live")
    assert "known: standard, deep" in str(err.value)


@pytest.mark.parametrize("net", [None, "", "mainnet", "ethereum", "ETH",
                                 "live", "production", "main", "homestead",
                                 "solana-mainnet"])
def test_plan_refuses_mainnet_and_missing_nets(net):
    mixin = ContractAnalysisMixin()
    with pytest.raises(ValueError):
        mixin.plan_contract_audit("contracts/plan.md", net)


@pytest.mark.parametrize("bad_target", ["", "a b", "f; touch x", "f|ls",
                                        "f&ls", "`x`", "$(x)", "a\nb",
                                        "..x", "f'x"])
def test_plan_scrubs_hostile_targets(bad_target):
    with pytest.raises(ValueError):
        ContractAnalysisMixin().plan_contract_audit(bad_target, "sepolia")


# ---- analyzer catalog -----------------------------------------------------
REQUIRED_ROW_KEYS = {"id", "class", "scope", "lab_fork", "purpose",
                     "detects", "template"}


def test_analyzer_catalog_shape():
    cat = ContractAnalysisMixin().analyzer_catalog()
    assert cat["classes"] == ["property-fuzzing", "repo-audit-flow",
                              "static-analyzer", "symbolic-execution"]
    assert len(cat["rows"]) == ANALYZER_ROW_TOTAL
    ids = [r["id"] for r in cat["rows"]]
    assert len(set(ids)) == len(ids)
    for row in cat["rows"]:
        assert REQUIRED_ROW_KEYS <= set(row), row["id"]
        assert row["class"] in cat["classes"]
        assert row["scope"] in ("evm", "non-evm", "all")
        assert row["lab_fork"] is False or row["lab_fork"] is True
        assert row["template"] is None or (
            isinstance(row["template"], str) and row["template"])
        assert isinstance(row["detects"], list)
        assert isinstance(row["purpose"], str) and row["purpose"]


def test_analyzer_catalog_filtered_by_class():
    mixin = ContractAnalysisMixin()
    for cls, expected_n in CLASS_ROW_TOTALS.items():
        cat = mixin.analyzer_catalog(cls)
        assert cat["class"] == cls
        assert len(cat["rows"]) == expected_n, cls
        assert {row["class"] for row in cat["rows"]} == {cls}
    counts = {c: len(mixin.analyzer_catalog(c)["rows"])
              for c in sorted(CLASS_ROW_TOTALS)}
    assert counts == CLASS_ROW_TOTALS
    assert sum(CLASS_ROW_TOTALS.values()) == ANALYZER_ROW_TOTAL


def test_analyzer_catalog_unknown_class_refused():
    with pytest.raises(ValueError) as err:
        ContractAnalysisMixin().analyzer_catalog("payload-gen")
    assert "known: " in str(err.value)


def test_fuzzing_rows_require_the_lab_fork():
    rows = ContractAnalysisMixin().analyzer_catalog()["rows"]
    by_id = {r["id"]: r for r in rows}
    for fuzz in ("echidna", "medusa", "foundry-invariant"):
        assert by_id[fuzz]["class"] == "property-fuzzing"
        assert by_id[fuzz]["lab_fork"] is True
    statics = [r for r in rows if r["class"] == "static-analyzer"]
    assert all(r["lab_fork"] is False for r in statics)


def test_analyzer_lookup_found_and_miss():
    mixin = ContractAnalysisMixin()
    hit = mixin.analyzer_lookup("slither")
    assert hit["found"] is True and hit["row"]["id"] == "slither"
    assert hit["row"]["class"] == "static-analyzer"
    ci = mixin.analyzer_lookup("SLITHER")
    assert ci["found"] is True and ci["tool"] == "slither"
    miss = mixin.analyzer_lookup("not-a-tool")
    assert miss == {"tool": "not-a-tool", "row": None, "found": False}


@pytest.mark.parametrize("bad", ["", "a b", "x;y", "t@x", "t" * 65, 5,
                                 None])
def test_analyzer_lookup_refuses_malformed_ids(bad):
    with pytest.raises(ValueError):
        ContractAnalysisMixin().analyzer_lookup(bad)


# ---- finding taxonomy -----------------------------------------------------
def test_finding_class_catalog_shape_and_counts():
    cat = ContractAnalysisMixin().finding_class_catalog()
    assert len(cat["rows"]) == FINDING_TOTAL
    assert {r["class"] for r in cat["rows"]} == {"access", "econ", "logic",
                                                "platform"}
    ids = [r["finding"] for r in cat["rows"]]
    assert len(set(ids)) == len(ids)
    for row in cat["rows"]:
        assert set(row) == {"finding", "class", "pairs", "review"}
        assert isinstance(row["review"], str) and row["review"]


def test_finding_pairing_crossrefs_both_ways():
    # the taxonomy's pairs and every analyzer row's detects must point
    # only at real ids in the OTHER catalog (the pairing is checked).
    analyzer_ids = {r["id"] for r in chain_ops.ANALYZERS}
    finding_ids = {r["finding"] for r in chain_ops.FINDINGS}
    for row in chain_ops.ANALYZERS:
        assert set(row["detects"]) <= finding_ids, row["id"]
    for row in chain_ops.FINDINGS:
        assert set(row["pairs"]) <= analyzer_ids, row["finding"]


def test_finding_pairing_example_rows():
    cat = ContractAnalysisMixin().finding_class_catalog()
    by_id = {r["finding"]: r for r in cat["rows"]}
    reentry = by_id["reentrancy-eth"]
    assert reentry["class"] == "logic"
    assert "slither" in reentry["pairs"]
    access = by_id["access-control"]
    assert "access-control-map" in access["pairs"]
    invariant = by_id["broken-invariant"]
    assert {"echidna", "medusa", "foundry-invariant"} == set(
        invariant["pairs"])


# ---- analyzer sweep runsheet ----------------------------------------------
def test_sweep_default_is_the_standard_set():
    plan = ContractAnalysisMixin().plan_analyzer_sweep(ADDR, "sepolia")
    assert [s["tool"] for s in plan["steps"]] == STANDARD_SWEEP
    assert plan["policy"] == POLICY_PIN
    slither = plan["steps"][0]
    assert slither["template"].startswith("slither " + ADDR)
    assert "{target}" not in slither["template"]


def test_sweep_preserves_request_order_and_lab_fork_flags():
    plan = ContractAnalysisMixin().plan_analyzer_sweep(
        SOURCE, "sepolia", tools=["slither", "echidna"])
    steps = plan["steps"]
    assert [s["tool"] for s in steps] == ["slither", "echidna"]
    assert steps[0]["requires_lab_fork"] is False
    assert steps[1]["requires_lab_fork"] is True
    assert "<lab-fuzz-config>" in steps[1]["template"]
    assert "{target}" not in str(steps)


def test_sweep_toolless_rows_carry_a_setup_note():
    plan = ContractAnalysisMixin().plan_analyzer_sweep(
        SOURCE, "sepolia", tools=["medusa"])
    step = plan["steps"][0]
    assert step["template"] is None
    assert "lab setup" in step["note"]


def test_sweep_refuses_unknown_and_empty_tool_lists():
    mixin = ContractAnalysisMixin()
    with pytest.raises(ValueError) as err:
        mixin.plan_analyzer_sweep(ADDR, "sepolia", tools=["nope"])
    assert "slither" in str(err.value)
    with pytest.raises(ValueError):
        mixin.plan_analyzer_sweep(ADDR, "sepolia", tools=[])


# ---- finding triage ------------------------
def test_triage_maps_known_and_uncategorized_labels():
    out = ContractAnalysisMixin().plan_finding_triage(
        ["reentrancy-eth", "never-heard-of"])
    assert out["categorized"] == 1
    first, second = out["rows"]
    assert first == {"label": "reentrancy-eth", "known": True,
                     "class": "logic",
                     "pairs": ["slither", "mythril"],
                     "review": first["review"]}
    assert "slither" in first["pairs"]
    assert second == {"label": "never-heard-of", "known": False,
                      "class": "uncategorized", "pairs": [],
                      "review": second["review"]}
    assert "manual review" in second["review"]


def test_triage_is_case_insensitive():
    out = ContractAnalysisMixin().plan_finding_triage(["REENTRANCY-ETH"])
    assert out["rows"][0]["label"] == "reentrancy-eth"
    assert out["rows"][0]["known"] is True


def test_triage_refuses_bare_string_and_hostile_labels():
    mixin = ContractAnalysisMixin()
    with pytest.raises(ValueError):
        mixin.plan_finding_triage("reentrancy-eth")
    with pytest.raises(ValueError):
        mixin.plan_finding_triage(["reentrancy-eth; drop"])
    with pytest.raises(ValueError):
        mixin.plan_finding_triage(["reentrancy eth"])


# ---- catalog leak + purity scans ------------------------------------------
def test_catalog_rows_carry_no_payload_or_address_leak():
    mixin = ContractAnalysisMixin()
    blob = str(mixin.analyzer_catalog()) \
        + str(mixin.finding_class_catalog()) \
        + str(mixin.contract_nets())
    for banned in ("selfdestruct(", "delegatecall(", "keccak256(",
                   "sstore(", "calldatacopy(", "private_key", "privkey",
                   "mnemonic", "shellcode"):
        assert banned not in blob, banned
    assert not re.findall(r"0x[0-9a-fA-F]{40}", blob), "no address leak"


def test_module_never_executes():
    source = Path(chain_ops.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned


def test_module_counts_match_the_pins():
    # the named constants are the drift alarm: recompute + re-pin here
    assert chain_ops.ANALYZER_ROW_TOTAL == len(chain_ops.ANALYZERS) == \
        ANALYZER_ROW_TOTAL
    assert chain_ops.FINDING_CLASS_TOTAL == len(chain_ops.FINDINGS) == \
        FINDING_TOTAL
    counts = {}
    for row in chain_ops.ANALYZERS:
        counts[row["class"]] = counts.get(row["class"], 0) + 1
    assert counts == CLASS_ROW_TOTALS
    assert len(chain_ops.TESTNET_NETS) == TESTNET_COUNT
    assert len(chain_ops.MAINNET_NETS) == MAINNET_COUNT
    assert chain_ops.STANDARD_SWEEP == tuple(STANDARD_SWEEP)
    assert chain_ops.DEEP_SWEEP == tuple(DEEP_SWEEP)
    assert [p[0] for p in chain_ops.AUDIT_PHASES] == PHASE_IDS
    # the scrub helper stays the ONE shared input gate
    with pytest.raises(ValueError):
        wp_scrub_target("0x0; drop")