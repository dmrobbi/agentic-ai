"""ContractAnalysisMixin (KA-046): smart-contract audit PLANNING ops
(no execution; testnet-only policy).

Adds contract-analysis planning to the kali agents. The ops never
execute and never touch a live chain: the catalog
is a curated INDEX of open-source analyzer tooling + repo-audit flows
(chain-agnostic, methodology-only), and every plan is a runsheet the
operator runs inside the lab under the host agent's normal gates.

Testnet-only policy (hard gate, enforced by the shared target resolver):
- every planned call needs an explicit lab/testnet net label
  (e.g. net='sepolia'); a missing/unknown label refuses;
- every mainnet-family label refuses by NAME (not heuristic luck);
- a target string carrying a mainnet hint/annotation refuses even when
  the net label is a testnet;
- '0x'-shaped targets must be exact 40-hex EVM addresses; anything else
  that starts '0x' refuses;
- ambiguous/malformed annotations and net mismatches refuse.

Sourcing: analyzer names (slither, mythril, ...) are referenced by
NAME only; the finding taxonomy + flow steps are re-authored in-house
methodology - no external prose, no payload strings, no exploit code.
No data file is used this task: the catalog lives as module constants.

Ops:
- contract_policy() - the policy rows
- contract_nets() - the allowed testnet labels vs the refused mainnet ones
- testnet_gate(net=None, address=None) - validate a lab designation +
  optional target through the SAME heuristics the plans use
- analyzer_catalog(cls=None) - the static-analyzer/flow INDEX; cls
  filters; unknown classes refuse
- analyzer_lookup(tool_id) - one catalog row by id; a miss = found:False
- finding_class_catalog() - the finding taxonomy with catalog pairing
- plan_contract_audit(target, net, depth='standard') - the 7-phase lab
  audit arc (depth=deep widens the suggested analyzer set)
- plan_analyzer_sweep(target, net, tools=None) - ordered per-tool
  runsheet; unknown ids refuse; fuzz rows flag the lab-fork requirement
- plan_finding_triage(labels) - map raw finding ids onto the taxonomy
"""

from __future__ import annotations

import re

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

POLICY = {"testnet_only": True, "no_live_rpc": True,
          "planning_only": True, "no_exploit_payloads": True}

# ---- network vocabulary ------------------------------------------------
# exact labels only: the policy refuses by name, not by guesswork.
TESTNET_NETS = {
    "testnet": "generic lab/testnet designation",
    "lab": "the owner's lab bench",
    "mock": "fully mocked lab chain",
    "dev": "lab development chain",
    "devnet": "lab development chain",
    "local-fork": "a local lab fork of a public chain (no live RPC)",
    "anvil": "anvil dev chain",
    "hardhat": "hardhat network",
    "ganache": "ganache lab chain",
    "sepolia": "ethereum testnet",
    "holesky": "ethereum testnet",
    "goerli": "legacy ethereum testnet (existing lab artifacts only)",
    "base-sepolia": "base L2 testnet",
    "arbitrum-sepolia": "arbitrum L2 testnet",
    "optimism-sepolia": "optimism L2 testnet",
    "polygon-amoy": "polygon testnet",
    "polygon-mumbai": "legacy polygon testnet (existing lab artifacts only)",
    "fuji": "avalanche testnet",
    "bnb-testnet": "bnb lab/testnet designation",
    "solana-testnet": "solana testnet cluster",
    "solana-devnet": "solana devnet cluster",
    "cosmos-testnet": "cosmos-sdk lab/testnet designation",
}

MAINNET_NETS = {
    "mainnet", "main", "eth", "ethereum", "homestead", "livenet", "live",
    "prod", "production", "arbitrum-one", "base-mainnet", "bnb-mainnet",
    "optimism-mainnet", "polygon-mainnet", "solana-mainnet",
}

_EVM_ADDR_RE = re.compile(r"0[xX][a-fA-F0-9]{40}$")
_MAINNET_HINT_RE = re.compile(r"mainnet|livenet|homestead", re.IGNORECASE)

# ---- static-analyzer catalog (chain-agnostic; methodology only) ---------
ANALYZER_CLASSES = ("property-fuzzing", "repo-audit-flow",
                    "static-analyzer", "symbolic-execution")

ANALYZERS = (
    {"id": "slither", "class": "static-analyzer", "scope": "evm",
     "lab_fork": False,
     "purpose": "solidity detector framework: call graphs, inheritance, "
                "storage writes",
     "detects": ("reentrancy-eth", "untrusted-external-call",
                 "delegatecall-injection", "uninitialized-storage",
                 "tx-origin", "shadowing"),
     "template": "slither {target} --json -"},
    {"id": "solhint", "class": "static-analyzer", "scope": "evm",
     "lab_fork": False,
     "purpose": "solidity lint: security + style rules over the source tree",
     "detects": ("tx-origin", "gas-griefing", "shadowing"),
     "template": "solhint {target}/contracts/**/*.sol --max-warnings 0"},
    {"id": "semgrep-contracts", "class": "static-analyzer", "scope": "evm",
     "lab_fork": False,
     "purpose": "pattern rules over solidity sources; the lab pins its "
                "ruleset so every run is reproducible",
     "detects": ("untrusted-external-call", "delegatecall-injection",
                 "tx-origin"),
     "template": "semgrep --config {ruleset} {target}"},
    {"id": "aderyn", "class": "static-analyzer", "scope": "evm",
     "lab_fork": False,
     "purpose": "rust static analyzer: detector reports over a solidity "
                "workspace",
     "detects": ("untrusted-external-call", "delegatecall-injection",
                 "uninitialized-storage", "shadowing"),
     "template": "aderyn {target}"},
    {"id": "woke", "class": "static-analyzer", "scope": "evm",
     "lab_fork": False,
     "purpose": "python solidity framework: precise AST/type analysis "
                "behind custom lab checks",
     "detects": ("reentrancy-eth", "arithmetic", "shadowing"),
     "template": None},
    {"id": "move-analyzer", "class": "static-analyzer", "scope": "non-evm",
     "lab_fork": False,
     "purpose": "Move (aptos/sui) source analysis + bytecode verification "
                "hooks",
     "detects": ("arithmetic", "resource-logic"),
     "template": None},
    {"id": "cargo-contract-audit", "class": "static-analyzer",
     "scope": "non-evm", "lab_fork": False,
     "purpose": "rust contract crates (cosmwasm/ink): lint + overflow "
                "checks + schema review",
     "detects": ("arithmetic", "msg-auth", "resource-logic"),
     "template": None},
    {"id": "anchor-idl-review", "class": "static-analyzer",
     "scope": "non-evm", "lab_fork": False,
     "purpose": "solana/anchor program surface review: signer and "
                "authority flows from the IDL",
     "detects": ("msg-auth", "signer-privilege", "access-control"),
     "template": None},
    {"id": "mythril", "class": "symbolic-execution", "scope": "evm",
     "lab_fork": False,
     "purpose": "EVM bytecode symbolic analysis; lab artifacts only, "
                "never a live chain",
     "detects": ("reentrancy-eth", "unchecked-external-call", "arithmetic",
                 "delegatecall-injection"),
     "template": "myth analyze {target}"},
    {"id": "manticore", "class": "symbolic-execution", "scope": "evm",
     "lab_fork": False,
     "purpose": "multi-path symbolic explorer for selected lab bytecode",
     "detects": ("untrusted-external-call", "delegatecall-injection",
                 "broken-invariant"),
     "template": None},
    {"id": "echidna", "class": "property-fuzzing", "scope": "evm",
     "lab_fork": True,
     "purpose": "property-based solidity fuzzer against broken invariants; "
                "needs a local lab fork",
     "detects": ("broken-invariant", "access-control"),
     "template": "echidna {target} --config <lab-fuzz-config>"},
    {"id": "medusa", "class": "property-fuzzing", "scope": "evm",
     "lab_fork": True,
     "purpose": "parallel property fuzzer; replays the lab seed corpus "
                "before new campaigns",
     "detects": ("broken-invariant", "access-control"),
     "template": None},
    {"id": "foundry-invariant", "class": "property-fuzzing", "scope": "evm",
     "lab_fork": True,
     "purpose": "forge invariant suites: stateful handlers over the lab "
                "fork",
     "detects": ("broken-invariant",),
     "template": "forge test --match-contract <invariant-contract>"},
    {"id": "access-control-map", "class": "repo-audit-flow", "scope": "all",
     "lab_fork": False,
     "purpose": "map every privileged entrypoint and its role graph "
                "before tooling",
     "detects": ("access-control", "signer-privilege", "msg-auth"),
     "steps": ("list every public/external state-changing entrypoint",
               "for each: the required role and the check actually "
               "enforced",
               "draw the role graph; flag the single-admin risk",
               "confirm every privileged call is lab-keyed on the "
               "testnet"),
     "template": None},
    {"id": "upgrade-path-review", "class": "repo-audit-flow", "scope": "all",
     "lab_fork": False,
     "purpose": "proxy/upgradeable paths: initializer order, storage "
                "layout, freeze power",
     "detects": ("uninitialized-storage", "delegatecall-injection",
                 "access-control"),
     "steps": ("locate the proxy pattern and its admin slot",
               "diff the storage layout across deployed lab artifacts",
               "review initializer modifiers for re-init paths",
               "doc who can upgrade, when, and how to freeze it"),
     "template": None},
    {"id": "oracle-integration-review", "class": "repo-audit-flow",
     "scope": "all", "lab_fork": False,
     "purpose": "price/oracle inputs: source freshness, deviation bounds, "
                "circuit breakers",
     "detects": ("oracle-trust", "gas-griefing"),
     "steps": ("doc every oracle read and its asset pair",
               "check the staleness and deviation guards",
               "simulate a manipulated round on the lab fork",
               "pair each read with a breaker"),
     "template": None},
    {"id": "dependency-provenance-audit", "class": "repo-audit-flow",
     "scope": "all", "lab_fork": False,
     "purpose": "lockfiles, vendor trees and submodules: versions, "
                "licenses, pinned refs",
     "detects": (),
     "steps": ("inventory manifests, lockfiles and git submodules",
               "pin every dependency to an exact ref",
               "check licenses + maintenance status",
               "keep untrusted registries out of the lab build"),
     "template": None},
)

ANALYZER_ROW_TOTAL = 17
CLASS_ROW_TOTALS = {"property-fuzzing": 3, "repo-audit-flow": 4,
                    "static-analyzer": 8, "symbolic-execution": 2}

# ---- finding taxonomy (pairs reference catalog ids, tools AND flows) ----
FINDINGS = (
    {"finding": "reentrancy-eth", "class": "logic",
     "pairs": ("slither", "mythril"),
     "review": "state effects land after every external call; guards on "
               "value paths"},
    {"finding": "untrusted-external-call", "class": "logic",
     "pairs": ("slither", "semgrep-contracts", "manticore"),
     "review": "the call target and the return handling are user-touched; "
               "wrap + check"},
    {"finding": "delegatecall-injection", "class": "platform",
     "pairs": ("slither", "aderyn", "semgrep-contracts"),
     "review": "the call target must be a lab-pinned constant, never "
               "caller input"},
    {"finding": "uninitialized-storage", "class": "platform",
     "pairs": ("slither", "aderyn"),
     "review": "every storage slot of deployed lab artifacts is claimed "
               "by the layout diff"},
    {"finding": "tx-origin", "class": "access",
     "pairs": ("slither", "solhint"),
     "review": "sender checks use msg.sender, never tx.origin"},
    {"finding": "shadowing", "class": "logic",
     "pairs": ("slither", "solhint", "aderyn", "woke"),
     "review": "shadowed names hide the real state; rename and re-run"},
    {"finding": "gas-griefing", "class": "econ",
     "pairs": ("solhint",),
     "review": "unbounded loops and refund paths grief callers; bound "
               "them on the lab fork"},
    {"finding": "arithmetic", "class": "logic",
     "pairs": ("mythril", "cargo-contract-audit", "move-analyzer"),
     "review": "overflows, truncations and rounding on the money paths; "
               "property-check them"},
    {"finding": "resource-logic", "class": "platform",
     "pairs": ("move-analyzer", "cargo-contract-audit"),
     "review": "resource/ownership rules hold across every abort path"},
    {"finding": "msg-auth", "class": "access",
     "pairs": ("cargo-contract-audit", "anchor-idl-review"),
     "review": "the message signer/authority is checked before any state "
               "mutation"},
    {"finding": "signer-privilege", "class": "access",
     "pairs": ("anchor-idl-review",),
     "review": "privilege escalation via missing signer checks on the "
               "program surface"},
    {"finding": "access-control", "class": "access",
     "pairs": ("echidna", "access-control-map"),
     "review": "every privileged entrypoint maps to a role on the lab "
               "chain, or refuses"},
    {"finding": "broken-invariant", "class": "logic",
     "pairs": ("echidna", "medusa", "foundry-invariant"),
     "review": "the fuzz suite pins the invariant; a violation is a "
               "finding, a green run is not clearance"},
    {"finding": "unchecked-external-call", "class": "logic",
     "pairs": ("manticore",),
     "review": "call/return paths the symbolic explorer reaches without "
               "a check"},
    {"finding": "oracle-trust", "class": "econ",
     "pairs": ("oracle-integration-review",),
     "review": "the oracle source, freshness and deviation bounds hold "
               "under the lab simulation"},
    {"finding": "bridge-trust", "class": "econ",
     "pairs": (),
     "review": "trust-model walkthrough: validators, quorum, who holds "
               "the pause power"},
    {"finding": "front-running", "class": "econ",
     "pairs": (),
     "review": "ordering exposure: sandwich windows and commit-reveal "
               "gaps, tested on the lab fork"},
    {"finding": "signature-replay", "class": "access",
     "pairs": (),
     "review": "nonce, chain-id and domain binding; a lab replay of the "
               "same sig must refuse"},
)

FINDING_CLASS_TOTAL = 18

# ---- planner arcs ------------------------------------------------------
AUDIT_PHASES = (
    ("1-scope", "Fix the lab boundary and the engagement scope",
     ("Confirm the net '{net}' passes testnet_gate; every mainnet form "
      "refuses.",
      "Record the engagement boundary: files, artifact bundle, lab fork "
      "config.",
      "No live RPC anywhere in the plan; every call runs in the lab."),
     ("# boundary: net={net} is the only network this plan touches",
      "# op: testnet_gate(net='{net}')")),
    ("2-inventory", "Inventory the source tree and the lab artifacts",
     ("Capture manifests, lockfiles, submodules, ABI JSON and deploy "
      "records.",
      "Doc the deployed testnet addresses next to their labels.",
      "Hash the inventory; the audit runs on this snapshot only."),
     ("sha256sum <inventory-manifest>",
      "# op: dependency-provenance-audit flow")),
    ("3-static-sweep", "Run the depth's analyzer set over the lab target",
     ("The sweep runshee: order the {depth} set from the catalog.",
      "Every template points at the lab target; nothing points at a "
      "public chain.",
      "Keep every report artifact hashed into the evidence bundle."),
     ("# op: plan_analyzer_sweep(target, net='{net}', tools="
      "<{depth}-set>)",
      "slither {target} --json -")),
    ("4-symbolic-invariant", "Symbolic + invariant pass on the lab fork",
     ("Bytecode symbolic analysis over lab artifacts only.",
      "Run the property/invariant suite (echidna/medusa/foundry rows "
      "require the lab-fork flag).",
      "Seed the fuzzers with the prior corpus before new campaigns."),
     ("# lab-fork required: echidna/medusa/foundry-invariant rows",
      "myth analyze {target}")),
    ("5-manual-review", "Walk the higher-risk classes by hand",
     ("The repo-audit flows first: access-control-map, "
      "upgrade-path-review, oracle-integration-review.",
      "Then the class walks: bridge-trust, front-running, "
      "signature-replay.",
      "Each walk ends in a written claim a test can falsify."),
     ("# op: analyzer_lookup('access-control-map') for the flow steps")),
    ("6-report", "Findings + severity + remediation, SOC-paired",
     ("Triage raw labels through the taxonomy; uncategorized rows go "
      "to manual review honestly.",
      "Severity: the class + exploitability under lab conditions only.",
      "Scrub everything before it leaves the machine."),
     ("# op: plan_finding_triage(<raw-label-list>)")),
    ("7-retest", "Close the loop: fix, re-run, pin the regression",
     ("Re-run the sweep rows that flagged; a closed finding re-tests "
      "green on the lab fork.",
      "Pin the failing case that opened the finding; it becomes the "
      "regression test.",
      "Hand the fix + the test to the defense. The plan itself never "
      "executes."),
     ("# regression: the failing case stays in the lab suite")),
)

DEPTHS = ("standard", "deep")
STANDARD_SWEEP = ("slither", "solhint", "mythril")
DEEP_SWEEP = ("slither", "solhint", "mythril", "semgrep-contracts",
              "aderyn", "woke", "manticore")

_UNCATEGORIZED_REVIEW = ("uncategorized label - send it to manual "
                         "review against the taxonomy before it enters "
                         "any report")

_ANALYZER_BY_ID = {row["id"]: row for row in ANALYZERS}
_FINDING_BY_ID = {row["finding"]: row for row in FINDINGS}
_NET_REQUIRED_MSG = ("testnet-only policy: an explicit lab/testnet net "
                     "label is required (e.g. net='sepolia')")
_KNOWN_NETS_MSG = "testnet-only policy accepts: " + ", ".join(
    sorted(TESTNET_NETS))


def _net_for(net):
    """Resolve the lab/testnet label; refuse missing, mainnet, unknown."""
    if not isinstance(net, str) or not net.strip():
        raise ValueError("%s; %s" % (_NET_REQUIRED_MSG, _KNOWN_NETS_MSG))
    form = net.strip().lower()
    if form in MAINNET_NETS:
        raise ValueError("net %r is a mainnet - refused by the "
                         "testnet-only policy (lab/testnet only)" % (net,))
    if form not in TESTNET_NETS:
        raise ValueError("unknown network %r - %s" % (net, _KNOWN_NETS_MSG))
    return form


class ContractAnalysisMixin:
    """Contract-audit planning ops (no execution; testnet-only policy)."""

    def _chain_target(self, target, net):
        """Resolve (target, net) through the shared scrub + the
        testnet-only heuristics + the host agent's target gate."""
        label = _net_for(net)
        t = wp_scrub_target(target)
        if _MAINNET_HINT_RE.search(t):
            raise ValueError("target %r carries a mainnet hint - refused "
                             "by the testnet-only policy" % (target,))
        base, annotation = t, None
        if "@" in t:
            parts = t.split("@")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise ValueError("malformed target annotation %r - use "
                                 "<target>@<testnet-label>" % (target,))
            base, annotation = parts[0], parts[1].lower()
            if annotation in MAINNET_NETS:
                raise ValueError("target annotation %r names a mainnet - "
                                 "refused by the testnet-only policy"
                                 % (annotation,))
            if annotation not in TESTNET_NETS:
                raise ValueError("unknown target annotation %r - %s"
                                 % (annotation, _KNOWN_NETS_MSG))
            if annotation != label:
                raise ValueError("network mismatch: target annotated %r "
                                 "but net=%r" % (annotation, label))
        kind = "address" if _EVM_ADDR_RE.fullmatch(base) else "source"
        if base[:2].lower() == "0x" and kind != "address":
            raise ValueError("target %r looks like an EVM address but "
                             "fails the exact 40-hex form" % (target,))
        if kind == "address":
            base = base.lower()
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(base)
            if not ok:
                raise ValueError("target rejected by host agent gate: %s"
                                 % (msg,))
        return {"target": base, "net": label, "target_kind": kind,
                "annotated": annotation is not None}

    # ---- policy + vocabulary -------------------------------------------

    def contract_policy(self) -> dict:
        """The hard policy rows behind every planning op."""
        return dict(POLICY)

    def contract_nets(self) -> dict:
        """The exact lab/testnet vocabulary vs the refused mainnet labels."""
        return {"allowed": sorted(TESTNET_NETS),
                "refused": sorted(MAINNET_NETS),
                "target_hints_refused": "any target string carrying a "
                                        "mainnet/livenet/homestead hint "
                                        "refuses",
                "policy": dict(POLICY)}

    def testnet_gate(self, net=None, address=None) -> dict:
        """Validate a lab/testnet designation (+ optional target) through
        the SAME heuristics the plans use; refusals raise ValueError."""
        if address is None:
            return {"policy": dict(POLICY), "net": _net_for(net),
                    "address": None, "target_kind": None, "allowed": True}
        info = self._chain_target(address, net)
        return {"policy": dict(POLICY), "net": info["net"],
                "address": info["target"], "target_kind": info["target_kind"],
                "annotated": info["annotated"], "allowed": True}

    # ---- catalogs -------------------------------------------------------

    @staticmethod
    def _row_view(row):
        view = dict(row)
        view["detects"] = list(row["detects"])
        if "steps" in view:
            view["steps"] = list(row["steps"])
        return view

    def analyzer_catalog(self, cls=None) -> dict:
        """The analyzer/flow INDEX; cls filters; unknown classes refuse."""
        if cls is None:
            return {"policy": dict(POLICY),
                    "classes": sorted(ANALYZER_CLASSES),
                    "rows": [self._row_view(r) for r in ANALYZERS]}
        if cls not in ANALYZER_CLASSES:
            raise ValueError("unknown analyzer class %r - known: %s"
                             % (cls, ", ".join(sorted(ANALYZER_CLASSES))))
        return {"policy": dict(POLICY), "class": cls,
                "rows": [self._row_view(r) for r in ANALYZERS
                         if r["class"] == cls]}

    def analyzer_lookup(self, tool_id) -> dict:
        """One catalog row by id (case-insensitive); a miss = found:False."""
        if not isinstance(tool_id, str):
            raise ValueError("tool_id must be a string")
        q = tool_id.strip().lower()
        if not q or len(q) > 64 or not re.fullmatch(r"[a-z0-9_.\-]+", q):
            raise ValueError("tool_id must be 1..64 chars of [a-z0-9_.-]: "
                             "%r" % (tool_id,))
        row = _ANALYZER_BY_ID.get(q)
        return {"tool": q, "row": self._row_view(row) if row else None,
                "found": row is not None}

    def finding_class_catalog(self) -> dict:
        """The finding taxonomy with its catalog pairing (id namespace "
        "covers analyzer tooling AND review flows)."""
        return {"policy": dict(POLICY),
                "rows": [{"finding": r["finding"], "class": r["class"],
                          "pairs": list(r["pairs"]), "review": r["review"]}
                         for r in FINDINGS]}

    # ---- planner arcs ----------------------------------------------------
    @staticmethod
    def _render(text, target, net, depth):
        return (text.replace("{target}", target).replace("{net}", net)
                .replace("{depth}", depth))

    def plan_contract_audit(self, target, net, depth="standard") -> dict:
        """The 7-phase lab audit arc for a testnet target; depth widens
        the suggested analyzer set (standard/deep only)."""
        info = self._chain_target(target, net)
        if depth not in DEPTHS:
            raise ValueError("depth %r unknown - known: standard, deep"
                             % (depth,))
        phases = []
        for pid, goal, acts, cmds in AUDIT_PHASES:
            phases.append({
                "phase": pid, "goal": goal,
                "activities": [self._render(a, info["target"],
                                            info["net"], depth)
                               for a in acts],
                "sample_commands": [self._render(c, info["target"],
                                                 info["net"], depth)
                                    for c in cmds],
                "policy": dict(POLICY)})
        return {"target": info["target"], "net": info["net"],
                "target_kind": info["target_kind"],
                "annotated": info["annotated"], "depth": depth,
                "policy": dict(POLICY),
                "suggested_sweep": list(DEEP_SWEEP if depth == "deep"
                                        else STANDARD_SWEEP),
                "phases": phases}

    def plan_analyzer_sweep(self, target, net, tools=None) -> dict:
        """Ordered per-tool runsheet for the lab; tools default to the
        standard set; every id must exist in the catalog."""
        info = self._chain_target(target, net)
        requested = list(STANDARD_SWEEP) if tools is None else list(tools)
        if not requested:
            raise ValueError("empty sweep request - list analyzer ids from "
                             "the catalog")
        for tool_id in requested:
            if tool_id not in _ANALYZER_BY_ID:
                raise ValueError("unknown analyzer id %r - known: %s"
                                 % (tool_id, ", ".join(sorted(
                                     _ANALYZER_BY_ID))))
        steps = []
        for tool_id in requested:
            row = _ANALYZER_BY_ID[tool_id]
            template = row["template"]
            if template and "{target}" in template:
                rendered = self._render(template, info["target"],
                                        info["net"], "standard")
                steps.append({"tool": tool_id, "class": row["class"],
                              "template": rendered,
                              "requires_lab_fork": row["lab_fork"]})
            else:
                steps.append({"tool": tool_id, "class": row["class"],
                              "template": None,
                              "note": "consult the tool's lab setup; use "
                                      "its documented invocation under "
                                      "the lab gates",
                              "requires_lab_fork": row["lab_fork"]})
        return {"target": info["target"], "net": info["net"],
                "policy": dict(POLICY), "steps": steps}

    def plan_finding_triage(self, labels) -> dict:
        """Map raw finding ids onto the taxonomy; unknown labels come "
        "back flagged uncategorized for manual review."""
        if isinstance(labels, (str, bytes)):
            raise ValueError("labels must be a list of finding ids, not a "
                             "bare string")
        rows = []
        for raw in labels:
            t = wp_scrub_target(raw).strip().lower()
            hit = _FINDING_BY_ID.get(t)
            rows.append({"label": t, "known": hit is not None,
                         "class": hit["class"] if hit else "uncategorized",
                         "pairs": list(hit["pairs"]) if hit else [],
                         "review": hit["review"] if hit
                         else _UNCATEGORIZED_REVIEW})
        return {"policy": dict(POLICY), "rows": rows,
                "categorized": sum(1 for r in rows if r["known"])}
