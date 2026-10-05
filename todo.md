# Kali agent — TODO (phased, decomposed for independent builders)

_Companion to `docs/KALI-AGENT-OPTIONS-100.md` (the option catalog; `OPT-n` refers to its
option numbers). Every task is independently buildable: one person or agent, an exclusive
file list, its own tests, a concrete acceptance gate. No two tasks in a phase share files;
shared wiring (agent class lines, role-ops.md, registry/docs sync) happens ONLY inside
`[INTEGRATION]` tasks at phase end._

**Tags:** `[BUILDER]` one person/agent, exclusive files · `[INTEGRATION]` phase-end wiring
· size `[S]` ≤ a day / `[M]` a focused wave / `[L]` multi-wave · risk `none` planners-only /
`lab` synthetic+vulnerable-app targets / `live` real-fire (always owner-signed consent first).

**Standing guardrails (every task inherits):**
- Ops are planners: they never execute. No `subprocess` / `os.system` / `eval` in mixin or
  catalog modules (test-pinned). Scrub all inputs (`wp_scrub_target`) and consult the host
  agent's `validate_target` via `getattr` (silent fallback when absent).
- Every task ships tests; the FULL suite must stay green (baseline pin: `BASELINE_SUITE_TOTAL` in `tests/test_ka_conventions.py` - 2019 collected after P0; update it in the task that moves the count. Conditional skips are env-gated - allowlist in `docs/KA-BUILDING-CONVENTIONS.md`).
- Commits authored as **Dawn Robbins <dmrobbipens@gmail.com>**; push BOTH remotes (origin =
  internal GitLab SSH, dmrobbi = GitHub) in lockstep; verify `git ls-remote` hashes match.
- No network calls in unit tests; fixtures are committed files. Lab/live items are
  owner-gated and follow kali_agent_v4's evidence discipline.
- Nothing copies external prose/code verbatim; credit sources as in-house re-authoring.

**Current state of the tree:** main at `27959ef` + the P0 wave (KA-F01 + KA-F02 landed); suite pin = BASELINE_SUITE_TOTAL; mixins:
web_pentest, redteam_pentest, xss_exploit; catalogs: redteam_tools.json (725/13),
xss_tools.json (15/5); kali.py + kali_v2.py carry all three mixins.

---

## P0 — Foundation (2 tasks; land before anything else)

- [x] **KA-F01 · Builder conventions + baseline pin** — [BUILDER][S][none] (supports all)
  - **Owns:** `docs/KA-BUILDING-CONVENTIONS.md` (new), `tests/test_ka_conventions.py` (new)
  - **Goal:** one page every builder reads: the guardrails above expanded into
    checklists (module shape, op shape, test shape, scrub/guard usage, commit/push
    procedure), plus a test pinning the suite baseline counts and the three-mixin import
    graph (no circular imports, kali + kali_v2 instantiate).
  - **Build:** write the doc from this file's Standing-guardrails section; write the
    convention test (registry create_agent smoke for kali/kali_v2 + mixin presence).
  - **Acceptance:** doc reviewed once; its test green in the full suite.
  - **Depends:** none. **Feeds:** everything (builders read it first).

- [x] **KA-F02 · Shared fixture layout** — [BUILDER][S][none] (supports all)
  - **Owns:** `tests/fixtures/README.md` (new), `tests/fixtures/` skeleton dirs
    (`parsers/`, `scans/`, `cve/`, `guard_corpus/`, `findings/`) with a committed
    `.gitkeep` each
  - **Goal:** one canonical fixture layout so P1-P6 builders never invent paths.
  - **Acceptance:** dirs exist, README names each dir's contract, suite untouched-green.
  - **Depends:** none. **Feeds:** fixture users (KA-003, KA-008, KA-018, KA-022...).

---

## P1 — Quick-pick battery (12 builder tasks + 1 integration; the first wave)

- [x] **KA-001 · CVE-matching eval corpus** — [BUILDER][S][none] (OPT-1)
  - **Owns:** `tests/fixtures/cve/cve_eval_corpus.json`, `tests/test_cve_eval.py`
  - **Goal:** pin `CVEMatchingEngine.match_cve` against 80+ real CVEs (EternalBlue,
    BlueKeep, Log4Shell, ProxyShell, SMBGhost, ProxyLogon + 30 edge cases: unknown,
    lowercase, whitespace, stale ids).
  - **Build:** curate the corpus (cve → expected exploit_name/metasploit_module/reliability
    or null for out-of-DB); parametrized tests; corpus shape schema-check test.
  - **Acceptance:** `pytest tests/test_cve_eval.py` green; no network; corpus committed.
  - **Depends:** KA-F02. **Feeds:** KA-INT-1, later KA-029.

- [x] **KA-006 · execute_tool branch matrix** — [BUILDER][S][none] (OPT-6)
  - **Owns:** `tests/test_execute_tool_matrix.py`
  - **Goal:** every branch of the tool-execution state machine pinned: unknown tool,
    auth-level rejections (each AuthorizationLevel), missing required args, whitelist /
    blacklist rejects, dry-run path (no exec), max-concurrent-jobs cap.
  - **Build:** table-driven tests against a real KaliAgent in dry-run; no network.
  - **Acceptance:** green; the state machine has zero untested branches (measured with
    a branch checklist comment).
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-014 · Guardrail integration pins** — [BUILDER][M][none] (OPT-14)
  - **Owns:** `tests/test_kali_guardrails_integration.py`
  - **Goal:** prove every `execute_tool` call passes input/tool/output guardrails:
    spy-stub the three guardrails, assert call order + blocking behavior.
  - **Build:** monkeypatch the guard pipeline; run authorized + unauthorized flows;
    pin that a blocked guardrail prevents subprocess construction entirely.
  - **Acceptance:** green; the pins documented as the guard contract.
  - **Depends:** KA-F01, KA-006 (for the flow fixtures). **Feeds:** KA-INT-1.

- [x] **KA-018 · Remediation-eval corpus** — [BUILDER][S][none] (OPT-18)
  - **Owns:** `tests/fixtures/findings/remediations.yaml`, `tests/test_remediation_eval.py`
  - **Goal:** 30 realistic findings → `generate_remediation_plan`: pin critical/high
    segmentation + the specific known remediations (Log4Shell JndiLookup removal,
    EternalBlue patching, weak-password policy).
  - **Acceptance:** green; corpus schema-checked.
  - **Depends:** KA-F02. **Feeds:** KA-INT-1.

- [x] **KA-051 · Engagement RBAC roles** — [BUILDER][M][none] (OPT-51)
  - **Owns:** `agentic_ai/agents/cyber/engagement_rbac.py` (new),
    `tests/test_engagement_rbac.py`
  - **Goal:** operator / observer-only / verify-only roles beyond the numeric levels:
    role object consulted by an `authorize_call(tool_name, role)` helper.
  - **Build:** standalone module + tests (mixins use it ONLY after KA-INT-1 wiring).
  - **Acceptance:** green; module imports clean; the helper's semantics documented.
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-052 · Expiry sweeper** — [BUILDER][S][none] (OPT-52)
  - **Owns:** `agentic_ai/agents/cyber/auth_expiry.py` (new), `tests/test_auth_expiry.py`
  - **Goal:** engagement authorizations with expiry auto-revoke: a `sweep(authorizations,
    now)` pure function + the audit-event contract.
  - **Build:** pure-function module (clock injected — testable); tests cover boundary
    times (exact expiry, past, future) + revocation events.
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-061 · Safe-mode proof** — [BUILDER][S][none] (OPT-61)
  - **Owns:** `tests/test_safe_mode_semantics.py`
  - **Goal:** a test proving safe_mode blocks mutation-class commands and lets
    read/scans through; if the current semantics fail the proof, write the FAILING test
    + a proposal note (the fix = an [INTEGRATION] decision).
  - **Build:** classify a command set (mutating vs read-only), run against
    safe_mode=True agent.
  - **Acceptance:** green test (or a red test + proposal doc if a real bug is proven —
    say so loudly in the task summary).
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-065 · Dry-run parity test** — [BUILDER][S][none] (OPT-65)
  - **Owns:** `tests/test_dry_run_parity.py`
  - **Goal:** dry-run output mirrors the would-be command string exactly; no side
    files/logs written in dry-run.
  - **Build:** run mixed command sets dry + captured-exec comparison (mock).
  - **Acceptance:** green.
  - **Depends:** KA-F01, KA-006. **Feeds:** KA-INT-1.

- [x] **KA-066 · Wazuh findings bridge (planner)** — [BUILDER][M][none] (OPT-66)
  - **Owns:** `agentic_ai/agents/cyber/soc_bridge.py` (new), `tests/test_soc_bridge.py`
  - **Goal:** SOC alert findings → per-finding verification plans (feed in a findings
    list; out come planner-level verification command sets referencing matching-engine
    results where a CVE is known).
  - **Build:** pure-planner module; a findings fixture corpus; NO live calls (the live
    pull = a later P5 task's wiring decision).
  - **Acceptance:** green; planner output schema documented.
  - **Depends:** KA-F01, KA-001 (corpus for the CVE path). **Feeds:** KA-INT-1.

- [x] **KA-067 · kevstig router bridge (planner)** — [BUILDER][M][none] (OPT-67)
  - **Owns:** `agentic_ai/agents/cyber/kev_bridge.py` (new), `tests/test_kev_bridge.py`
  - **Goal:** a coverage.json (the kevstig API shape) in → routed CVEs out → matching
    recommendations ("daily fan-out" planner core; the periodic execution = P5 job).
  - **Build:** fixture coverage.json in tests/fixtures/scans/; pure functions; pinned
    on the known API field set (catalog_count/routed_count/uncovered_count/platforms/
    entries).
  - **Acceptance:** green.
  - **Depends:** KA-F02, KA-001. **Feeds:** KA-INT-1.

- [x] **KA-082 · Evidence bundler** — [BUILDER][M][none] (OPT-82)
  - **Owns:** `agentic_ai/agents/cyber/evidence_bundle.py` (new), `tests/test_evidence_bundle.py`
  - **Goal:** per-engagement bundle: tar + manifest + sha256 per file; manifest
    self-entry excluded (the bedim backup precedent); verify() rejects tampering.
  - **Build:** standalone module (tempdir-based tests).
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-095 · pve-lab battery target playbook** — [BUILDER][M][lab] (OPT-95)
  - **Owns:** `docs/KA-LAB-TARGET.md` (new), `scripts/lab/pve-lab-battery.sh` (new)
  - **Goal:** the standard battery target: a pve-lab VM with snapshot-reset between
    runs; the playbook scripts reset + verification; documents the TCG/lab net facts.
  - **Build:** script + doc; NO live executions in CI (manual executor only).
  - **Acceptance:** script `--check` mode green; doc complete; owner-gate marked.
  - **Depends:** KA-F01. **Feeds:** KA-INT-1.

- [x] **KA-INT-1 · Phase-1 wiring + release** — [INTEGRATION][S][none]
  - **Owns (SHARED files this task only):** `agentic_ai/agents/cyber/kali.py`,
    `agentic_ai/agents/cyber/kali_v2.py` (class lines + safe-mode/authorization
    integrations KA-051/052/061 decided), `skills/agentic-roles/references/role-ops.md`
    (new ops rows), `AGENT_MATRIX.md` (row sync)
  - **Goal:** wire the phase's standalone modules into both agents per the
    builders' contracts; resolve KA-061's proposal if any; run the full suite; report.
  - **Acceptance:** suite green (2007+new); both remotes lockstep; role-ops consistent.

---

## P2 — Exploit-test depth (27 builder tasks + 1 integration; remaining track A)

- [x] **KA-002 · KEV-driven matching eval** — [BUILDER][M][none] (OPT-2)
  - **Owns:** `tests/fixtures/scans/kevstig_coverage_snapshot.json` (new), `tests/test_kev_matching_eval.py` (new)
  - **Goal:** the kevstig API's coverage.json shape (committed snapshot; field set:
    catalog_count/routed_count/uncovered_count/platforms/entries) in → every routed CVE
    fed to match_cve → a coverage % report (routed CVEs the DB knows vs not); the
    measured gap gates KA-029's expansion queue.
  - **Build:** pure functions + fixture snapshot (no network in tests); a live-refresh
    variant is opt-in (documented), same pattern as KA-012.
  - **Acceptance:** green offline; the coverage report renders as a small table in the
    test summary; schema pinned to the known API shape.
  - **Depends:** KA-F02, KA-001. **Feeds:** KA-INT-2, KA-029.

- [x] **KA-003 · Parser regression fixtures** — [BUILDER][S][none] (OPT-3)
  - **Owns:** `tests/fixtures/parsers/{nmap_xml,sqlmap,nuclei,crackmapexec}.sample.*`,
    `tests/test_parser_fixtures.py`
  - **Goal:** real recorded outputs parsed: every extracted field pinned per fixture.
  - **Acceptance:** green; fixtures committed (synthetic-but-realistic: mark provenance).
  - **Depends:** KA-F02. **Feeds:** KA-INT-2.

- [x] **KA-004 · MetasploitRPC mocked battery** — [BUILDER][M][none] (OPT-4)
  - **Owns:** `tests/test_msfrpc_mock.py`, `tests/fixtures/parsers/msfrpc_responses.json`
  - **Goal:** requests-mock all RPC calls (login/logout/module*/job.create/session.list/
    db.*/run); pin shapes + failure branches (timeout, auth fail, malformed).
  - **Acceptance:** green; zero network in CI.
  - **Depends:** KA-F02. **Feeds:** KA-INT-2.

- [x] **KA-005 · generate_payload argument battery** — [BUILDER][S][none] (OPT-5)
  - **Owns:** `tests/test_generate_payload_args.py`
  - **Goal:** msfvenom arg building + metachar rejections + file-vs-stdout branches
    (subprocess mocked).
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-007 · Playbook smoke battery** — [BUILDER][M][none] (OPT-7)
  - **Owns:** `tests/test_playbook_smoke.py`
  - **Goal:** the five audit playbooks dry-run against a stubbed registry: plan shapes,
    deterministic step order, no orphan steps (see KA-025 cross-check).
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-008 · Guard-fuzz corpus** — [BUILDER][S][none] (OPT-8)
  - **Owns:** `tests/fixtures/guard_corpus/hostile_inputs.json`, `tests/test_guard_fuzz.py`
  - **Goal:** hostile-input corpus (control chars, unicode, shell tricks, nulls,
    oversize, nested quotes) swept through all scrubbers/guards; invariant:
    ValueError-or-clean, never other exceptions.
  - **Acceptance:** green; corpus committed.
  - **Depends:** KA-F02. **Feeds:** KA-INT-2.

- [x] **KA-009 · Lab-target parity battery** — [BUILDER][M][lab] (OPT-9)
  - **Owns:** `tests/lab/test_planner_parity.py`, `docker/lab-targets/docker-compose.yml`,
    `docker/lab-targets/README.md`
  - **Goal:** dockerized Juice Shop/DVWA/WordPress targets; planners run against live
    lab targets with a no-phantom-cmd assertion (every planned command = known binary).
  - **Build:** manual-executor only; README covers the teardown/reset (ties to KA-095).
  - **Acceptance:** battery passes in the lab once (recorded in the doc); skipped
    cleanly in CI (marker).
  - **Depends:** KA-F01, KA-008. **Feeds:** KA-INT-2.

- [x] **KA-010 · Matching-precision eval** — [BUILDER][M][none] (OPT-10)
  - **Owns:** `tests/test_matching_precision.py`, `tests/fixtures/cve/precision_cases.json`
  - **Goal:** seed scan results with near-miss versions (patched-but-adjacent, EOL
    banners); measure precision/recall of the pipelines; emit a measured report.
  - **Acceptance:** green + a committed baseline eval report.
  - **Depends:** KA-001. **Feeds:** KA-INT-2.

- [x] **KA-011 · Parser schema-version compatibility** — [BUILDER][S][none] (OPT-11)
  - **Owns:** `tests/fixtures/parsers/versioned/`, `tests/test_parser_versions.py`
  - **Goal:** nmap XML from multiple versions + nuclei schema evolutions parse without
    drift.
  - **Acceptance:** green.
  - **Depends:** KA-003. **Feeds:** KA-INT-2.

- [x] **KA-012 · CVE_EXPLOIT_DB staleness gate** — [BUILDER][M][none] (OPT-12)
  - **Owns:** `tests/test_cve_db_staleness.py`, `scripts/ka/cve_db_check.py`
  - **Goal:** every DB entry's reference resolves — offline mirror mode (committed
    snapshot) for CI + a live-nightly variant (schedule = P5 decision).
  - **Acceptance:** green offline; the script has an opt-in live mode.
  - **Depends:** KA-F02. **Feeds:** KA-INT-2.

- [x] **KA-013 · Cross-generation op parity** — [BUILDER][S][none] (OPT-13)
  - **Owns:** `tests/test_generation_parity.py`
  - **Goal:** kali, kali_v2, kali_agent_v4 CLI commands behave identically where they
    overlap (drift test; v4 read-only comparisons only).
  - **Acceptance:** green (or documented deltas with the reason).
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-015 · Authorization-expiry enforcement** — [BUILDER][S][none] (OPT-15)
  - **Owns:** `tests/test_auth_expiry_enforcement.py`
  - **Goal:** authorizations with expires_at revoke at + after expiry inside the
    execution path; boundary tests.
  - **Acceptance:** green (or red-with-proposal if the enforcement is missing — loud).
  - **Depends:** KA-F01, KA-052. **Feeds:** KA-INT-2.

- [x] **KA-016 · Concurrency soak** — [BUILDER][S][none] (OPT-16)
  - **Owns:** `tests/test_execute_concurrency.py`
  - **Goal:** 8 parallel dry-runs: job_lock correctness, counter returns to zero, no
    deadlock.
  - **Acceptance:** green (use pytest-timeout to bound it).
  - **Depends:** KA-006. **Feeds:** KA-INT-2.

- [x] **KA-017 · Evidence hash-chain verify** — [BUILDER][M][none] (OPT-17)
  - **Owns:** `agentic_ai/agents/cyber/evidence_chain.py` (new), `tests/test_evidence_chain.py`
  - **Goal:** hash-chained evidence entries + tamper detection (v4 discipline
    generalized as a pure module).
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-019 · Tool-DB completeness test** — [BUILDER][S][none] (OPT-19)
  - **Owns:** `tests/test_kali_tools_db_schema.py`
  - **Goal:** every ToolDefinition complete, authorization matches the category's
    expectation, command/name consistent.
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-020 · Hostile-arg property sweep** — [BUILDER][M][none] (OPT-20)
  - **Owns:** `tests/test_hostile_args_all_ops.py`
  - **Goal:** generated hostile arguments across ALL planner ops of the three mixins +
    the registry kali agents: only ValueErrors, never crashes.
  - **Acceptance:** green.
  - **Depends:** KA-008. **Feeds:** KA-INT-2.

- [x] **KA-021 · laya-loop replay eval (planner)** — [BUILDER][L][none] (OPT-21)
  - **Owns:** `agentic_ai/agents/cyber/laya_replay.py` (new), `tests/test_laya_replay.py`
  - **Goal:** replay flagged-alert audit rows through matching + planning; precision
    report (the audit-log shape fixture committed; no live SOC calls).
  - **Acceptance:** green; report template documented.
  - **Depends:** KA-010. **Feeds:** KA-INT-2.

- [x] **KA-022 · Synthetic-scan battery** — [BUILDER][M][none] (OPT-22)
  - **Owns:** `tests/fixtures/scans/` (template corpus), `tests/test_scan_to_plan.py`
  - **Goal:** "scan in → plan out": template-generated nmap/sqlmap/nuclei → matching +
    recommendations end-to-end.
  - **Acceptance:** green.
  - **Depends:** KA-F02, KA-003. **Feeds:** KA-INT-2.

- [x] **KA-023 · Catalog link-rotation test** — [BUILDER][M][none] (OPT-23)
  - **Owns:** `tests/test_catalog_links.py`, `scripts/ka/catalog_check.py`
  - **Goal:** the catalogs' URLs re-verified: offline mirror mode (committed hash
    snapshot) for CI + opt-in live mode; dead links flagged in a report file.
  - **Acceptance:** green offline; live mode documented.
  - **Depends:** KA-F02. **Feeds:** KA-INT-2.

- [x] **KA-024 · XSS-ops context assertions** — [BUILDER][S][none] (OPT-24)
  - **Owns:** `tests/test_xss_ops_extended.py`
  - **Goal:** callback steps use only catalog tools; countermeasures cross-check vs
    prevention; per-context plan assertions.
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-025 · Playbook-vs-DB consistency** — [BUILDER][S][none] (OPT-25)
  - **Owns:** `tests/test_playbook_tools_exist.py`
  - **Goal:** playbook tools exist in KALI_TOOLS_DB + mixin catalogs (no orphans).
  - **Acceptance:** green.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-026 · Exploit-test replay mode** — [BUILDER][L][none] (OPT-26)
  - **Owns:** `agentic_ai/agents/cyber/replay_mode.py` (new), `tests/test_replay_mode.py`
  - **Goal:** record a dry-run chain → fixture → replay for regression (pure recording
    of PLANNED commands, no execution).
  - **Acceptance:** green.
  - **Depends:** KA-006. **Feeds:** KA-INT-2.

- [x] **KA-027 · Nuclei-tag pinning** — [BUILDER][M][none] (OPT-27)
  - **Owns:** `tests/test_nuclei_tags.py`, `tests/fixtures/parsers/nuclei_tags.json`
  - **Goal:** automated-class template tags + severity mapping pinned against a
    committed snapshot (no upstream drift).
  - **Acceptance:** green.
  - **Depends:** KA-003. **Feeds:** KA-INT-2.

- [x] **KA-028 · Doc-claim matrix** — [BUILDER][M][none] (OPT-28)
  - **Owns:** `tests/test_kali_doc_claims.py`, `docs/KA-DOC-CLAIMS.md`
  - **Goal:** each documented kali improvement claim mapped to its proving test.
  - **Acceptance:** green; doc lists all claims with test ids.
  - **Depends:** KA-F01. **Feeds:** KA-INT-2.

- [x] **KA-029 · CVE DB expansion pipeline** — [BUILDER][L][none] (OPT-29)
  - **Owns:** `scripts/ka/cve_db_propose.py` (new), `tests/test_cve_db_proposals.py`
  - **Goal:** KEV's newest-30d + CISA references → PROPOSAL file rows (human-reviewed
    before any CVE_EXPLOIT_DB change); shape tests pin proposals; review queue =
    `docs/KA-CVE-DB-REVIEW-QUEUE.md`.
  - **Acceptance:** green; proposals well-formed; the DB unchanged by this task.
  - **Depends:** KA-001, KA-012. **Feeds:** KA-INT-2.

- [x] **KA-030 · Exploit-test runbook** — [BUILDER][S][none] (OPT-30)
  - **Owns:** `docs/KA-EXPLOIT-TESTS.md`, `Makefile` (battery targets — integration-
    reviewed)
  - **Goal:** how to run the batteries locally: venv, fixtures, lab markers, ordering.
  - **Acceptance:** commands in the doc verified once by hand; Makefile targets
    `make ka-tests` + `make ka-battery(lab)`.
  - **Depends:** KA-F01 (read this doc last — it ties P1+P2 together).
  - **Feeds:** KA-INT-2.

- [ ] **KA-INT-2 · Phase-2 wiring + release** — [INTEGRATION][S][none]
  - **Owns (SHARED):** the shared-file set of P1's integration task + `Makefile`
    cross-check with KA-030 + the CI file (if any) for the offline-battery target.
  - **Goal:** wire new pure modules where a decision exists (none required for
    fixture/test-only tasks); run the full suite; release notes.
  - **Acceptance:** suite green; both remotes lockstep; runbook commands all pass.

---

## P3 — Methodology mixins (20 builders + 1 integration; track B)

_Each mixmixin builder: a NEW module file + NEW test file + (when catalog-driven) a NEW
builder + data file. NO edits to kali.py / kali_v2.py — the phase integration wires them._

- [ ] **KA-031 · PrivescMixin** — [BUILDER][M][none] (OPT-31)
  - **Owns:** `agentic_ai/agents/cyber/privesc.py`, `tests/test_privesc_ops.py`,
    `tools/build_privesc_capability.py` (GTFOBins/LOLBAS-capability INDEX re-authored
    as our data), `data/privesc_index.json`
  - **Acceptance:** ops = plan_privesc(target, platform) + privesc_capability_lookup;
    no payloads beyond command syntax; suite green with its tests.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-032 · ADMixin** — [BUILDER][M][lab] (OPT-32)
  - **Owns:** `agentic_ai/agents/cyber/ad_pentest.py`, `tests/test_ad_ops.py`
  - **Acceptance:** plan_ad(scope) + ad_command_catalog + ad_detection_notes; lab-only
    policy tag; lab battery hook marker.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-033 · CloudMixin** — [BUILDER][M][none] (OPT-33)
  - **Owns:** `agentic_ai/agents/cyber/cloud_pentest.py`, `tests/test_cloud_pentest_ops.py`
  - **Acceptance:** per-cloud enum planners + IAM blast-radius checklists + detection.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-034 · ContainerMixin** — [BUILDER][M][none] (OPT-34)
  - **Owns:** `agentic_ai/agents/cyber/container_pentest.py`, `tests/test_container_ops.py`
  - **Acceptance:** escape-surface planners + k8s RBAC checklist + tool catalog.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-035 · MobileMixin** — [BUILDER][M][none] (OPT-35)
  - **Owns:** `agentic_ai/agents/cyber/mobile_pentest.py`, `tests/test_mobile_ops.py`
  - **Acceptance:** APK/IPA static+dynamic planners + detection notes.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-036 · Wireless depth** — [BUILDER][M][lab] (OPT-36)
  - **Owns:** `agentic_ai/agents/cyber/wireless_pentest.py`, `tests/test_wireless_ops.py`
  - **Acceptance:** monitor-mode capture planners + rogue-AP playbook + detection.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-037 · OSINTMixin** — [BUILDER][S][none] (OPT-37)
  - **Owns:** `agentic_ai/agents/cyber/osint_pentest.py`, `tests/test_osint_ops.py`
  - **Acceptance:** domain/email/persona enum planners.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-038 · ForensicsMixin** — [BUILDER][S][none] (OPT-38)
  - **Owns:** `agentic_ai/agents/cyber/forensics_ops.py`, `tests/test_forensics_ops.py`
  - **Acceptance:** volatility/fls/exiftool analyst workflows + evidence handling.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-039 · MalwareAnalysisMixin** — [BUILDER][M][none] (OPT-39)
  - **Owns:** `agentic_ai/agents/cyber/malware_ops.py`, `tests/test_malware_ops.py`
  - **Acceptance:** static-first methodology + detonation sandbox-only gate.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-040 · NetworkDeviceMixin** — [BUILDER][M][lab] (OPT-40)
  - **Owns:** `agentic_ai/agents/cyber/network_device.py`, `tests/test_network_device_ops.py`
  - **Acceptance:** router/switch/fw enum + config-audit catalogs.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-041 · API-SecurityMixin** — [BUILDER][M][none] (OPT-41)
  - **Owns:** `agentic_ai/agents/cyber/api_pentest.py`, `tests/test_api_ops.py`
  - **Acceptance:** REST/GraphQL planners + auth-surface catalogs.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-042 · SocialEngMixin** — [BUILDER][M][lab] (OPT-42)
  - **Owns:** `agentic_ai/agents/cyber/socialeng_ops.py`, `tests/test_socialeng_ops.py`
  - **Acceptance:** simulation planners with CONSENT gates (the op refuses without a
    consent record); lab-only policy.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-043 · ICS/IoT mixin** — [BUILDER][M][lab] (OPT-43)
  - **Owns:** `agentic_ai/agents/cyber/ics_iot.py`, `tests/test_ics_iot_ops.py`
  - **Acceptance:** modbus/S7 planners + firmware flow; air-gapped-lab requirement.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-044 · PostExploitMixin** — [BUILDER][M][lab] (OPT-44)
  - **Owns:** `agentic_ai/agents/cyber/postexp.py`, `tests/test_postexp_ops.py`
  - **Acceptance:** enumeration strategy + evidence-only policy gates.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-045 · WebAuthMixin** — [BUILDER][M][none] (OPT-45)
  - **Owns:** `agentic_ai/agents/cyber/webauth_ops.py`, `tests/test_webauth_ops.py`
  - **Acceptance:** SSO/OAuth/JWT planner methods (no secrets handling).
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-046 · Contract-analysis mixin** — [BUILDER][L][lab] (OPT-46)
  - **Owns:** `agentic_ai/agents/cyber/chain_ops.py`, `tests/test_chain_ops.py`
  - **Acceptance:** static-analyzer catalog + testnet-only policy.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-047 · web_pentest phases 9-12** — [BUILDER][M][none] (OPT-47)
  - **Owns:** `tests/test_web_pentest_extended.py` (the module edit lands via
    KA-INT-3: builder files `docs/web_pentest_phases_9_12.md` with the proposed tuples)
  - **Acceptance:** 4 new phases spec'd (business-logic, supply-chain/SBOM,
    PII-exposure, STIG-baseline mapping) with activities + safe sample commands.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-048 · WEB_VULN_CLASSES +10** — [BUILDER][M][none] (OPT-48)
  - **Owns:** `tests/test_web_vuln_extended.py` (+ the proposed dict in
    `docs/web_vuln_additions.md`; module edit via KA-INT-3)
  - **Acceptance:** 10 new classes with commands; scrub-tested; no payload drift.
  - **Depends:** KA-F01. **Feeds:** KA-INT-3.

- [ ] **KA-049 · Per-CMS catalogs** — [BUILDER][M][none] (OPT-49)
  - **Owns:** `tools/build_cms_catalog.py` (new), `data/cms_flows.json` (new),
    `tests/test_cms_flows.py`
  - **Acceptance:** WP/Drupal/Joomla/typo3 flows; URLs verified live; no payloads.
  - **Depends:** KA-F02. **Feeds:** KA-INT-3.

- [ ] **KA-050 · plan_full_engagement** — [BUILDER][M][none] (OPT-50)
  - **Owns:** `agentic_ai/agents/cyber/full_engagement.py` (new), `tests/test_full_engagement.py`
  - **Acceptance:** composes existing mixin plans (only what exists at build time;
    composition contract documented).
  - **Depends:** KA-F01 (+ any P3 mixins that exist).  **Feeds:** KA-INT-3.

- [ ] **KA-INT-3 · Phase-3 wiring** — [INTEGRATION][M][none]
  - **Owns (SHARED):** kali.py + kali_v2.py class wiring, role-ops.md rows,
    AGENT_MATRIX.md, the KA-047/048 spec'd edits applied to web_pentest.py.
  - **Acceptance:** suite green; both remotes lockstep; docs synced.

---

## P4 — Safety layer (11 builders + 1 integration; track C remainder)

- [ ] **KA-053 · Blast-radius classifier** — [BUILDER][M][none] (OPT-53)
  - **Owns:** `agentic_ai/agents/cyber/blast_radius.py` (new), `tests/test_blast_radius.py`
  - **Acceptance:** command → {read|scan|exploit-class} tagging + the authorization
    requirement mapping.
- [ ] **KA-054 · Per-target rate limiting** — [BUILDER][S][none] (OPT-54)
  - **Owns:** `agentic_ai/agents/cyber/rate_limit.py` (new), `tests/test_rate_limit.py`
  - **Acceptance:** sliding-window cap per (tool, target) + audit-event shape.
- [ ] **KA-055 · Egress guard** — [BUILDER][M][none] (OPT-55)
  - **Owns:** `agentic_ai/agents/cyber/egress_guard.py` (new), `tests/test_egress_guard.py`
  - **Acceptance:** network-command classification; RFC1918 requires lab staging;
    external requires an auth tag; DNS-resolution strategy documented.
- [ ] **KA-056 · Credential vaulting** — [BUILDER][M][none] (OPT-56)
  - **Owns:** `agentic_ai/agents/cyber/credvault.py` (new), `tests/test_credvault.py`
  - **Acceptance:** creds never in CLIs; exec-time reads via env-file contract
    (the mailbox/secrets pattern).
- [ ] **KA-057 · Immutable audit chain** — [BUILDER][S][none] (OPT-57)
  - **Owns:** `agentic_ai/agents/cyber/audit_chain.py` (new), `tests/test_audit_chain.py`
  - **Acceptance:** hash-chained audit jsonl + verify op; collision with KA-017
    avoided (017 = evidence dir; this = the agent's own audit log).
- [ ] **KA-058 · Rollback requirements** — [BUILDER][M][none] (OPT-58)
  - **Owns:** `agentic_ai/agents/cyber/rollback_plan.py` (new), `tests/test_rollback_plan.py`
  - **Acceptance:** mutating executions require a declared undo step (contract tests).
- [ ] **KA-059 · Sandbox profile** — [BUILDER][M][none] (OPT-59)
  - **Owns:** `docker/sandbox/` (new: profile + README), `tests/test_sandbox_docs.py`
  - **Acceptance:** profile reviewed (integration task mounts it); doctor-check spec'd.
- [ ] **KA-060 · Consent gate** — [BUILDER][M][none] (OPT-60)
  - **Owns:** `agentic_ai/agents/cyber/consent_gate.py` (new), `tests/test_consent_gate.py`
  - **Acceptance:** non-dry-run executions demand an owner-signed consent record
    (generalizes v4's evidence discipline); the gate's refusal audited.
- [ ] **KA-062 · Budget/quota** — [BUILDER][S][none] (OPT-62)
  - **Owns:** `agentic_ai/agents/cyber/budgets.py` (new), `tests/test_budgets.py`
- [ ] **KA-063 · Staging verification** — [BUILDER][S][none] (OPT-63)
  - **Owns:** `agentic_ai/agents/cyber/staging_check.py` (new), `tests/test_staging_check.py`
- [ ] **KA-064 · Doctor tool-version matrix** — [BUILDER][S][none] (OPT-64)
  - **Owns:** `docs/ka_tool_versions.json` (new), `tests/test_tool_versions.py`
- [ ] **KA-INT-4 · Phase-4 wiring** — [INTEGRATION][M][none]
  - **Acceptance:** the gates compose (order pinned: consent → auth → blast-radius →
    egress → rate-limit → execute); suite green; lockstep push.

---

## P5 — Fleet tie-ins (13 builders + 1 integration; track D remainder)

- [ ] **KA-068 · Aging-exploitable queue** — [BUILDER][M][none] (OPT-68)
  - **Owns:** `agentic_ai/agents/cyber/aging_queue.py` (new), `tests/test_aging_queue.py`
  - **Acceptance:** patch-report ages × exploit availability → priority report (pure
    planner; the patch report.json shape fixture committed).
- [ ] **KA-069 · Tickets bridge** — [BUILDER][M][none] (OPT-69)
  - **Owns:** `agentic_ai/agents/cyber/tickets_bridge.py` (new), `tests/test_tickets_bridge.py`
  - **Acceptance:** engagement → ticket payloads (the soc-tickets contract; mocked).
- [ ] **KA-070 · Remediation-ticket integration** — [BUILDER][S][none] (OPT-70)
  - **Owns:** `agentic_ai/agents/cyber/remediation_tickets.py` (new), `tests/test_remediation_tickets.py`
- [ ] **KA-071 · laya double-check** — [BUILDER][L][none] (OPT-71)
  - **Owns:** `agentic_ai/agents/cyber/laya_verify.py` (new), `tests/test_laya_verify.py`
- [ ] **KA-072 · STIG-coverage gap report** — [BUILDER][M][none] (OPT-72)
  - **Owns:** `tools/build_stig_gap_report.py` (new), `tests/test_stig_gap.py`
- [ ] **KA-073 · Newsroom threat feed** — [BUILDER][S][none] (OPT-73)
  - **Owns:** `agentic_ai/agents/cyber/threat_feed.py` (new), `tests/test_threat_feed.py`
- [ ] **KA-074 · Healthcheck row** — [BUILDER][S][none] (OPT-74)
  - **Owns:** `tests/test_healthcheck_kali_row.py`, `docs/ka_healthcheck_row.md` (the
    healthcheck.sh edit itself = the integration task's, since the script is shared).
- [ ] **KA-075 · Engagement → SOC memory** — [BUILDER][S][none] (OPT-75)
  - **Owns:** `agentic_ai/agents/cyber/soc_memory_bridge.py` (new), `tests/test_soc_memory_bridge.py`
- [ ] **KA-076 · Fleet test harness** — [BUILDER][L][lab] (OPT-76)
  - **Owns:** `docker/fleet-harness/` (new), `tests/lab/` additions, harness README
- [ ] **KA-077 · Report email bridge** — [BUILDER][S][none] (OPT-77)
  - **Owns:** `agentic_ai/agents/cyber/report_mail.py` (new), `tests/test_report_mail.py`
  - **Acceptance:** uses the reports@ mailbox env pattern; dry-send default; owner
    notification contract.
- [ ] **KA-078 · Lab detection loop** — [BUILDER][L][lab] (OPT-78)
  - **Owns:** `docs/KA-LAB-DETECTION.md` (new), `scripts/lab/enroll-wazuh.sh` (new)
  - **Acceptance:** the playbook (owner-run) documented end-to-end; NOT executed by CI.
- [ ] **KA-079 · Registry/doc sync** — [BUILDER][S][none] (OPT-79)
  - **Owns:** `scripts/ka/doc_sync.py` (new), `tests/test_doc_sync.py`
  - **Acceptance:** agent cards + AGENT_MATRIX.md + registry-description consistency
    checker (future integrations run it).
- [ ] **KA-080 · Appliance CVE corpus** — [BUILDER][M][lab] (OPT-80)
  - **Owns:** `tools/build_appliance_corpus.py` (new), `data/appliance_cves.json` (new),
    `tests/test_appliance_corpus.py`
  - **Acceptance:** KEV appliance set (vCenter/ESXi, Citrix, F5, Ivanti) as proposal
    data (KA-029's review queue), lab-only flagging.
- [ ] **KA-INT-5 · Phase-5 wiring** — [INTEGRATION][M][none]
  - **Acceptance:** bridge wiring behind a feature flag default-off; healthcheck row
    (the shared script edit) lands here; suite green; lockstep push.

---

## P6 — Evidence/reporting + ops (18 builders + 1 integration; tracks E/F remainder)

- [ ] **KA-081 · Report assembler op** — [BUILDER][M][none] (OPT-81)
  - **Owns:** `agentic_ai/agents/cyber/report_assembler.py` (new), `tests/test_report_assembler.py`
- [ ] **KA-083 · Timeline builder** — [BUILDER][S][none] (OPT-83)
- [ ] **KA-084 · IOC extractor** — [BUILDER][M][none] (OPT-84)
- [ ] **KA-085 · Retest diff op** — [BUILDER][M][none] (OPT-85)
- [ ] **KA-086 · Screenshot capture** — [BUILDER][M][none] (OPT-86)
- [ ] **KA-087 · Tool KB** — [BUILDER][M][none] (OPT-87)
- [ ] **KA-088 · No-orphan-numbers gate** — [BUILDER][S][none] (OPT-88)
- [ ] **KA-089 · Severity calibration** — [BUILDER][M][none] (OPT-89)
- [ ] **KA-090 · Publishable redaction path** — [BUILDER][M][none] (OPT-90)
- [ ] **KA-091 · Kali-package doctor** — [BUILDER][S][none] (OPT-91)
- [ ] **KA-092 · CLI ergonomics** — [BUILDER][S][none] (OPT-92)
- [ ] **KA-093 · Cards/matrix sync** — [BUILDER][S][none] (OPT-93)
- [ ] **KA-094 · Secrets-store wiring** — [BUILDER][M][none] (OPT-94)
- [ ] **KA-096 · Reproducible kali profile** — [BUILDER][M][none] (OPT-96)
  - **Owns:** `docker/kali-ci/Dockerfile` (new) + README (tool set per phase)
- [ ] **KA-097 · CI matrix** — [BUILDER][M][none] (OPT-97)
  - **Owns:** `.gitlab-ci.yml` additions proposal (the integration task applies; the
    shared CI file = integration-reviewed)
- [ ] **KA-098 · Plan explorer** — [BUILDER][M][none] (OPT-98)
- [ ] **KA-099 · Skill sync** — [BUILDER][S][none] (OPT-99)
- [ ] **KA-100 · Owner dashboard widget** — [BUILDER][M][none] (OPT-100)
- [ ] **KA-INT-6 · Phase-6 wiring + release** — [INTEGRATION][M][none]
  - **Acceptance:** the assembled toolkit released; docs sync (KA-079's checker
    green); suite green; lockstep push; the todo file closed out with a summary.

---

## Parallelism map (how this file is meant to run)

- P0: 2 builders in parallel, half a day.
- From P1 on: UP TO 12 concurrent builders in P1, 26 in P2, 20 in P3, 11 in P4,
  13 in P5, 18 in P6 — every builder = one task, one exclusive file set, no merges
  except at the phase's [INTEGRATION] task.
- Integration tasks: one designated person/agent each; they are the ONLY shared-file
  edits (kali.py / kali_v2.py / role-ops.md / AGENT_MATRIX.md / Makefile / CI /
  healthcheck.sh).
- Cross-phase deps are explicit per task (Depends/Feeds); everything else is free.