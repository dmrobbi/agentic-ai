# Kali agent — 100 improvement options

_The BUILDABLE decomposition of these options — phased, independent-builder tasklist with
file ownership, acceptance gates, and dependencies — lives in `todo.md` (repo root)._

_2026-10-05, owner request ("research and give me 100 more options to improve the
kali agent and make more exploit tests"). Grounded in the current state: registry
agents KaliAgent (2,758 lines; ~40-tool DB, MetasploitRPC, execute_tool flow,
6 parsers, 5 playbooks) + KaliAgentV2 (1,321 lines; OutputParsers for
nmap/sqlmap/nuclei/crackmapexec, CVEMatchingEngine, ToolRecommendationEngine,
RemediationEngine), the three mixins (web_pentest / redteam / xss) with their
generated catalogs (725-tool red-team, 15-tool XSS), the kali_agent_v4 CLI
generation (live-fire + evidence discipline), and the SOC fleet around them
(Wazuh, kevstig, laya, patch monitor, tickets, pve-lab). Suite today: 2007
passed / 5 skipped._

Tags: [S] ≤ a day, [M] a focused wave, [L] multi-wave. Risk: none = planners only;
lab = synthetic/vulnerable-app targets; live = real-fire (owner-gated always).

## Quick pick — if only ten land

Do these first: 1 (CVE-matching eval corpus), 6 (execute_tool branch battery),
14 (guardrail integration pin), 51-52 (RBAC + expiries), 18 (remediation eval),
61 (safe-mode proof), 65 (dry-run parity), 82 (evidence bundler),
66-67 (Wazuh + kevstig bridges), 95 (pve-lab battery target). They raise the
test floor AND make the first lab battery repeatable.

## A. Exploit-test expansion (the ask) — 30 options

- [1] **CVE-matching eval corpus** [S/none] — fixture of 80+ real CVEs (EternalBlue,
  BlueKeep, Log4Shell/42XXX, ProxyShell, SMBGhost, ProxyLogon, ...) each pinning the
  expected exploit/metasploit module from CVE_EXPLOIT_DB; catches silent DB drift.
- [2] **KEV-driven matching eval** [M/none] — feed the live kevstig coverage.json's
  routed CVEs into match_cve; report coverage % (routed CVEs the DB knows vs not);
  gate the DB-expansion task on the measured gap.
- [3] **Parser regression fixtures** [S/none] — recorded real outputs (nmap -oX,
  sqlmap, nuclei jsonl, crackmapexec) under tests/fixtures/; parametrized parse tests
  pinning every extracted field.
- [4] **MetasploitRPC mocked battery** [M/none] — requests-mock the RPC endpoints
  (auth.login, job.create, session.list, db_hosts/db_services/db_vulns/db_creds);
  pin request shapes + every failure branch.
- [5] **generate_payload argument battery** [S/none] — msfvenom arg construction,
  metachar rejection, file-vs-stdout branches with the subprocess mocked.
- [6] **execute_tool branch matrix** [M/none] — table-driven: unknown tool, auth-level
  rejections, missing required args, whitelist/blacklist rejects, dry-run path,
  max-concurrent-jobs cap — pin every branch of the state machine.
- [7] **Playbook smoke battery** [M/none] — the five audit playbooks dry-run against a
  stubbed tool registry: plan shapes, step ordering, no orphan steps.
- [8] **Guard-fuzz corpus** [S/none] — hostile-input corpus (control chars, unicode,
  shell metachars, nulls, nested quotes) swept through wp_scrub_target +
  _validate_command_args + every _guard: invariant = ValueError or clean, never
  another exception.
- [9] **Lab-target parity battery** [M/lab] — dockerized Juice Shop/DVWA/WordPress
  targets; planners run against live targets with a no-phantom-cmd assertion (every
  planned command is a known binary).
- [10] **Matching-precision eval** [M/none] — seed scan results with near-miss
  versions; measure match precision/recall; emit an eval report each run.
- [11] **Parser schema-version compatibility** [S/none] — nmap XML from multiple nmap
  versions, nuclei schema evolutions: backward-compat pinned.
- [12] **CVE_EXPLOIT_DB staleness gate** [M/none] — every DB entry's exploit
  reference resolves (live-nightly check or offline pinned mirror); stale rows flagged.
- [13] **Cross-generation op parity** [S/none] — kali, kali_v2, and v4 CLI commands
  behave identically where they overlap; drift test.
- [14] **Guardrail integration pins** [M/none] — prove every execute_tool passes
  input/tool/output guardrails (spy on the path).
- [15] **Authorization-expiry enforcement** [S/none] — engagement authorizations with
  expires_at: expiry revokes (test; fix if the sweeper is missing).
- [16] **Concurrency soak** [S/none] — 8 parallel dry-run executions: job_lock
  correctness, counters return to zero, no deadlock.
- [17] **Evidence hash-chain verify** [M/none] — v4 evidence/ manifest + sha chain +
  a tamper-detection test.
- [18] **Remediation-eval corpus** [S/none] — 30 realistic findings → remediation
  plans; pin critical/high segmentation and the specific known remediations.
- [19] **Tool-DB completeness test** [S/none] — every ToolDefinition: fields complete,
  authorization matches category expectations, command name consistent with the tool
  name.
- [20] **Hostile-arg property sweep** [M/none] — all three mixins' ops under generated
  hostile arguments: only ValueErrors, never crashes.
- [21] **laya-loop replay eval** [L/lab] — replay flagged SOC alerts through the
  matching engine; precision report on the SOC's real alert stream.
- [22] **Synthetic-scan battery** [M/none] — template-generated nmap/sqlmap/nuclei
  outputs → matching + recommendations end-to-end ("scan in → plan out" harness).
- [23] **Catalog link rotation test** [M/none] — the 725-link red-team catalog
  re-verified on a schedule; dead links flagged in a report.
- [24] **XSS-ops per-context assertions** [S/none] — expand the xss battery: every
  callback step uses only catalog tools; countermeasures cross-checked against
  prevention.
- [25] **Playbook-vs-DB consistency** [S/none] — playbook-embedded tools must exist in
  KALI_TOOLS_DB and the mixin catalogs (no orphan steps).
- [26] **Exploit-test replay mode** [L/none] — record a dry-run chain once, replay for
  regression (fixture-based, vcrpy-style).
- [27] **Nuclei-tag pinning** [M/none] — the automated-class templates pinned against
  the upstream template set; severity mapping drift detected.
- [28] **Doc-claim matrix** [M/none] — KALIAG_V2_IMPROVEMENTS / KALI_AGENT.md claims
  each mapped to the test proving them; docs can't drift from code.
- [29] **CVE DB expansion pipeline** [L/none] — scheduled proposal job: newest KEV
  entries + CISA references → reviewed CVE_EXPLOIT_DB rows; shape tests pin them.
- [30] **Exploit-test runbook** [S/none] — docs/exploit-tests.md: how to run the
  battery locally (venv, fixtures, lab mode) — the operationalization.

## B. Planner/methodology depth — 20 options

- [31] **PrivescMixin** [M/none] — Linux/Windows privilege-escalation planners:
  enumeration command sets (linpeas/winpeas/sudo -l/kernel), GTFOBins/LOLBAS-capability
  index as re-authored generated data, detection pairing.
- [32] **ADMixin** [M/lab] — AD methodology: Kerberos attack-class catalog (AS-REP
  roasting, kerberoasting, DCSync — names + detection), LDAP enum command sets,
  delegation notes.
- [33] **CloudMixin** [M/none] — AWS/Azure/GCP enum planners (scout suite, prowler,
  pacu), IAM blast-radius checklists, detection notes.
- [34] **ContainerMixin** [M/none] — container/escape surface planners, k8s RBAC
  misconfig checklist, container-security tool catalog.
- [35] **MobileMixin** [M/none] — APK/IPA static+dynamic methodology (mobsf, objection,
  jadx), frida notes.
- [36] **Wireless depth** [M/lab] — monitor-mode capture plans, rogue-AP playbook,
  WPA methodology + detection pairing (extends the wireless playbook).
- [37] **OSINTMixin** [S/none] — domain/email/persona enum catalogs
  (theHarvester/amass/spiderfoot/maltego).
- [38] **ForensicsMixin** [S/none] — volatility/fls/exiftool analyst workflows +
  evidence-handling rules.
- [39] **MalwareAnalysisMixin** [M/none] — static-first methodology
  (binwalk/strings/yara), detonation sandbox-only gate.
- [40] **NetworkDeviceMixin** [M/lab] — router/switch/firewall enum + config-audit
  command sets.
- [41] **API-SecurityMixin** [M/none] — REST/GraphQL planners (arjun/kiterunner),
  spec-driven checks, auth-surface catalogs.
- [42] **SocialEngMixin** [M/lab] — phishing/impersonation SIMULATION planners with
  consent gates + SOC watch pairing (lab-only by policy).
- [43] **ICS/IoT mixin** [M/lab] — modbus/S7 enum planners, IoT firmware flow
  (binwalk tie-in), air-gapped lab requirement.
- [44] **PostExploitMixin** [M/lab] — post-enumeration strategy (credential-access
  classes, lateral skeleton) with evidence-only policy.
- [45] **WebAuthMixin** [M/none] — SSO/OAuth/JWT surface method plans (token storage,
  redirect validation) planner-level.
- [46] **Contract-analysis mixin** [L/lab] — static analyzer catalog (slither/mythril),
  testnet-only policy.
- [47] **web_pentest phases 9-12** [M/none] — business-logic, supply-chain/SBOM,
  privacy/PII exposure, regulatory mapping to STIG baselines.
- [48] **WEB_VULN_CLASSES +10** [M/none] — deserialization, XXE, race conditions,
  prototype pollution, IDOR, request smuggling, cache poisoning, WebDAV traversal,
  GraphQL, DNS-rebinding SSRF.
- [49] **Per-CMS catalogs** [M/none] — WordPress/Drupal/Joomla/typo3-specific enum
  flows beyond wpscan/wpscan-audit.
- [50] **plan_full_engagement** [M/none] — compose recon → web → xss → privesc into
  one ordered plan with shared scrubbed context.

## C. Execution-safety layer — 15 options

- [51] **Engagement RBAC roles** [M/none] — operator / observer-only / verify-only
  roles enforced in execute_tool beyond the numeric levels.
- [52] **Expiry sweeper** [S/none] — stale engagement authorizations auto-revoked +
  audited.
- [53] **Blast-radius classifier** [M/none] — tag commands (read/scan/exploit-class);
  exploit-class requires elevated authorization + lab staging.
- [54] **Per-target rate limiting** [S/none] — sliding-window cap per (tool, target)
  with audit events.
- [55] **Egress guard** [M/none] — every network-touching command's target resolved;
  RFC1918 requires lab staging; external requires the authorization tag.
- [56] **Credential vaulting** [M/none] — creds via the secrets store, read at
  exec-time, never CLI args (hydra/msf paths).
- [57] **Immutable audit chain** [S/none] — hash-chained audit jsonl + verify op.
- [58] **Rollback requirements** [M/none] — mutating executions declare an undo step
  recorded in the audit trail.
- [59] **Sandbox profile** [M/none] — seccomp/apparmor profile + a doctor check that
  critical tools run sandboxed.
- [60] **Consent gate** [M/none] — non-dry-run executions require an owner-signed
  consent record (generalize v4's evidence discipline to the registry agents).
- [61] **Safe-mode proof** [S/none] — a test that safe_mode truly blocks mutation
  commands (verify current semantics; fix if they don't).
- [62] **Budget/quota** [S/none] — daily execution budget + cost budget for
  API-using tools, surfaced in status.
- [63] **Staging verification** [S/none] — targets verified inside the lab range
  (pve-lab 10.10.10.0/24) before scan classes; prod-LAN hits warned.
- [64] **Doctor tool-version matrix** [S/none] — installed versions vs a pinned
  matrix; drift flagged.
- [65] **Dry-run parity test** [S/none] — dry-run mirrors the would-be command string
  exactly and writes nothing.

## D. SOC / fleet tie-ins — 15 options

- [66] **Wazuh findings bridge** [M/none] — the SOC's alert findings → per-finding
  verification plans from the matching engine; ticket-ready.
- [67] **kevstig router bridge** [M/none] — daily routed-KEV CVEs → matching +
  exploit recommendations as a scheduled job.
- [68] **Aging-exploitable queue** [M/none] — patch-monitor ages × exploit
  availability = the priority report (what is old, unpatched, and exploitable).
- [69] **Tickets bridge** [M/none] — engagements auto-create/close remediation
  tickets through the existing soc-tickets flow.
- [70] **Remediation-ticket integration** [S/none] — failed lab verifications open
  tickets via the soc-remediation-tickets skill.
- [71] **laya double-check** [L/none] — laya's escalated decisions get independent
  verification plans from the kali agent.
- [72] **STIG-coverage gap report** [M/none] — maintained baselines (stig-baselines)
  × fleet scan state = which baselines lack agent coverage; per-STIG-control-family
  templates.
- [73] **Newsroom threat feed** [S/none] — curated security stories parsed into a
  daily threat-brief input for planners.
- [74] **Healthcheck row** [S/none] — the SOC healthcheck gains a kali-agent
  op-presence check.
- [75] **Engagement → SOC memory** [S/none] — summaries pushed into the SOC memory
  store under the tenant (the memory bridge exists).
- [76] **Fleet test harness** [L/lab] — compose profile: SOC sidecars + a
  vulnerable-app farm for repeated battery runs.
- [77] **Report email bridge** [S/none] — engagement reports via the
  reports@bedimsecurity.com plumbing; owner-notified on battery completion.
- [78] **Lab detection loop** [L/lab] — enroll a pve-lab target in Wazuh: exploit
  battery runs then produce REAL detection evidence (exploit → detection observed).
- [79] **Registry/doc sync** [S/none] — every mixin land updates AGENT_MATRIX.md,
  agent cards, and registry descriptions in the same commit.
- [80] **Appliance CVE corpus** [M/lab] — extend matching with the KEV appliance set
  (vCenter/ESXi, Citrix, BIG/IP, Ivanti...) for lab-only appliance tests.

## E. Evidence / reporting / knowledge — 10 options

- [81] **Report assembler op** [M/none] — executions + findings + parser outputs →
  one themed markdown/HTML report (the site's report template).
- [82] **Evidence bundler** [S/none] — per-engagement tar + manifest + sha256
  (generalize v4's EVIDENCE_PACKAGE).
- [83] **Timeline builder** [S/none] — audit events → attack-path chronology.
- [84] **IOC extractor** [M/none] — executions/outputs → clean IOC list + SOC feed.
- [85] **Retest diff op** [M/none] — two runs vs the same target → findings churn.
- [86] **Screenshot capture** [M/none] — headless-browser evidence for web findings
  (the playwright-on-thing1 recipe).
- [87] **Tool KB** [M/none] — per-tool in-house one-pagers (command patterns,
  false-positive notes) as generated data.
- [88] **No-orphan-numbers gate** [S/none] — every report number traces to an
  execution/parser source.
- [89] **Severity calibration** [M/none] — findings cross-checked against CVSS + the
  SOC's deterministic severity rules (the laya module's rules).
- [90] **Publishable redaction path** [M/none] — scrubbed report versions via the
  site's capabilities pipeline (owner-gated).

## F. Ops / deploy / UX — 10 options

- [91] **Kali-package doctor** [S/none] — every KALI_TOOLS_DB binary verified
  present on the host; per-tool presence rows.
- [92] **CLI ergonomics** [S/none] — convenience wrappers in cli.py:
  `agenticai kali <tool> ...` style chaining.
- [93] **Cards/matrix sync** [S/none] — agent cards + /team/ + AGENT_MATRIX.md
  updated by the same gate that forces registry-driven regeneration.
- [94] **Secrets-store wiring** [M/none] — agent credentials via the OpenClaw
  secrets pattern (masked flows), not env/args.
- [95] **pve-lab battery target** [M/lab] — a pve-lab node as the standard battery
  target with snapshot-reset between runs.
- [96] **Reproducible kali profile** [M/none] — Dockerfile (kali-rolling) + pinned
  tools for CI batteries.
- [97] **CI matrix** [M/none] — suite in GitLab CI; the lab battery an executor job
  marked manual.
- [98] **Plan explorer** [M/none] — rich REPL browsing plans/ops without execution
  (the v4 dashboard pattern).
- [99] **Skill sync** [S/none] — kali-agent/agentic-roles skills updated with the
  battery + runbook references.
- [100] **Owner dashboard widget** [M/none] — one-glance status: suite state, CVE-DB
  coverage %, last battery run, evidence count.

## Where each lives

- Mixins/catalogs/tests: `agentic_ai/agents/cyber/`, `tools/`, `tests/` (this repo).
- v4 work: `kali_agent_v4/` (the CLI generation; evidence discipline).
- Fleet tie-ins: SOC scripts (`scripts/soc/`), the tickets/healthcheck/bridges.
- Lab work: the pve-lab cluster (gus2) for staged targets.

_Owner gates: everything lab/live stays owner-signed; planner-only items ship on
the standing rules (planners never execute; scrubbers + guards everywhere; tests
pin safety). Suggested first wave: Quick pick above._