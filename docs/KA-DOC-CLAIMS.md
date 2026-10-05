# KA-DOC-CLAIMS.md - the kali claim matrix

Each documented kali-improvement claim mapped to the test that proves
it (KA-028). The untested claims are MARKED, not hidden. Every tested
row: the claim's verbatim source-text exists (grep-pinned) and the
named test exists in the suite (import-pinned).

| claim | source | proving test | tested |
|---|---|---|---|
| The web pentest plan is 12-phase | `skills/agentic-roles/references/role-ops.md` | `tests/test_kali_web_pentest.py :: test_plan_web_pentest_twelve_phases` | yes |
| The red-team catalog is 13 phases / ~725 tools | `skills/agentic-roles/references/role-ops.md` | `tests/test_redteam_ops.py :: test_catalog_structure` | yes |
| The XSS methodology plan is 7-phase | `skills/agentic-roles/references/role-ops.md` | `tests/test_xss_ops_extended.py :: test_plan_structure_and_contexts` | yes |
| Every execute_tool branch is pinned (the 29-branch matrix) | `tests/test_execute_tool_matrix.py` | `tests/test_execute_tool_matrix.py :: test_matrix_branch_checklist_documented` | yes |
| safe_mode blocks mutation-class tool categories | `agentic_ai/agents/cyber/kali.py` | `tests/test_safe_mode_semantics.py :: test_proposed_safe_mode_blocks_mutation_class` | yes |
| Engagement authorizations expire inside the execution path | `agentic_ai/agents/cyber/auth_expiry.py` | `tests/test_auth_expiry_enforcement.py :: test_at_expiry_boundary_revoked_in_execution_path` | yes |
| Dry-run output mirrors the would-be command exactly | `tests/test_dry_run_parity.py` | `tests/test_dry_run_parity.py :: test_dry_output_mirrors_built_command_exactly` | yes |
| Matching is version-blind (patched rows still match) | `tests/fixtures/cve/precision_cases.json` | `tests/test_matching_precision.py :: test_patched_rows_still_match_the_version_blindness` | yes |
| Evidence chains detect per-entry tampers without cascade | `agentic_ai/agents/cyber/evidence_chain.py` | `tests/test_evidence_chain.py :: test_tamper_detection_no_cascade` | yes |
| SOC findings never crash on schema violations | `agentic_ai/agents/cyber/soc_bridge.py` | `tests/test_soc_bridge.py :: test_unplannable_routes_never_crash` | yes |
| Replay parity derives everything from argument order | `agentic_ai/agents/cyber/replay_mode.py` | `tests/test_replay_mode.py :: test_replay_matches_current_behavior` | yes |
| 600+ penetration testing tools (the v1 docstring claim) | `agentic_ai/agents/cyber/kali.py` | `docs/KA-DOC-CLAIMS.md` | no - aspirational docstring: 52 v1 DB rows + 24 v2 rows + 740 cataloged links do not sum to 600; marked untested in this matrix, not hidden |
