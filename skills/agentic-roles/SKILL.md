---
name: "agentic-roles"
description: "Use when running, inspecting, or integrating any of the 35 role agents in the agentic-ai fleet (security, compliance, developer, chaos, cyber agents) from the CLI, tests, or automation."
---

# Agentic Roles — running the agent fleet

Every agent in `agentic_ai/agents/` is instantiable with zero setup and
usable through one CLI surface:

```bash
agenticai agent list                        # the registry: id, class, category
agenticai agent card <id>                   # instantiate + agent card, no side effects
agenticai agent ops  <id>                   # op menu (Source column: role vs base)
agenticai agent run  <id> --op <op> --args '{"...": "..."}'
agenticai agent run  <id> --task <type> --payload '{...}'   # agents with perform_task
```

The registry of truth is [agentic_ai/agents/registry.py] and the generated
per-agent op menu is [references/role-ops.md](references/role-ops.md).
Verified usage examples (all executed before publishing) live in
[references/example-payloads.md](references/example-payloads.md).

## Steps

1. Discover: `agenticai agent list`, then `agenticai agent card <id>` (never
   requires an LLM) and `agenticai agent ops <id>`. `card` and `ops` are the
   dry-run layer — instantiation only. Done when you can name the op.
2. Run an op: `agenticai agent run <id> --op <op> --args '{"key": "value"}'` —
   built-in domain ops need no inference engine. Constructor kwargs go to
   `--params`. Methods that are coroutines are awaited automatically;
   output is JSON. Errors print the underlying message, not a stack trace.
3. Task dispatch on the 6 agents with `perform_task` (developer, finance,
   lead, qa, sales, sysadmin): the payload IS the target method's kwargs
   (`--task implement --payload '{"feature": "...", "language": "python"}'`
   → `implement_feature(**payload)`). Wrong keys surface the agent's real
   signature in the error.
4. From Python: `from agentic_ai.agents.registry import create_agent,
   list_agents, resolve_agent_class` — `resolve_agent_class` is lazy; the
   registry never imports an agent module until asked.
5. Tests: `tests/test_registry.py` pins that every registered id resolves
   and instantiates plus an end-to-end scan op. Run the suite (fast, ~8 s)
   after touching any agent module.
6. Aliases (`chaos`→`chaos_monkey`, `vendor`→`vendor_risk`, `cloud`→
   `cloud_security`, `ml`/`mlops`→`ml_ops`) keep older call sites working.

## Notes

- The registry is the only source of truth for agent ids — never hardcode an
  agent list (the old CLI listed a `product` agent that never existed and
  omitted the biblical_scholar and V2 cyber agents).
- Ops that hit real systems (kali/redteam tooling, cloud connectors) say so
  in their op docstrings; everything in `card`/`ops`/`list` is side-effect-free.
- The kali family has its own skill: [agentic-ai/skills/kali-agent](../kali-agent/SKILL.md).

## House rules

- New agents get a registry entry at birth; `agent list` is generated, so the
  matrix in docs/AGENT_MATRIX.md is regenerated from the registry, not by hand.
- Fix latent enum/attribute defects at the point of use — an agent that cannot
  instantiate is a critical finding, not a quirk (biblical_scholar shipped
  with four unusable enum references; fixed 2026-09-29).