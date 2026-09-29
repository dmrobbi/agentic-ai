# Example payloads (verified 2026-09-29)

Every example below was executed against the CLI/registry before publishing.
CLI `agent run` invocations are stateless (a fresh instance per run) — single
op per call. Stateful multi-op flows go through Python (last example).

## security: code scan (CLI, no LLM needed)

```bash
agenticai agent run security --op scan_code \
  --args '{"code": "password = \"hunter2\"\napi_key = \"sk_live_abc123\""}'
```

Returns `SecurityFinding` objects (`hardcoded_secrets`, `HARDWARE_SECRETS`
CWE-798, severity HIGH, line numbers, recommendation).

## developer: task dispatch (CLI, perform_task agent)

```bash
agenticai agent run developer --task implement \
  --payload '{"feature": "login rate limiter", "language": "python"}'
# -> {"status": "implemented", "feature": "...", "implementation": "..."}
```

`--payload` keys are the target method's kwargs (`implement` →
`implement_feature(feature=..., language=...)`); wrong keys surface the
agent's real signature in the error.

## compliance: register a regulation (CLI)

```bash
agenticai agent run compliance --op add_regulation \
  --args '{"name": "GDPR", "framework": "GDPR", "jurisdiction": "EU"}'
# -> Regulation(regulation_id=..., status=NOT_ASSESSED, ...)
```

## data_analyst: stateful flow (Python - CLI runs are per-invocation stateless)

```python
from agentic_ai.agents.registry import create_agent

a = create_agent("data_analyst")
ds = a.register_dataset(name="demo", source="inline", columns=["value"])
a.load_data(ds.dataset_id, [{"value": float(x)} for x in [1, 2, 3, 4, 5, 6, 7, 8, 9]])
print(a.calculate_statistics(ds.dataset_id, "value"))
# -> {'mean': 5.0, 'median': 5.0, 'std_dev': 2.582, 'p25': 3.0, 'p95': 8.6, ...}
```

## Discovering everything else

```bash
agenticai agent list          # all ids
agenticai agent card <id>     # dry-run instantiation
agenticai agent ops  <id>     # op menu with Source (role module vs base)
```

Ops whose docstrings mention real systems (kali/redteam tooling, cloud
connectors) require those systems; the dry-run commands never do.