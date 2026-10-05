# docker/lab-targets - the planner-parity battery's lab targets (KA-009)

INTENTIONALLY VULNERABLE containers for authorized lab use only. Not for
any exposed/host production network. The battery's live half is
OWNER-CONSENT-GATED (`KA_LAB_BATTERY=1` for the tests; the pve-lab
variant's owner-gate lives in docs/KA-LAB-TARGET.md).

## Services

| service | port | image | purpose |
|---|---|---|---|
| juice-shop | 8181 | bkimminich/juice-shop:latest | modern SPA attack surface |
| dvwa | 8182 | vulnerables/web-dvwa:latest | classic php vuln classes |
| wordpress | 8183 | wordpress:6.4-php8.2-apache + mariadb:10.6 | CMS flows |

## Bring up / reset / tear down

```
docker compose -f docker/lab-targets/docker-compose.yml up -d
# reset between runs: down -v && up -d (fresh database state)
docker compose -f docker/lab-targets/docker-compose.yml down -v
```

The password values are LAB-ONLY constants (they live in the compose
file; nothing here is secret). Host ports 8181-8183.

## The battery (tests/lab/test_planner_parity.py)

- The OFFLINE half runs everywhere: every argv[0] the planners emit is a
  KNOWN binary (the v1 tool-DB command rows + the documented infra set
  from the planner catalog) - a planned phantom binary = a battery
  failure, no docker needed.
- With `KA_LAB_BATTERY=1`: the docker targets must be up
  (`docker compose ps`) and the planners plan against the lab ports.
- Absent (CI and every other default): the two live tests SKIP cleanly;
  the offline battery still runs.

## Tie-ins

- pve-lab variant + owner-gate: docs/KA-LAB-TARGET.md (KA-095).
- The runbook: docs/KA-EXPLOIT-TESTS.md (KA-030).
