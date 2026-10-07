# docker/fleet-harness - the fleet test harness (KA-076 / OPT-76)

Compose profile + owner-run driver for REPEATED lab battery runs: a
vulnerable-app farm plus the SOC sidecar slice, alongside the original
docker/lab-targets trio (KA-009).

LAB BOUNDARY: everything here is intentionally vulnerable and lab-only;
never run it against an exposed or production network. Owner-gated
consent flows through environment gates (KA_FLEET_HARNESS=1); the test
suite never executes any of this (compose + script are committed DATA
the tests only parse; nothing starts in CI - there is no CI for the
harness, by design).

## Files

- `docker-compose.fleet-lab.yml` - the compose: two opt-in profiles
  (`fleet-farm`, `fleet-soc`); a bare `up` starts NOTHING.
- `harness.sh` - the driver: `help|status|up|down|reset|run|evidence`;
  state-changers demand the gate; `run lab` saves evidence with a sha256
  manifest.
- `README.md` - this file.

## The farm (profile `fleet-farm`) - host ports 8191-8194

| service | host:container | image (verified 2026-10-06) | battery surface |
|---|---|---|---|
| farm-httpd | 8191:80 | httpd:2.4.49 | path-traversal/RCE class (CVE-2021-41773/42013 shape) |
| farm-solr | 8192:8983 | solr:8.2.0 | velocity RCE + Log4Shell class (44XXX matching surfaces) |
| farm-wp-old | 8193:80 | wordpress:5.8.1-apache (db: mariadb:10.6) | legacy CMS CVE matching |
| farm-redis | 8194:6379 | redis:5.0.14 | unauth cache / postexp chain surfaces |
| farm-oob | none | python:3.11-alpine (`python3 -m http.server 8195`) | OOB/SSRF callbacks: `oob.fleet.example` |

Host aliases (on the shared lab network): `<service>.fleet.example` per
service, `oob.fleet.example` for the catcher. The callback catcher is
HTTP-only; DNS-level OOB stays a pve-lab matter (KA-095).

## The SOC slice (profile `fleet-soc`)

| service | ports | image | role |
|---|---|---|---|
| soc-wazuh-manager | none published | wazuh/wazuh-manager:4.7.0 | agent-enrollment plane for lab targets (1514/1515 + API 55000, internal to the lab network) |

The indexer (wazuh/wazuh-indexer:4.7.0) is DOCUMENTED, NOT DEPLOYED: a
clean start needs cert/config scaffolding that belongs to the
detection-loop task (KA-078's owner playbook). The compose carries it as
a comment so the tie-in stays visible and test-pinned.

## Gates (env)

| gate | owned by | meaning |
|---|---|---|
| `KA_FLEET_HARNESS=1` | KA-076 tests + this driver | deliberate harness consent (tests stay skipped without it; the driver's state-changers refuse without it) |
| `KA_LAB_BATTERY=1` | KA-009 tests | the lab-targets live half |
| `BRUTEFORCE_E2E=1` | SOC e2e test | the benign brute-force pipeline |

Gate semantics: raising `KA_FLEET_HARNESS=1` does NOT start anything by
itself. With the gate raised but the farm down, the up-state tests SKIP
with the repair hint (`harness.sh up farm`) instead of failing - the
harness's own `run lab` flow guarantees the farm is up first. Without
any gate, the whole file skips cleanly (the default everywhere).

## Quickstart (owner)

```
# shared lab network (or let harness.sh create the placeholder)
docker compose -f docker/lab-targets/docker-compose.yml up -d
docker/fleet-harness/harness.sh up farm
docker/fleet-harness/harness.sh run lab    # gates + farm + evidence
docker/fleet-harness/harness.sh reset      # fresh DB state between runs
docker/fleet-harness/harness.sh down
```

`harness.sh run lab` = gate check → farm up (idempotent) →
`pytest tests/lab` with `KA_LAB_BATTERY=1 KA_FLEET_HARNESS=1` →
`evidence/<UTC stamp>/battery.log` + `manifest.sha256`.

## Evidence

`evidence/` is RUNTIME output (created by `run lab`, untracked by
design); the tar+manifest bundling generalizes the evidence discipline
later (KA-082). The pytest python env is the owner's (the active venv);
the driver calls `python3 -m pytest` from the repo root.

## Ties

- KA-009 `docker/lab-targets`: the original trio (8181-8183) and the
  parity battery this harness amplifies with fresh surfaces.
- KA-095: pve-lab target with snapshot-reset = the live-metal analog of
  `harness.sh reset`.
- KA-096: reproducible kali profile = the future runner image for these
  batteries (the drivers stay host-side until then).
- KA-078: detection loop = enrolling lab targets into the wazuh slice
  (real detection evidence; the manager sidecar is its landing zone).
- KA-029/KA-080: the farm's CVE classes are matching surfaces for the
  exploit/corpus work.
- KA-059: the external-network join + opt-in profile posture copied
  here (deny-by-default, start-clean).

## Maintenance

Image tags were verified live against Docker Hub at write time
(2026-10-06). Bump a tag in the compose AND the `IMAGES` pin in
`tests/lab/test_fleet_harness.py` in the same task - the pin is the
drift alarm, not a decoration. Ports 8181-8183 stay reserved for
KA-009; this harness owns 8191-8194.
