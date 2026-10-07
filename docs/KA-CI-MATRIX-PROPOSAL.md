# KA-097 · CI matrix proposal (suite gate + manual lab battery)

**Status:** PROPOSAL — builders never touch `.gitlab-ci.yml` (a shared fleet
file per docs/KA-BUILDING-CONVENTIONS.md §1); the `[INTEGRATION]` task applies
this block. The accepted todo entry, verbatim:

> [97] CI matrix [M/none] — suite in GitLab CI; the lab battery an executor
> job marked manual.
>
> **Owns:** `.gitlab-ci.yml` additions proposal (the integration task applies;
> the shared CI file = integration-reviewed)

This proposal owns exactly two files:
`docs/KA-CI-MATRIX-PROPOSAL.md` (this doc) and
`tests/test_ci_matrix_proposal.py` (the pinning test).

## The two jobs

| job | stage | runs | posture |
|---|---|---|---|
| `pytest-suite` | test | the FULL suite (`python3 -m pytest tests/ -q`) teed to a verdict log, plus the planner-purity slice (`pytest -k purity`, the `test_module_purity_source_scan` pins) teed separately; verdicts are read through the house grep filter, never tail | automatic on MRs + the default branch (`main`); `when: always` artifacts (verdict log + purity output), short expiry, generous timeout, small retry |
| `lab-battery` | lab | the KA-009 battery from `docker/lab-targets/README.md`: compose up → consent-gated `pytest tests/lab` → `down -v` (documented recipe) | MANUAL in every pipeline shape (`when: manual` in each
  rule), `allow_failure: false`; the consent value only ever comes from a
  protected CI/CD variable, never from this file |

Why the lab battery keeps the consent gate even though it is already
manual: the manual click is the owner's consent to RUN the executor, and
the protected variable is the consent VALUE — a manual run without it
aborts at the refusal line, so no click can reach the lab without consent.
CI only HOSTS the executor: docs/KA-EXPLOIT-TESTS.md's ordering rule (lab
batteries = owner-run, consent-gated procedures) stays the source of truth,
and the non-CI owner path (`docker/fleet-harness/harness.sh run lab`)
remains as documented. What the job buys over the shell runbook: the same
consent-gated battery with kept evidence (the teed `lab-battery.log`
artifact) and the documented teardown on every exit path.

## The EXACT yaml block to append to .gitlab-ci.yml

The fragment mirrors the root pipeline's house style
(`python:${PYTHON_VERSION}-slim` images, MR + `main` rules, artifacts with
`expire_in`, comment banner sections). It is self-contained so it lints
standalone; the `stages:` list inside it documents what it needs (the
integrator merges `lab` into the root stages list — the root list stays the
source of truth for the full file).

```yaml
# ============================================
# KA-097 additions (PROPOSAL block)
# Integrator note: merge `lab` into the root stages list; these two jobs
# own the test + lab stages only.
# ============================================
stages:
  - test
  - lab

# ============================================
# KA-097: the pytest suite gate
# ============================================
pytest-suite:
  stage: test
  image: python:${PYTHON_VERSION}-slim
  before_script:
    - apt-get update && apt-get install -y gcc
    - python -m venv venv
    - source venv/bin/activate
    - pip install --upgrade pip
    - pip install -r requirements.txt
  script:
    - cd "$CI_PROJECT_DIR"
    - set -o pipefail
    - python3 -m pytest tests/ -q 2>&1 | tee pytest-verdict.log
    - grep -E "[0-9]+ (passed|failed|error)" pytest-verdict.log
    - python3 -m pytest tests/ -q -k "purity" 2>&1 | tee purity-scan.log
    - grep -E "[0-9]+ (passed|failed|error)" purity-scan.log
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
  artifacts:
    when: always
    paths:
      - pytest-verdict.log
      - purity-scan.log
    expire_in: 1 day
  timeout: 30m
  retry:
    max: 2
    when: always

# ============================================
# KA-097: the KA-009 lab battery - MANUAL ONLY
# compose up -> consent-gated pytest -> down -v
# ============================================
lab-battery:
  stage: lab
  image: python:${PYTHON_VERSION}-slim
  services:
    - docker:29-dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  # The lab consent gate is a protected CI/CD variable (Settings > CI/CD >
  # Variables, marked Protected; Masked where GitLab allows), referenced
  # BY NAME below. NEVER inline its value in this file.
  before_script:
    - apt-get update && apt-get install -y gcc docker.io docker-compose-v2
    - python -m venv venv
    - source venv/bin/activate
    - pip install --upgrade pip
    - pip install -r requirements.txt
  script:
    - cd "$CI_PROJECT_DIR"
    # consent refusal FIRST: a manual run without the protected consent
    # variables aborts before anything lab-touching starts
    - test "${KA_LAB_BATTERY}" = "1"
    - docker info
    - docker compose version
    - docker compose -f docker/lab-targets/docker-compose.yml up -d
    - docker compose -f docker/lab-targets/docker-compose.yml ps
    - python3 -m pytest tests/lab -q 2>&1 | tee lab-battery.log
    - grep -E "[0-9]+ (passed|failed|error)" lab-battery.log
  after_script:
    # teardown ALWAYS: down -v is the documented reset between runs
    - docker compose -f docker/lab-targets/docker-compose.yml down -v || true
  rules:
    # manual in every pipeline shape: never automatic, only owner-clicked
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: manual
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  allow_failure: false
  artifacts:
    when: always
    paths:
      - lab-battery.log
    expire_in: 1 day
  timeout: 45m
```

## Integration instructions

1. Append the block above to `.gitlab-ci.yml` unchanged except for its
   `stages:` list: merge `lab` into the root `stages:` list
   (lint, test, build, security, deploy currently) — in the merged file the
   root list wins; the fragment redeclaration only keeps the standalone
   fragment linters and this proposal's pinning test green.
2. Owner setup for the consent gate (its VALUE never lives in the repo):
   GitLab Settings > CI/CD > Variables → create `KA_LAB_BATTERY` as a
   Protected variable (Masked where GitLab allows the value), value `1`.
   The lab job references it BY NAME only; the refused-run path
   (`test "${KA_LAB_BATTERY}" = "1"` aborting first) proves the gate is
   load-bearing, not decorative. `KA_FLEET_HARNESS` stays the consent for
   the NON-CI harness path (`harness.sh` + `run lab`), which this fragment
   deliberately does not touch.
3. Runtime detail review items, deliberately left to the integration pass:
   - the dind plumbing: the fragment sets `DOCKER_HOST`/`DOCKER_TLS_CERTDIR`
     explicitly; if the instance's runner config already provides dind
     variables (the root `build:` job carries none), drop them.
   - the base packages `docker.io` + `docker-compose-v2` from the slim
     base's Debian repos (client + compose plugin; verify against the
     actual slim release at apply time). The house `docker:29` job shape
     is the fallback if the apt route is rejected in review.
   - the `-k purity` slice definition (it runs the planner-purity
     source-scan pins) and the artifact expiry (`1 day` = short; nudge if
     the instance wants different).

## The pinning test

`tests/test_ci_matrix_proposal.py` extracts the doc's single ```yaml fence,
parses it when pyyaml is present (each parse-dependent test guards itself
with `pytest.importorskip("yaml")`), and asserts:

- `stages` declared: `test`, `lab`.
- `pytest-suite` exists: stage `test`, script runs
  `python3 -m pytest tests/ -q` teed to `pytest-verdict.log`, verdict read
  by the house grep filter, purity slice teed to `purity-scan.log`,
  MR + `main` rules, `when: always` artifacts for both logs, short expiry,
  generous timeout, retry max >= 1.
- `lab-battery` exists: stage `lab`, every rule `when: manual`,
  `allow_failure: false`, the compose up → pytest → `down -v` sequence and
  the consent-refusal line present.
- Consent gate referenced BY NAME only: no inline `GATE=1` form in the
  yaml; every `$` reference is an uppercase variable NAME.
- No secret VALUES: a forbidden-marker scan (token/password/key literal
  shapes) over the yaml text passes, plus a parsed-key walk (no
  secret-valued keys anywhere in the fragment).
- Without pyyaml, the regex-fallback test still pins the shape offline.

## Notes

- `pytest-verdict.log` / `purity-scan.log` / `lab-battery.log` are job
  artifacts, never tracked repo files.
- `-k purity` + `-q` keep the scan cheap; the full suite is the merge gate,
  the purity slice is the kept evidence artifact.
- Adding the 10 tests moves `BASELINE_SUITE_TOTAL` (4946 → 4956, tests/
  collect-only). This builder task is explicitly barred from
  `tests/test_ka_conventions.py`, so the landing shows exactly one suite
  failure — the stale pin — which the integration pass updates with these
  files in the same commit (suite-baseline discipline, conventions §6).