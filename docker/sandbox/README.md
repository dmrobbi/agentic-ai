# docker/sandbox - the fleet sandbox profile (KA-059)

DENY-BY-DEFAULT planner artifacts for containerized agent-tool execution.
Nothing here executes on its own: the profile is a POLICY (what a hardened
runtime must look like) plus a compose FRAGMENT (that policy expressed in
compose), both mounted and driven by the [INTEGRATION] task (KA-INT-4,
Phase-4 wiring). Parse-and-pin tests live in `tests/test_sandbox_docs.py`.

Owned by KA-059 (todo.md P4, safety layer). Tracker: `todo.md`.

## Files

- `sandbox-profile.yml` - the versioned posture MANIFEST (format 1):
  profile identity, the `default_deny` axes, the mounts/network/images
  ALLOWLISTS, egress posture, capability + security posture, service tiers,
  and the `doctor_checks` spec.
- `docker-compose.sandbox.yml` - the compose FRAGMENT implementing the
  manifest: two opt-in service tiers, zero bind mounts, zero published
  ports, entrypoint/command intentionally absent.
- `README.md` - this file: the format decision, the posture statement, the
  mounting shape, and the doctor-check spec (documentation, not
  implementation).

## Profile format

Planner decision, versioned: the profile = a YAML **manifest**
(`sandbox-profile.yml`, `format: 1`, `status: reviewed`) that names every
axis and allowlist, plus a YAML **compose fragment**
(`docker-compose.sandbox.yml`) that mechanically realizes the manifest's
runtime half. The manifest is the SOURCE OF TRUTH; the fragment must
reference only images/paths the manifest documents as existing-in-repo or
explicitly integration-mounted. Format changes bump `profile.format`.

## Deny-by-default posture

Every axis denies first; the only allow paths are the manifest's explicit
allowlists, honored when the integration mounts the profile:

- **mounts** - the fragment ships ZERO bind mounts; a mount the integration
  adds must match exactly one `mounts.allowlist` entry (read-only), or it is
  denied. Writable scratch is tmpfs `/tmp` only.
- **network** - the baseline tier runs `network_mode: none`; the only
  documented networked tier joins exclusively the allowlisted lab network.
- **capabilities** - `cap_drop: [ALL]` and nothing added back.
- **egress** - none, ever, from the profile itself (see Egress posture).
- **syscalls** - seccomp/apparmor stay on their docker-default filters;
  disabling or unconfining them is out of policy.
- **execution** - every service sits behind an opt-in compose profile, so a
  bare `docker compose -f docker-compose.sandbox.yml up` starts NOTHING; the
  integration decides WHAT to run (entrypoint/command stay unset here).

## Mountable compose fragment

The fragment is a compose-services fragment: an integration merges it
(`docker compose -f integration.yml -f docker/sandbox/docker-compose.sandbox.yml`
or compose `include`) and supplies exactly the things the manifest reserves
for it: the entrypoint/command, allowlist-gated read-only mounts, and env
values through the env-file contract (KA-056: credentials never as compose
literals or CLI arguments). The fragment provides the image
(`agentic-ai:latest`, built by the repo root `Dockerfile` via
`docker-compose.yml`) and this hardening set on BOTH tiers: non-root user
`65534:65534`, `read_only: true`, tmpfs `/tmp` (noexec/nosuid, 64 MiB),
`cap_drop: [ALL]`, `no-new-privileges:true`, `pids_limit: 256`,
`mem_limit: 2g`, `restart: "no"` (a dead sandbox stays dead). Tiers:

- `sandbox-runtime` (compose profile `sandbox`) - the baseline tier:
  no network at all.
- `sandbox-runtime-lab` (compose profile `sandbox-lab`) - the owner-gated
  lab tier: joins ONLY `lab-targets_default` (the network the
  `docker/lab-targets/docker-compose.yml` stack creates) and flags the run
  via the single allowlisted literal env `SANDBOX_EGRESS=lab-staged`.

## Egress posture

Consistent with the wave's egress guard semantics (KA-055,
`egress_guard.py`, network-command classification):

- **RFC1918 targets** - require lab staging: reachable ONLY through the lab
  tier joined to the lab-target network (owner-gated, the
  `docker/lab-targets` stack).
- **external targets** - require an auth tag: classified at the agent layer
  by the egress guard; the sandbox never opens external egress itself.
- **DNS** - `staging-only`: the baseline tier resolves nothing; with lab
  staging active, resolution happens only through the staged lab network.
  The agent-layer DNS-resolution strategy is documented by KA-055; this
  profile enforces the container-layer half (doctor check SBX-11).
- **gate order** - the sandbox sits under the composed gates
  (consent -> auth -> blast-radius -> egress -> rate-limit -> execute,
  KA-INT-4): a sandbox run still passes every gate before anything runs.

## Doctor-check spec

Documentation, not implementation: the MANIFEST carries the authoritative
list (`doctor_checks`, ids `SBX-01..SBX-12`, each with a `check` and an
`expected`) that a doctor tool verifies at run time against mounted
containers:

- SBX-01 seccomp filter active (never disabled) / SBX-02 apparmor profile
  active (never disabled) / SBX-03 no-new-privileges effective.
- SBX-04 running uid != 0 / SBX-05 rootfs read-only, only writable path the
  declared tmpfs / SBX-06 capabilities dropped to NONE with nothing added
  back.
- SBX-07 baseline tier has no interfaces beyond loopback / SBX-08 lab tier
  connected ONLY to the allowlisted lab network / SBX-09 no published ports.
- SBX-10 every host bind mount read-only and allowlisted / SBX-11 egress
  probe from the baseline tier fails (nothing resolves, nothing connects) /
  SBX-12 no credential literals in compose envs (KA-056 env-file contract).

A doctor implementation lands as its own task; this directory SPEC's the
checks so the integration can mount the profile and prove it.

## Test pins

`tests/test_sandbox_docs.py` pins, parse-only (no container execution, no
docker socket, no network): the exact dir layout; the README's required
sections (this list of H2 headings); the manifest's required top-level keys
and its deny-by-default statements (parsed and counted); the egress tier
semantics; the fragment's per-service hardening set and network posture;
the reference rule (images/paths exist in-repo or are documented
integration mounts); the doctor-check spec (structure + every id surfaces
in this README).