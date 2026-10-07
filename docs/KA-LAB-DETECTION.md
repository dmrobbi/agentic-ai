# KA lab detection - the wazuh enrollment + detection-loop playbook (KA-078)

**OWNER-GATE: this playbook mutates the lab target (package install + service
enable + a real failed-ssh attack) — `--enroll` refuses without
`KA_LAB_CONSENT=1`; the attack steps are gated by the same judgment.**
`--check`/`--verify` are read-only. Nothing in the CI suite executes any of
this; the agentic-ai suite keeps to planners, fixtures, and stubs (see
CI discipline at the bottom).

**Sibling playbook:** `docs/KA-LAB-TARGET.md` (the battery target + its
consent gate + reset machinery). This doc is the detection twin of that one:
same target, one more layer — enroll the target in the SOC's Wazuh, then let
a battery run produce REAL detection evidence.

## What the loop is

OPT-78's normative line: enroll a lab target in Wazuh so exploit battery runs
then produce REAL detection evidence — attacker-side action → the target's
sshd logs it → the wazuh agent ships it → the manager's ruleset raises the
expected rule → the kali agent's SOC findings bridge
(`agentic_ai/agents/cyber/soc_bridge.py`, KA-066) turns the alert row into a
per-finding verification plan. One loop = one attack → one detection → one
plan.

## Contract (placeholders only — set the real values from your own inventory)

192.0.2.x addresses are documentation-range placeholders. Every endpoint
below arrives through env/flags (the helper hardcodes none):

| placeholder | meaning |
|---|---|
| `<LAB-HOST>` | the host that runs the qemu battery target (the battery playbook's tier host) |
| `<LAB-TARGET-ADDR>:<LAB-TARGET-PORT>` | the target's ssh endpoint as seen from an attacking host |
| `<KALI-HOST>` | the host the kali agent runs on (runs the attack + the bridge step; needs `sshpass`) |
| `<SOC-HOST>` | the host running the wazuh docker stack |
| `<WAZUH-MANAGER-CONTAINER>` | the wazuh-manager container name on `<SOC-HOST>` |
| `<WAZUH-MANAGER-IP>` | the manager's address as seen FROM THE TARGET (enrollment target) |
| `<LAB-TARGET-HOST>` | the target's hostname (the agent's name on the manager) |

The lab key, hostfwd ports, and the reset machinery are the battery
playbook's — re-verify those facts there before trusting.

## Ground truth (verified live 2026-10-06 on the SOC stack; re-verify before trusting)

- SOC manager: docker wazuh stack, **v4.14.8**
  (`docker exec <WAZUH-MANAGER-CONTAINER> /var/ossec/bin/wazuh-control info`).
- Agent package: `https://packages.wazuh.com/4.x/yum/wazuh-agent-<ver>-1.x86_64.rpm`
  — the 4.14.8 rpm returned HTTP 200. Keep the agent version EQUAL to the
  manager's version.
- Enrollment (authd): port **1515/TCP**, `<use_password>no</use_password>` on
  this fleet (the manager's `<auth>` block). The helper still carries
  `WAZUH_REGISTRATION_PASSWORD` for managers that demand one (stored on the
  agent at `/var/ossec/etc/authd.pass`, 640, root:wazuh — the installer's
  own handling).
- Agent reporting: port **1514/TCP**.
- The rpm packages NO ossec.conf — the installer generates one. On any
  systemd distro (the battery target is one) it adds
  `<log_format>journald</log_format>` collection and SKIPS the
  `[!journald]`-marked plain-file rows; without journald it collects the
  plain files (on the redhat family: `/var/log/secure`). sshd events flow on
  EITHER path, so the loop below works regardless of rsyslog.

## Rules the loop exercises

Verified in the manager's ruleset (`0095-sshd_rules.xml` of the v4.14.8
stack, 2026-10-06; re-verify after upgrades):

| rule id | level | trigger | when it fires |
|---|---|---|---|
| 5706 | 6 | `Did not receive identification string from` | a TCP connect to 22 closed without an ssh banner (a plain `nmap -sT -p 22` probe) |
| 5716 | 5 | `^Failed\|` PAM auth error | each wrong password for a REAL username |
| 5760 | 5 | `Failed password\|Failed keyboard\|authentication error` | the same event class (companion decoder path) |
| 5710 | 5 | `illegal user\|invalid user` | each attempt with a NON-existent username |
| **5712** | **10** | frequency=8 / timeframe=120 on 5710, same source ip | 8+ invalid-user failures from one source in 120s — THE expected detection |
| 5720 | 10 | frequency=8 on 5716 | 8+ failed passwords for real usernames from one source (the benign-script path) |
| 5763 | 10 | frequency=8 / timeframe=120 on 5760 | the 5760-stream's brute-force correlation |
| 5715 | 3 | ssh auth success | the normal-traffic noise the attack sits next to |

Severity mapping for the bridge step = the fleet's own
(`agentic_ai/infrastructure/wazuh_client.py::map_level_to_severity`, pinned
by tests): below 4 informational; 4–6 low; 7–9 medium; 10–12 high; 13+
critical. A level-10 detection → severity **high**.

## Step 0 — preflight (read-only)

ON `<LAB-HOST>` (repo checked out; run from the repo root):

```
scripts/lab/pve-lab-battery.sh --check      # the battery target tier (exit 0 = green)
scripts/lab/enroll-wazuh.sh --check         # adds the wazuh tier
```

Expected (second call):

```
[enroll] OK host tier (key present)
[enroll] OK target tier (hostname '<LAB-TARGET-HOST>' via 127.0.0.1:2226)
[enroll] INFO: wazuh-agent not installed yet (expected before --enroll)
[enroll] WARN: manager tier skipped (set WAZUH_MANAGER_ADDR for the full check)
[enroll] CHECK-OK (read-only preflight green)
```

With `WAZUH_MANAGER_ADDR=192.0.2.10` set (plus `--manager` flag) the manager
tier probes authd port 1515 FROM the target
(`timeout 3 bash -c '</dev/tcp/.../1515'`) and must read
`OK manager tier (authd port 1515 reachable from the target)`. A FAIL here =
routing/firewall first, agent second — do not enroll against a broken tier.

## Step 1 — enroll (owner gate)

ON `<LAB-HOST>`:

```
KA_LAB_CONSENT=1 WAZUH_MANAGER_ADDR=192.0.2.10 \
  scripts/lab/enroll-wazuh.sh --enroll
```

(192.0.2.10 = `<WAZUH-MANAGER-IP>` as seen from the target. Fresh install =
the wazuh docs' env-driven deployment
(`WAZUH_MANAGER`, `WAZUH_MANAGER_PORT`, `WAZUH_REGISTRATION_PORT`,
`WAZUH_REGISTRATION_PASSWORD`, `WAZUH_AGENT_NAME` — empty values degrade to
the installer's defaults). Re-run = reconfigure in place (the helper seds
the `<address>`, `<manager_address>`, and port tags, then restarts) —
idempotent.)

Expected console (fresh install; trimmed to the informative lines):

```
[enroll] consent ok (KA_LAB_CONSENT=1)
[enroll] OK host tier (key present)
[enroll] OK target tier (hostname '<LAB-TARGET-HOST>' via 127.0.0.1:2226)
[enroll] enroll step: install-or-reconfigure + start (timeout 300s; package https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.8-1.x86_64.rpm)
install: https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.8-1.x86_64.rpm
service: active
journald localfile blocks: 1
[enroll] ENROLL-DONE - verify with --verify, then the playbook's manager-side steps (docs/KA-LAB-DETECTION.md)
```

`service: active` is the agent-side half of the proof; `ossec.log tail`
should show the enrollment completing with INFO lines and no ERROR.

Gate refused without consent:

```
[enroll] REFUSED: --enroll needs KA_LAB_CONSENT=1 (owner gate; see docs/KA-LAB-DETECTION.md)
```

(exit 2 — the same gate discipline as the battery playbook's
`KA_BATTERY_CONSENT`.)

## Step 2 — the manager saw the enrollment (ON `<SOC-HOST>`, read-only)

```
docker exec <WAZUH-MANAGER-CONTAINER> /var/ossec/bin/agent_control -l
```

Expected (shape; placeholder values):

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: <WAZUH-MANAGER-NAME> (server), IP: 127.0.0.1, Active/Local
   ID: <ID>, Name: <LAB-TARGET-HOST>, IP: any, Active
```

The registration moment also lands in the manager's ossec.log:

```
2026/10/06 <hh:mm:ss> wazuh-authd: INFO: Received request for a new agent (<LAB-TARGET-HOST>) from: 192.0.2.20
```

Duplicate names are REJECTED (`WARNING: Duplicate name '<x>', rejecting
enrollment. Agent '<nnn>' key already exists on the manager.`) — that is the
ground for the reset-cycle remedy in step 6.

## Step 3 — the attack (FROM `<KALI-HOST>`; needs sshpass)

The kali agent plans all three tools used here (`nmap`, `hydra`, sshd
probes). Two deterministic attacker-side actions against the target:

**(a) the scan probe** (single-shot, fires rule 5706 within seconds):

```
nmap -sT -p <LAB-TARGET-PORT> <LAB-TARGET-ADDR>
```

**(b) the marker brute force** (the rule-5712 path; the per-run username
marker is the house pattern from `scripts/soc/benign_ssh_bruteforce_test.py`
— it makes OUR alert identifiable among normal fleet noise):

```
marker="brf-$(openssl rand -hex 3)"
for i in $(seq 1 12); do
  sshpass -p 'w4ng-Passw0rd' ssh -p <LAB-TARGET-PORT> \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 \
    "${marker}-${i}@<LAB-TARGET-ADDR>" true 2>/dev/null || true
done
```

12 invalid-user attempts complete in well under the 120s correlation
window; each fires rule 5710, so rule **5712** raises on the 8th attempt
from the same source ip. The same loop against a REAL username (e.g.
`root@`) produces 5716 events instead → rule 5720 raises on the 8th.

`sshpass` is the same prerequisite the e2e gate documents
(`which sshpass || install it with your package manager`).

Timing note: the correlated sshd rules suppress repeats for 60s
(`ignore="60"`) — re-running the loop within a minute will NOT mint a new
level-10 row; wait it out between loops.

## Step 4 — the manager raised the expected rule (ON `<SOC-HOST>`, read-only)

```
docker exec <WAZUH-MANAGER-CONTAINER> sh -c 'grep -h "\"id\":\"5712\"" /var/ossec/logs/alerts/alerts.json | tail -1'
```

Expected (shape; placeholder values — one jsonl row):

```
{"timestamp":"2026-10-06T22:10:31.410+0000","rule":{"level":10,"description":"sshd: brute force trying to get access to the system. Non existent user.","id":"5712","mitre":{"id":["T1110"]},"firedtimes":8,"mail":false,"groups":["syslog","sshd","authentication_failures"],...},"agent":{"id":"<ID>","name":"<LAB-TARGET-HOST>","ip":"192.0.2.20"},"manager":{"name":"<WAZUH-MANAGER-NAME>"},"id":"<epoch>.<millis>","full_log":"Failed password for invalid user brf-<marker>-12 from 192.0.2.5 port 51024 ssh2","predecoder":{"program_name":"sshd","timestamp":"Oct 06 22:10:29","hostname":"<LAB-TARGET-HOST>"},"data":{"srcip":"192.0.2.5","srcuser":"brf-<marker>-12",...}}
```

The marker from step 3b appears in `srcuser`/`full_log` — that is how you
know THIS loop minted this row. After (a), grep

```
grep -h "\"id\":\"5706\"" /var/ossec/logs/alerts/alerts.json | tail -1
```

expecting `"sshd: insecure connection attempt (scan)."`. After the real-user
variant, grep `-E '"id":"(5720|5763)"'`.

The SOC side reads these same rows from the `wazuh-alerts-*` index through
the dashboard/API — the opt-in e2e
(`tests/integration/test_ssh_bruteforce_e2e.py`, `BRUTEFORCE_E2E=1`, never
CI) asserts that longer chain: indexer reachability → SOC ingest → the
auto-incident path. This playbook stops at the manager + the bridge.

## Step 5 — the agent's findings bridge sees it (FROM `<KALI-HOST>`; repo on sys.path)

Map the 5712 alert row onto the KA-066 finding contract
(`id` ^[A-Za-z0-9_.-]{1,64}$; `severity` severity-word; `host` scrub-safe —
no spaces, no metacharacters; `summary` free text) using the fleet severity
mapping above (level 10 → high). The bridge is a PURE PLANNER: it never
executes anything; its steps are the owner's re-verification plan.

```
python3 - <<'PY'
from agentic_ai.agents.cyber.soc_bridge import SocFindingsVerifier
finding = {
    "id": "lab-detect-20261006-2210",   # unique per loop; <= 64 chars, [A-Za-z0-9_.-]
    "severity": "high",                 # rule.level 10 -> high (fleet mapping)
    "host": "<LAB-TARGET-HOST>",        # the agent name from the alert (example: lab-target.lab.example)
    "summary": "sshd: brute force trying to get access to the system. Non existent user.",
}
import json
print(json.dumps(SocFindingsVerifier().verify_findings([finding]), indent=2))
PY
```

Expected output (captured live 2026-10-06 from this exact call with the
synthetic-label host; the host string is echo-through, not a lookup):

```
{
  "planned": [
    {
      "finding_id": "lab-detect-20261006-2210",
      "severity": "high",
      "host": "lab-target.lab.example",
      "cve": null,
      "verification_steps": [
        "nmap -sV -sC -oX /tmp/lab-detect-20261006-2210-nmap.xml lab-target.lab.example"
      ],
      "notes": [
        "manual triage: 'sshd: brute force trying to get access to the system. Non existent user.' (severity high)"
      ]
    }
  ],
  "unplannable": [],
  "summary": {
    "total": 1,
    "planned": 1,
    "unplannable": 0,
    "with_known_cve": 0
  }
}
```

That `verification_steps` list is the loop's close: the SOC alerted, and the
kali agent already knows how it would re-verify the finding. Schema-violating
rows never crash the flow — they land in `unplannable` with reasons (the
bridge's pinned behavior); a finding whose `host` carries spaces or
metacharacters is rejected by the same scrub the planners use.

## Step 6 — evidence + the reset cycle

- Save the attack stdout, the alert rows, and the bridge JSON on `<KALI-HOST>`
  (or `<SOC-HOST>`), NOT on the target: the battery playbook's `--reset`
  rolls the target's disk to pristine, wiping the agent and anything stored
  there. Evidence discipline = the v4 engagement convention (reference the
  files from the engagement report).
- After every battery `--reset`, the enrolled agent is GONE — re-run step 1
  before the next loop. Because the manager keeps the previous enrollment
  (duplicate-name rejection, step 2), prefer a fresh agent name per cycle
  (`WAZUH_AGENT_NAME=lab-$(date +%m%d%H%M)`) or drop the stale registration
  first from `<SOC-HOST>`:
  `docker exec <WAZUH-MANAGER-CONTAINER> /var/ossec/bin/manage_agents -r <ID>`.

## CI discipline

This playbook is a MANUAL executor, like the battery one. Nothing here runs
in CI: no test executes the loop, and this task's Owns list carries no test
file on purpose — the suite's collect-only total is untouched by KA-078.
The offline twins around the loop stay in the suite instead:
`tests/test_soc_bridge.py` (the bridge schema), the
`map_level_to_severity` pins in `tests/test_wazuh_client.py`, and the
opt-in `tests/integration/test_ssh_bruteforce_e2e.py`. Gates: `KA_LAB_CONSENT=1`
enrolls (set by the owner, explicitly), alongside `KA_BATTERY_CONSENT` and
the established environment-gate table in `docs/KA-EXPLOIT-TESTS.md`.

## Related

- `docs/KA-LAB-TARGET.md` — the battery target + reset machinery (the sibling)
- `docs/KA-EXPLOIT-TESTS.md` — the environment-gate discipline table
- `docs/KA-BUILDING-CONVENTIONS.md` — the guardrails every builder reads
- `todo.md` — KA-078 (OPT-78), KA-066, KA-095 entries
- `scripts/lab/pve-lab-battery.sh` + `scripts/lab/enroll-wazuh.sh` — the two
  lab helper scripts
- `scripts/soc/benign_ssh_bruteforce_test.py` — the SOC fleet's live-fire
  driver (the real-user 5720 path + indexer/SOC-agent assertions)
- `agentic_ai/agents/cyber/soc_bridge.py` (KA-066) — the findings bridge
- `agentic_ai/infrastructure/wazuh_client.py` — the severity-mapping pin
