# SOC end-to-end live test (benign SSH brute-force)

This script verifies the full **Wazuh → OpenSearch indexer → SecurityOperationsAgent** pipeline by firing real bad-password SSH attempts at a Wazuh-monitored host and asserting the resulting brute-force alert is picked up by the SOC poller.

## When to run this

- After any change to `agentic_ai/agents/cyber/soc.py` (ingest path)
- After any change to `agentic_ai/infrastructure/wazuh_client.py` (indexer client / poller)
- After upgrading Wazuh manager or indexer
- After changing rule 5551 / 5760 / 5763 / 5720 (the SSH brute-force correlation rules)
- Before each major release as a smoke test
- After a suspected incident to confirm the SOC pipeline is still catching live attacks

## Prerequisites

1. **Wazuh manager + indexer reachable** at `127.0.0.1:9200` (or override with `WAZUH_INDEXER_URL`)
2. **A target host where:**
   - sshd accepts password auth (`sshd_config: PasswordAuthentication yes`)
   - The Wazuh agent is enrolled and reporting
   - sshd logs go to either `auth.log` or journald (the agent must read it)
   - A real local user account exists (the test logs in as a real user with wrong password)
3. **sshpass** installed on the test runner: `apt-get install -y sshpass`
4. The test runner can reach the target on TCP/22

## Run it

```bash
# Default target = target-host (192.0.2.151, agent 004)
python3 scripts/soc/benign_ssh_bruteforce_test.py --attempts 12 --timeout 120

# Custom target
python3 scripts/soc/benign_ssh_bruteforce_test.py \
    --target 192.0.2.151 \
    --user demo-user \
    --attempts 10 \
    --timeout 90
```

Expected output:
```
[*] firing 12 bad-password attempts at 192.0.2.151 as user=demo-user
[*] 12/12 attempts failed-as-expected
[*] polling Wazuh indexer for level>=10 SSH alert from 192.0.2.151 as user=demo-user ...
[OK]   Wazuh alert seen: rule=5551 level=10 PAM: Multiple failed logins in a small period of time.
       timestamp=2026-08-03T20:19:15.118Z
       agent=target-host
[*] running SecurityOperationsAgent.ingest_wazuh_alert on the alert...
[OK]   ingested: +1 alert(s), +1 incident(s), severity=high
[ALL GOOD] benign brute-force → Wazuh → SOC pipeline verified end-to-end.
```

## Run via pytest

`tests/integration/test_ssh_bruteforce_e2e.py` wraps the script as an opt-in integration test:

```bash
# Run it (auto-skips if sshpass or Wazuh are missing)
python3 -m pytest tests/integration/test_ssh_bruteforce_e2e.py -v

# Opt out without removing the test
BRUTEFORCE_E2E=0 python3 -m pytest tests/integration/test_ssh_bruteforce_e2e.py -v

# Custom target / attempts / timeout via env
BRUTEFORCE_TARGET=192.0.2.151 \
BRUTEFORCE_ATTEMPTS=12 \
BRUTEFORCE_TIMEOUT=120 \
  python3 -m pytest tests/integration/test_ssh_bruteforce_e2e.py -v
```

The pytest wrapper takes ~35s end-to-end on a healthy stack.

## How it works

1. **Fires 10–12 bad-password SSH attempts** at the target via `sshpass` (NOT stdin piping — that doesn't work; see Troubleshooting below).
2. The target's sshd logs `Failed password for <user> from <srcip>` for each, which the Wazuh agent picks up as **rule 5760** (level 5, "sshd: authentication failed").
3. After 8 events from the same source IP within 120s, Wazuh fires the correlation alert **rule 5763** (level 10, "sshd: brute force trying to get access"). OR rule 5551 (PAM) depending on how sshd is configured.
4. The Wazuh manager forwards the alert to the OpenSearch indexer (`wazuh-alerts-4.x-YYYY.MM.DD`).
5. The test polls the indexer with the same `WazuhIndexerClient` the production SOC uses, looking for `rule.level >= 10` in the `authentication_failed(s)` rule group from our source IP.
6. When found, the test feeds the alert through `SecurityOperationsAgent.ingest_wazuh_alert()` and asserts that both a `SecurityAlert` and an `IncidentReport` were created.

## Rule 5763 ignore window — IMPORTANT

Rule 5763 has `ignore="60"`, meaning **once it fires from a source IP, subsequent brute-force attempts from that IP are suppressed for 60 seconds**. If you re-run the test within 60s of the previous successful run, rule 5763 will NOT fire again, and the test will fail.

Either:
- Wait 60s+ between runs (the test will print `0 hits` and time out after `--timeout` seconds)
- Run from a different source IP

## Troubleshooting

### Test times out with `0 hits` in poll loop

**Most likely cause:** rule 5763 is in its `ignore="60"` window. Check:
```bash
curl -ks -u admin:CHANGE_ME \
  "https://127.0.0.1:9200/wazuh-alerts*/_search?size=3&q=rule.id:5763&sort=@timestamp:desc" | jq .
```
If the latest 5763 is < 60s old, wait it out.

### `Failed password` events appear in journald but not in indexer

The Wazuh agent on the target may not be reading journald. Check `/var/ossec/etc/ossec.conf` on the target for:
```xml
<localfile>
    <log_format>journald</log_format>
    <location>journald</location>
</localfile>
```
For Ubuntu 22.04+ / Debian 12+ / Raspbian 12 hosts that's the only reliable way.

### sshd doesn't accept password auth

The target's `sshd_config` must have `PasswordAuthentication yes`. Verify:
```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o BatchMode=no user@host true < /dev/null
```
You should get a `password:` prompt. If you get `Permission denied (publickey)` without a prompt, password auth is disabled.

### Test fails with `permission denied` but no sshpass errors

If `sshpass` is missing, the script falls back to stdin piping, which **does NOT actually send the password** — OpenSSH closes the connection on the password prompt before reading stdin. sshd only logs `Connection closed by authenticating user`, NOT `Failed password`. This will generate rule 5710 ("Invalid user") only if the user doesn't exist, NOT rule 5716/5760 ("Failed password") — and rule 5763 will never fire.

Install sshpass: `apt-get install -y sshpass` (the script will warn at startup).

### Test generates 5710 not 5760 ("Invalid user" not "Failed password")

The `--user` argument is for a user that doesn't exist on the target. Rule 5710 doesn't count toward 5763's frequency threshold. Use a real user.

### Manually verify the rule 5763 will fire

```bash
docker exec wazuh-stack_wazuh.manager_1 \
    grep -A5 'id="5763"' /var/ossec/ruleset/rules/0095-sshd_rules.xml
```
Should show `frequency="8" timeframe="120" ignore="60"`.

## Why not just write a unit test?

The whole point of this test is to verify the **production wiring**: that sshd on the target produces log lines the Wazuh agent reads, that the manager correlates them, that the indexer stores them, and that the SOC client queries them correctly. Mocking any of those layers would defeat the purpose.

The unit-level SOC ingestion is already covered by `tests/test_wazuh_soc_auto_escalate.py` (the `description=` bug found there proves that path matters).

## Related

- `scripts/soc/soc_daily_report.py` — daily summary of all alerts (this test's "did anything fire yesterday?" view)
- `tests/test_wazuh_soc_auto_escalate.py` — unit test for the ingest+escalate path
- `agentic_ai/agents/cyber/soc.py::ingest_wazuh_alert` — the production code under test
- `agentic_ai/infrastructure/wazuh_client.py::WazuhIndexerClient.search_alerts` — the polling primitive
