# KA-074 / Healthcheck row (OPT-74)

Builder spec (KA-074, OPT-74: "[74] Healthcheck row [S/none] - the SOC
healthcheck gains a kali-agent op-presence check"). The shared SOC healthcheck
script (`/opt/soc-openclaw/deploy/healthcheck.sh` on thing1, run hourly by
`soc-healthcheck.timer`) is a shared fleet file, so it is edited ONLY by the
[INTEGRATION] task: apply the block below VERBATIM at the placement below.
This doc plus `tests/test_healthcheck_kali_row.py` are this builder's
deliverables; the test pins this doc as the contract.

## Semantics

The row asserts the kali agent's planner surface stays importable on this
host: both agent classes (`agentic_ai.agents.cyber.kali` -> `KaliAgent`,
`agentic_ai.agents.cyber.kali_v2` -> `KaliAgentV2`) import cleanly and each
still carries >=100 public op methods from its mixin composition. The probe
is planner-only: a `python3 -c` import + `dir()` count - nothing is executed,
no network, no writes. Either module rotting (import failure, truncated
composition) drops the row to red; additive op growth stays green by design
(floors, not exact counts).

## The row (insert verbatim)

```bash
echo "--- kali-agent op-presence ---"
# OPT-74 (KA-074): the kali agent's planner surface must stay importable on
# this host. Planner-only probe: imports the two kali classes and counts
# public op methods; nothing executes, no network.
KALI_REPO="${SOC_KALI_REPO:-$HOME/agentic-ai}"
KALI_N=$(cd "$KALI_REPO" 2>/dev/null && python3 -c "
import importlib
ka = importlib.import_module('agentic_ai.agents.cyber.kali').KaliAgent
kv = importlib.import_module('agentic_ai.agents.cyber.kali_v2').KaliAgentV2
n = len([x for x in dir(ka) if not x.startswith('_')])
n2 = len([x for x in dir(kv) if not x.startswith('_')])
assert n >= 100 and n2 >= 100, 'kali surface collapsed: %d+%d' % (n, n2)
print(n + n2)" 2>/dev/null || echo 0)
KALI_N=${KALI_N:-0}
[ "$KALI_N" -gt 0 ] 2>/dev/null \
  && ok "kali-agent ops: $KALI_N" \
  || bad "kali-agent ops: $KALI_N (want >0) — kali import or composition failed; repo at $KALI_REPO"
```

## Placement

Insert the block AFTER the `--- sub-agents ---` section (after its closing
`fi`) and immediately BEFORE the line:

    echo "--- secrets perms (assert, never rewrite) ---"

The anchor line is unique in the current script (verified 2026-10-06).
Section order stays: systemd units -> timers -> HTTP backends -> fleet ->
sub-agents -> **kali-agent op-presence** -> secrets perms -> pipeline state
perms -> laya gated decision path -> summary.

## Conventions the row follows (current script, as of 2026-10-06)

`ok()`/`bad()` are shell helpers defined at the top of the script (after the
`DASH=` line) and are CALLED bare - no parentheses, one quoted message
argument. Their definitions as they exist today, quoted for reference only
(the integration task does not change them):

```text
ok()  { echo "  ok   $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
```

- Section intro format: `echo "--- <lowercase title> ---"` (like
  `--- systemd units ---`, `--- sub-agents ---`).
- Env-overridable input with a home default under SOC_* naming, like
  `DASH="${SOC_DASHBOARD_URL:-...}"` and `MB="${SOC_MAILBOX_ENV:-...}"`;
  the empty-value guard follows the fleet section's `T=${T:-0}` style.
- Threshold compares use `2>/dev/null` on the bracket test with the
  `&& ok ... || bad ...` chain (fleet-section pattern).
- bad() messages carry the cause hint after an em dash, matching the
  mailbox-perms, laya, and sub-agents rows.

## Integration verification

1. `bash -n /opt/soc-openclaw/deploy/healthcheck.sh`
2. Hand-run the script (`deploy/healthcheck.sh`, as wez - see the script's
   header note about PATH and secret ownership): under normal state the new
   row prints `ok   kali-agent ops: 313` (313 = KaliAgent 192 +
   KaliAgentV2 121 public op methods on 2026-10-06; the drift alarm triggers
   only when a class falls below its floor).
3. `tests/test_healthcheck_kali_row.py` stays green; the two gated live
   cross-checks also pass on thing1 when run with `KA074_LIVE_SCRIPT=1`
   (they skip on hosts without the deployed script - owner-gated opt-in,
   same precedent as the lab batteries).
