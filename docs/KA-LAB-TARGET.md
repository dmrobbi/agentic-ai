# KA lab target - the pve-lab battery playbook (KA-095)

**OWNER-GATE: every executing mode of this playbook (`--reset`, `--run`)
refuses without `KA_BATTERY_CONSENT=1` in its environment.** `--check` and
`--verify` are read-only and ungated. Nothing in the CI suite launches this
script; the agentic-ai batteries keep to planners, fixtures, and stubs.

## Contract

The standard battery target is **rocky-scan** - a standalone KVM VM on
gus2, launched as a raw `qemu-system-x86_64` process (no libvirt), ssh via
gus2 port 2226, disk `~/verify-aai/pve-vm/rocky-scan-disk.qcow2`. A
battery run = execute assessment commands against the target, collect the
output as evidence, then RESET the target's disk to a pristine snapshot
before the next run.

Modes (the script lives at `scripts/lab/pve-lab-battery.sh` in this repo;
run it ON gus2 - scp a copy or check out the repo there):

| mode | gate | behavior |
|------|------|----------|
| `--check` | none (read-only) | host tier + target-reachability + snapshot inventory; exit 0 = green |
| `--verify` | none (read-only) | post-run target sanity (up, uptime, hostname) |
| `--reset` | KA_BATTERY_CONSENT=1 | stop the qemu vm -> qcow2 rollback to `pristine` -> relaunch (the exact rocky launch block of the house launcher) |
| `--run CMD...` | KA_BATTERY_CONSENT=1 | execute one battery command on the target over ssh |

Exit codes: 0 green; 1 target/host tier failure; 2 consent refused;
3 usage.

## Reset machinery (qcow2 internal snapshots)

- ARM (one time, VM stopped, owner-gated):
  `qemu-img snapshot -c pristine ~/verify-aai/pve-vm/rocky-scan-disk.qcow2`
- LIST: while the VM RUNS the image is write-locked - listing uses the
  force-share read (`qemu-img snapshot -l -U ...`); without a live qemu the
  plain form works. The playbook reports whichever state holds.
- RESET (gated): stop the qemu (pgrep with a character-class pattern -
  never a raw self-matching pattern), `qemu-img snapshot -a pristine`,
  relaunch the rocky block, then `--verify`.

## Topology facts (verified live 2026-10-05; re-verify before trusting)

- Launcher: `~/verify-aai/pve-vm/boot-all.sh` boots 5 VMs with
  `-enable-kvm -cpu host` (VT-x enabled on gus2; NEVER revert those args to
  TCG). Hostfwd ssh ports: 2222-2225 = the four PVE nodes, 2226 =
  rocky-scan. Guest MACs in the qemu lines are load-bearing (cloud-init
  matched them) - never edit them.
- **The four PVE node disks are BACK** (the owner chose REBUILD; the
  regeneration completed 2026-10-05 evening: the disks are live-written by
  the running nodes again, re-verified 2026-10-06/07). The pve-lab
  cluster is deployed: 4 nodes, quorate, HA CRM master active with
  watchdogs armed, ct:100 running; gold-build snapshots exist per disk.
  The battery target deliberately does NOT depend on the cluster.
- rocky-scan has been up since 2026-10-02 02:16 UTC (verified live: load
  ~0; the disk's fresh mtime is the VM's own writes, not a second
  process - checked with lsof).
- Key: `~/verify-aai/pve-vm/pve-pilot-key` (root@ all lab machines).
- Timing discipline: keep foreground ssh commands on gus2 under ~25s; run
  long batteries nohup'd and poll.

## CI discipline

This playbook is a MANUAL executor. The agentic-ai suite never touches the
lab; lab/live risk stays behind the consent gate; any LIVE exploitation
beyond the lab requires fresh owner consent (the todo's global rule).

Related: `stig-baselines` docs/proxmox/CLUSTER-HA-SETUP.md (the original
cluster build + HA guide) and the pve-lab-recovery skill (the house
relaunch/verify/fence runbook this playbook reuses).
