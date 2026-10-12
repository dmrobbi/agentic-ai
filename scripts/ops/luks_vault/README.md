# luks-vault — a LUKS2 image inside a container: open while running, locked at rest

Part of the fleet's LUKS container-ops campaign (`docs/LUKS_OPS.md` — the verified
host guide; `docs/LUKS_EXECUTIVE_SUMMARY.md` — the method overview; the chassis
planner `LuksOpsMixin`). **The ask:** a container whose LUKS image can be
unlocked while the container runs, and is LOCKED (ciphertext at rest, no mapper,
no plaintext device) whenever the container is off.

## Design

- **Container**: `ubuntu:24.04` + `cryptsetup`/`e2fsprogs`, running **privileged**.
  Privileged is not a shortcut: LUKS2 + dm-crypt is a kernel-level encryption layer
  (loop attach + device-mapper). No unprivileged path keeps real LUKS; the rail is
  documented here instead of hidden.
- **Vault storage**: a named Docker volume at `/vault` holds `vault.img` — the LUKS2
  container. The image is created at runtime inside the volume and PERSISTS LOCKED
  across `stop`, `down`, and even container removal (the volume outlives the
  container). Nothing is baked into the image layer.
- **Locking mechanic**: the pid1 entry (`vault_entry wait`) idles in an interruptible
  loop with a SIGTERM/SIGINT trap: at `docker compose stop` (or docker stop) it
  unmounts and `luksClose`s the mapper before exiting. After that, `vault.img` holds
  only ciphertext: the master key exists solely inside the kernel's dm-crypt state
  while the mapper is open, and the unlock credential exists solely in the LUKS
  header's keyslot binding.
- **Credentials**: stdin only. `unlock` pipes the passphrase in, stages a 0600 key at
  `/run`, verifies the credential with `open --test-passphrase` BEFORE opening the
  mapper, shreds the staged key immediately after, and prints only markers. The
  credential is never in argv, env, logs, or the image.
- **One-time filesystem**: the first successful unlock formats the payload ext4
  (a `tune2fs` probe guards it); later unlocks mount the existing fs. Canary
  round-trips verify read/write; wrong-credential negatives prove rejection.
- **Scratch rail (the campaign's rule)**: `selftest` runs the whole loop on a
  container-side `/tmp` scratch image and leaves the real vault untouched. Block
  devices stay off the table without owner-signed consent.

## Quick use

```bash
./luks_vault.sh build
./luks_vault.sh up                      # start the pid1 entry (rebuilds with any entry changes)
printf '%s' '<pass>' | ./luks_vault.sh create 64   # vault.img in the volume; the keyslot binds THIS credential
./luks_vault.sh status                  # VAULT-LOCKED no-mapper
printf '%s' '<pass>' | ./luks_vault.sh unlock   # the SAME credential opens the mapper + mounts /mnt/vaultvol
./luks_vault.sh status                  # VAULT-OPENED mapper=vaultvol
# ... use /mnt/vaultvol (in-container path; host access = exec/docker-volume patterns)
./luks_vault.sh lock                    # unmount + luksClose -> VAULT-LOCK-OK
./luks_vault.sh status                  # VAULT-LOCKED no-mapper (the img = ciphertext)
./luks_vault.sh stop                    # the pid1 trap locks on the way down (idempotent)
./luks_vault.sh up && ./luks_vault.sh status    # the LOCKED vault persisted; unlock works again
./luks_vault.sh selftest                # the container-side scratch self-test
printf '%s' 'not-the-cred' | ./luks_vault.sh unlock || true   # pre-enroll negative: VAULT-CREDENTIAL-REJECTED
./luks_vault.sh destroy --yes           # remove the volume (data gone; refuses without --yes)
printf '%s' '<pass>' | ./luks_vault.sh tpm-enroll     # seal the payload key to THIS machine's TPM
./luks_vault.sh tpm-unlock              # the TPM-bound open: no stdin passphrase; the chip = the authority
```

### TPM machine-binding (the machine-lock ask)

- `tpm-enroll` takes the vault's EXISTING passphrase via stdin (piped, staged 0600,
  handed with `--unlock-key-file`, shredded after) and runs
  `systemd-cryptenroll --tpm2-device=auto` on the vault image: the payload's disk key
  gets sealed against the chip the enroll ran on (default PCRs, incl. PCR7/SecureBoot
  measurements). From then on the locked image unseals ONLY on machines carrying that
  TPM root — a copied image is inert on any other hardware. The passphrase keyslot
  stays as the manual recovery.
- `tpm-unlock` runs `cryptsetup open --token-only vaultvol /vault/vault.img` (the
  systemd-tpm2 token plugin via the cryptsetup CLI — no passphrase, no ask-password
  hang; stdin closed). A copy fails with `VAULT-TPM-UNSEAL-FAILED` everywhere else.
- **The machine is the authority (measured on thing1's real TPM2)**: after enrollment
  ANY root process on the enrolled machine can open the vault — the systemd-tpm2
  token plugin consults the chip on plain `cryptsetup open`, and after any successful
  open the volume key sits in the kernel keyring, so later reopens succeed without
  the credential. The wrong-credential rejection applies BEFORE enrollment (the
  selftest's negatives prove it) and on foreign machines. This = exactly the ask:
  the containers can only be used on the specific machines. The passphrase = the
  off-machine + recovery credential; revoking a machine = wipe its slot
  (`cryptsetup luksKillSlot`), re-enroll a replacement.
- The container runs privileged, so the host's TPM device nodes are in scope; the
  Dockerfile carries systemd + tpm2-tools (the enroll/unseal binaries + the TSS
  libraries).

### HA posture (PVE cluster / Kubernetes)

The vault's credential surface = TPM chips + the kernel keyring + the recovery
passphrase. Two shapes make several machines run the LUKS with HA capability:

- **Shape A — the physical-chip fleet (active-passive over shared storage)**: the
  vault image lives on storage reachable by every node (NFS, CephFS/RBD-backed
  volume); enroll it on EVERY permitted node (one TPM slot each, the recovery
  passphrase kept). The container runs active on ONE node at a time; the failover =
  PVE's HA manager (fencing + the restart policy) or a Kubernetes
  StatefulSet/Deployment with replicas=1 on a PVC, with nodeAffinity pinning to the
  enrolled nodes. Foreign nodes stay inert. Slot budget: LUKS2 allows 32 keyslots —
  one per node = fine for any real fleet; revocation = the per-slot wipe.
- **Shape B — the vTPM carrier (the cluster-native answer)**: bind to a swtpm-backed
  VIRTUAL TPM whose state lives next to the vault on the same shared storage, so
  "the machine" = the VM's chip itself and the package (vault + chip state) moves as
  one unit:
  - **Proxmox VE**: the VM's `tpmstate0` disk (the swtpm backend, v1.2 + v2.0) — the
    state's volid follows the VM through migrations (the volid-updates = the
    supported handoffs); offline migration = straightforward, live = verify-first on
    your stack. PVE's HA manager = the failover authoritatively (the VM restarts on
    the second node; the shared storage holds the state + the vault).
  - **Kubernetes → KubeVirt**: persistent TPM + UEFI state = the FEATURE STATE since
    KubeVirt v1.0.0 — the state = the files on the virt-launcher pod's
    backend-storage PVC; the vTPM's live migration has been actively fixed through
    2026 (the decentralized-migration-era fixes, June 2026) = the actively
    maintained path for VM-bound LUKS with TPM on k8s.
- **The honest interaction**: the physical-chip binding fights MIGRATION (each node
  needs its own slot; the image still lands on the shared storage); the vTPM = the
  binding that travels with the VM = the migration-friendlier option; the
  single-node container (this repo's shape) = the simplest: the host chip = the
  binding, the volume = the vault.
- Measured on thing1 (2026-10-12, the definitive cycle): enroll = the slot-1 token;
  the unseal = no credential, twice (fresh + post-lock persistence); the
  foreign-machine simulation (the token slot killed) = the unseal failed fast
  (VAULT-TPM-UNSEAL-FAILED); the passphrase = the recovery opened; the canary =
  persisted through the cycles + the at-rest image carried no plaintext.

The passphrase placeholder in the docs is a placeholder — real credentials are the
operator's stdin at create and unlock time. The vault's keyslot binds whatever was
piped at create; unlocking later demands that credential (or a later-added recovery
slot's). Staged key files live 0600 under /run and are shredded immediately after
use; nothing secret is stored in the repo, the image, the volume layout, or logs.

## Files

- `Dockerfile` — the base image (no vault inside; the systemd + tpm2-tools layer = the TPM binaries).
- `docker-compose.yml` — privileged + the named volume.
- `vault_entry.sh` — the entry: `wait/create/unlock/lock/status/selftest` +
  `tpm-enroll`/`tpm-unlock` + the lock-at-stop trap.
- `luks_vault.sh` — the host orchestrator (the same command rows incl. tpm-*).

<!-- project: idm.wezzel.com/crab-meat-repos/agentic-ai -->