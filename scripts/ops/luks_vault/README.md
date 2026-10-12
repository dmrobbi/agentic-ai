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
./luks_vault.sh destroy --yes           # remove the volume (data gone; refuses without --yes)
```

The passphrase placeholder in the docs is a placeholder — real credentials are the
operator's stdin at create and unlock time. The vault's keyslot binds whatever was
piped at create; unlocking later demands that credential (or a later-added recovery
slot's). Staged key files live 0600 under /run and are shredded immediately after
use; nothing secret is stored in the repo, the image, the volume layout, or logs.

## Files

- `Dockerfile` — the base image (no vault inside).
- `docker-compose.yml` — privileged + the named volume.
- `vault_entry.sh` — the entry: `wait/create/unlock/lock/status/selftest` + the
  lock-at-stop trap.
- `luks_vault.sh` — the host orchestrator.

<!-- project: idm.wezzel.com/crab-meat-repos/agentic-ai -->