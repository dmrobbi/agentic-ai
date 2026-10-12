# LUKS2 container ops — verified host guide

_Re-authored in-house ops guide. Inspired by cyberanchor's gist `6535a5b38ceb4c57986d4c8324e0a94c`
("CryptSetup | LUKS cryptocontainer CheatSheet"; public gist, **no license** — all rights
reserved by its author). No prose or material is copied from it; the workflow arc is credited,
every command is re-derived and re-verified in-house._

_Verified on 2026-10-11: thing1 (Ubuntu 24.04), cryptsetup `2.7.0`, e2fsprogs `1.47.0`,
file-backed containers only. See Appendix A for the smoke transcript and Appendix B for the
source link inventory. Appendix C lists every deviation from the source material and why._

## 0. Tooling and permission model on this host

- `cryptsetup` and `mkfs.ext4` live in **`/usr/sbin`** (cryptsetup 2:2.7.0-1ubuntu4.2; e2fsprogs
  1.47.0-2.4~exp1ubuntu4.1). The non-root shell PATH on this host **omits `/usr/sbin`** — call the
  binaries by absolute path, or through `sudo` (root's secure_path includes sbin). A bare
  `cryptsetup --version` in a user shell reads "command not found" and is a PATH artifact, not a
  missing package.
- File-backed containers (an `.img` file) do **not** need root for: `luksFormat`, `luksAddKey`,
  `luksKillSlot`, `luksDump`, `luksHeaderBackup/Restore`, `open --test-passphrase` — cryptsetup
  edits the file directly. Root IS required for device activation: `luksOpen`/`luksClose` and
  the following `mkfs.ext4` + `mount` (dm-crypt mapper device).
- Packaging, for reference: Arch installs via `cryptsetup` + `e2fsprogs` (pacman); this host is
  apt-based, and both packages were already present at probe time (2026-10-11).

## 1. Container creation — two profiles

| Parameter | FAST profile | SECURE profile |
|---|---|---|
| type | luks2 | luks2 |
| cipher / key size | `aes-xts-plain64`, 256-bit (two 128-bit AES keys) | `aes-xts-plain64`, 512-bit (two 256-bit AES keys) |
| hash | sha256 | sha512 |
| PBKDF | pbkdf2, 1,000,000 force-iterations | argon2id, **1 GiB memory (host default here)**, parallel 8, iter-time 5000 |
| sector size | implicit | 4096 |
| keyslot cipher | default | `aes-xts-plain64`, 512 |
| header sizing | defaults (16 KiB x2 metadata + 16 MiB keyslots) | 16 MiB keyslots area + 256 KiB metadata per copy |

```bash
# scratch container file (urandom fill — it is real bulk data, not sparse)
dd if=/dev/urandom of=container.img bs=1M count=64 status=none

# FAST profile
/usr/sbin/cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 --key-size 256 --hash sha256 \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000000 --use-random \
  container.img --key-file=key --batch-mode

# SECURE profile (1 GiB Argon2id — the corrected default)
/usr/sbin/cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
  --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 8 --iter-time 5000 \
  --use-random --sector-size 4096 \
  --keyslot-cipher aes-xts-plain64 --keyslot-key-size 512 \
  --luks2-keyslots-size 16m --luks2-metadata-size 256k \
  container.img --key-file=key --batch-mode
```

- `--use-random` draws the master key from `/dev/random`; on modern kernels the CRNG makes this
  effectively non-blocking, while `--use-urandom` is the conservative alternative. Either is fine
  on kernels >= 5.6.
- The source sheet's secure profile showed `--pbkdf-memory 4194304` (4 GiB) while its own note
  recommended 1 GiB for limited-RAM systems — a contradiction resolved here: **1 GiB is the
  documented default; treat 4 GiB as an explicit RAM-rich variant** (it must fit a single
  unlock's memory spike, and Argon2id parallel-8 at 4 GiB will thrash a 4 GB host).

## 2. Lifecycle: open - format - mount - close

```bash
# key from a 0600 scratch file (NOT a process substitution under sudo — see below)
printf '%s' '<passphrase>' > key && chmod 600 key

sudo /usr/sbin/cryptsetup luksOpen container.img cryptvol --key-file=key
sudo /usr/sbin/mkfs.ext4 -q /dev/mapper/cryptvol
sudo mkdir -p /mnt/cryptvol && sudo mount /dev/mapper/cryptvol /mnt/cryptvol
sudo chown "$USER:$USER" /mnt/cryptvol
# ... use it ...
sudo umount /mnt/cryptvol && sudo /usr/sbin/cryptsetup luksClose cryptvol
```

Two trapdoors verified today:

- **`sudo` + process-substitution key files fail.** `sudo cryptsetup ... --key-file=<(printf ... )`
  dies with "Failed to open key file": sudo does not carry the shell's extra fds into the
  sudo'd process, so `/dev/fd/63` cannot resolve there. Use a real 0600 file (or run cryptsetup
  unprivileged where the op allows it — section 0).
- **`--key-file` reads RAW BYTES, trailing newline included.** Formatting with a here-string
  (`<<<`, which appends `\n`) and later testing with a newline-free `printf '%s'` produces two
  different keys and "No key available with this passphrase". The source sheet's consistent
  `echo -n` habit is load-bearing: `echo` vs `echo -n` genuinely changes the key. Verified
  negative: the same passphrase formatted with a trailing `\n` was rejected when tested without.

## 3. Key management and the slot map

LUKS2 allows up to **32 keyslots** (LUKS1 had 8); slots are storage regions, not a priority
order — any working slot activates the device. Convention: keep slot 0 as the primary
passphrase/key slot and use higher slots for recovery keys, agents, and rotation staging.

| Slot state | Meaning |
|---|---|
| empty | no credential bound |
| populated | authenticates independently; ANY single one activates the volume |

Rules that keep you locked out less:

- Add a **recovery key to a free slot BEFORE** rotating or killing anything.
- Never `luksKillSlot` the last working slot; when authenticating a kill with a key file, use a
  DIFFERENT slot's credential than the slot being killed.

### Key files

```bash
dd if=/dev/urandom of=key_new bs=4096 count=1 && chmod 600 key_new
# whole-file semantics: every byte of key_new matters; never regenerate it
```

### Add a slot (auth with existing key, new key on stdin or from file)

```bash
# new passphrase to slot 3, authenticated via existing key file:
printf '%s' '<new-passphrase>' | /usr/sbin/cryptsetup luksAddKey container.img \
  --key-slot 3 --key-file=key_existing --new-keyfile=- --batch-mode

# new key file to slot 3, authenticated via existing passphrase on stdin:
printf '%s' '<existing-passphrase>' | /usr/sbin/cryptsetup luksAddKey container.img \
  key_new --key-slot 3 --key-file=- --batch-mode
```

### Rotate slot 0 (the source sheet's "add to slot 0" — renamed, because it kills)

The flow called "Add to slot 0 using key file from slot 3" in the source begins with
`luksKillSlot container.img 0` — it **destroys the current slot 0 credential before writing the
replacement**. Treat it as what it is:

1. Stage the new credential in a FREE slot first (add, then `open --test-passphrase` it).
2. Only then remove the old one — and confirm the removal target aloud/in chat before the kill.
3. If slot 0 must be reclaimed afterwards, add the rotated key to it explicitly.

```bash
printf '%s' '<new-pass>' | /usr/sbin/cryptsetup luksAddKey container.img --key-slot 5 \
  --key-file=key_slot3 --new-keyfile=- --batch-mode          # stage on slot 5
/usr/sbin/cryptsetup open --test-passphrase container.img --key-slot 5 \
  --key-file=key_slot5_new                                    # prove it
/usr/sbin/cryptsetup luksKillSlot container.img 0 --key-file=key_slot3 --batch-mode
```

### Test flows

```bash
/usr/sbin/cryptsetup open --test-passphrase container.img                     # interactive
/usr/sbin/cryptsetup open --test-passphrase container.img --key-file=key      # key file
/usr/sbin/cryptsetup open --test-passphrase container.img --key-slot 3 --key-file=key   # specific slot
```

### Kill a slot

```bash
/usr/sbin/cryptsetup luksKillSlot container.img 0 --key-file=key_slot3 --batch-mode
```

## 4. Complex passphrases (shell-safe entry)

For machine-injected passphrases with metacharacters: pipe the exact bytes on stdin
(`--key-file=-` / `--new-keyfile=-`), never inline-quote them into argv, and verify the byte
stream with `hexdump -C` before trusting it:

```bash
printf '%s' '<complex-passphrase>' | hexdump -C     # inspect exact bytes first
printf '%s' '<complex-passphrase>' | /usr/sbin/cryptsetup luksAddKey ... --new-keyfile=-
```

(No example passphrases are committed in this guide; material stays out of the repo.)

## 5. Header geometry — and why the 4 MB wipe is wrong

Every LUKS2 container starts with TWO metadata copies plus the keyslots area, then the payload
data. On this host's fast-profile container, `luksDump` reports:

```text
Metadata area: 16384 bytes (per copy; secure-profile sheets set 256 KiB)
Keyslots area: 16744448 bytes (~16 MiB)
```

So the header region (both metadata copies + all keyslots) spans roughly **16.5 MiB from byte
0** (36 MiB+ payload follows). The source sheet's header-removal demo `dd ... bs=1M count=4`
overwrites only 4 MiB — it leaves the bulk of the keyslot area untouched and recoverable. The
in-house rule: **derive the wipe length from geometry, never a magic constant**:

```bash
# parse the header region size out of luksDump (metadata x2 + keyslots area),
# round up to the next MiB, wipe exactly that prefix:
HDR_BYTES=$(/usr/sbin/cryptsetup luksDump container.img | awk '
  /Metadata area:/  { meta = $3 }  /Keyslots area:/ { ks = $3 }
  END { printf "%d", 2 * meta + ks + 1048576 }')        # + 1 MiB margin
dd if=/dev/zero of=container.img bs=1M count=$(( HDR_BYTES / 1048576 )) \
  conv=notrunc status=none
```

(Deleting a header makes the container content unreachable by design; keep a backup first if
the wipe is ever meant to be reversible.)

## 6. Header backup / restore

```bash
/usr/sbin/cryptsetup luksHeaderBackup container.img --header-backup-file header.bak
/usr/sbin/cryptsetup luksHeaderRestore container.img --header-backup-file header.bak
```

Store header backups offline, `chmod 600`, on media separate from the container: a header
backup is a full unlock oracle for every keyslot it carries.

## 7. Detached headers

```bash
# create with the header stored elsewhere (container data starts bare at offset 0 of .img)
dd if=/dev/urandom of=container.img bs=1M count=64 status=none
/usr/sbin/cryptsetup luksFormat --type luks2 --header header.bin container.img --key-file=key --batch-mode

sudo /usr/sbin/cryptsetup luksOpen --header header.bin container.img cryptvol
sudo /usr/sbin/mkfs.ext4 -q /dev/mapper/cryptvol
# ... mount, use, unmount ...
sudo /usr/sbin/cryptsetup luksClose cryptvol

# extract a detached header from an existing (intact) container:
/usr/sbin/cryptsetup luksHeaderBackup container.img --header-backup-file header.bin
/usr/sbin/cryptsetup luksDump --header header.bin container.img        # verify before trusting

# then, if truly wanted, wipe the header region per the geometry rule (section 5)
```

Guardrails: without the header file the container is inert. Two copies on separate media;
test a RESTORE before relying on detached storage (restore-then-`--test-passphrase`).

## 8. Key file derived from an image — methodology note

The source demonstrates a key file made from image bytes wrapped in a fixed byte envelope
(prepend N bytes of `0x31`, append N bytes of `0x2E`), with SHA-512 pins on BOTH the original
image and the derived key. In-house methodology, generic form:

1. Stage the source image ONCE, offline; pin its hash in the vault record.
2. Derive: `envelope = prefix-marker || image-bytes || suffix-marker` (markers are part of the
   secret).
3. Pin the derived key's hash too (prove the envelope), then treat the derived key as any key
   file (slot add, test-passphrase).
4. Never depend on re-downloading third-party media at use time — URLs rot and images change;
   the staged bytes are the material.

Honest classification: this is **obscurity, not secrecy** — anyone learning the envelope
parameters and seeing the image reproduces the key. Use it as a decoy/deception layer around a
real key, not instead of one.

## 9. Passphrases from BIP-39 seed phrases — methodology + explicit warning

The source derives disk passphrases from a 12-word BIP-39 mnemonic through a client-side web
generator. In-house stance: **do not couple wallet-recovery material to disk encryption.**

- A BIP-39 mnemonic is a high-value secret (cryptocurrency custody). Binding it to a disk key
  doubles the blast radius of either secret leaking, and encourages the mnemonic being typed
  into a browser context where a compromised generator reads it silently.
- Third-party "client-side only" claims are unverifiable from a served bundle; treat the
  generator as a supply-chain risk.
- If the flow is REQUIRED for an engagement, run it offline, on a live-USB host, against a
  mnemonic generated for this purpose alone (never a mnemonic in use as a wallet), and derive
  locally (on-box KDF) rather than through a web tool. This guide intentionally carries NO
  example mnemonic, seed phrase, or derivative passphrase.

## 10. Quick reference

```bash
# health/dump
/usr/sbin/cryptsetup luksDump container.img
/usr/sbin/cryptsetup open --test-passphrase container.img --key-file=key
# slot ops (all unprivileged on file-backed containers)
printf '%s' '<pass>' | /usr/sbin/cryptsetup luksAddKey container.img --key-slot N \
  --key-file=key_existing --new-keyfile=- --batch-mode
/usr/sbin/cryptsetup luksKillSlot container.img N --key-file=key_other --batch-mode
# header ops
/usr/sbin/cryptsetup luksHeaderBackup container.img --header-backup-file header.bak
/usr/sbin/cryptsetup luksHeaderRestore container.img --header-backup-file header.bak
# volume activation (root)
sudo /usr/sbin/cryptsetup luksOpen container.img cryptvol --key-file=key
sudo umount /mnt/cryptvol && sudo /usr/sbin/cryptsetup luksClose cryptvol
# TPM machine-binding (the host's real TPM 2.0; enrollment runs unprivileged on a 0600 key file)
/usr/bin/systemd-cryptenroll --tpm2-device=auto --unlock-key-file=key container.img
sudo /usr/sbin/cryptsetup open --token-only container.img cryptvol < /dev/null
```

## 11. TPM machine-binding (the vault container arc, 2026-10-12)

The vault container (`scripts/ops/luks_vault/`) binds its payload key to the HOST's
TPM 2.0. LIVE-verified end-to-end: the enrolled token's credentialless unseal x2
(fresh + post-lock), the empty-credential enroll rejected, the slot-kill
foreign-machine simulation (the unseal failed fast), the passphrase recovery — the
20-leg definitive cycle green, every leg exit-code checked.

```bash
# the credential = a real 0600 key file (never argv/env); the seal leaves the
# passphrase slot untouched = recovery + off-machine credential
/usr/bin/systemd-cryptenroll --tpm2-device=auto --unlock-key-file=key container.img
# verify the systemd-tpm2 token landed (measured shape: PCR 7, sha256 bank, ECC SRK):
/usr/sbin/cryptsetup luksDump container.img | sed -n '/^Tokens/,$p'
# the TPM-bound open: NO credential; stdin closed so a failed consult fails fast
sudo /usr/sbin/cryptsetup open --token-only container.img cryptvol < /dev/null
sudo mkfs.ext4 -q /dev/mapper/cryptvol    # one-time: only on a fresh payload
sudo mkdir -p /mnt/cryptvol && sudo mount /dev/mapper/cryptvol /mnt/cryptvol
```

Semantics (measured, stated plainly):

- The machine IS the authority post-enrollment: any root process on the enrolled
  machine can unseal (the token consult on plain `cryptsetup open`); after any
  successful open the kernel keyring carries the volume key and later opens succeed
  without the token.
- The wrong-credential rejection = PRE-enrollment and OFF-machine (the negative
  controls in section 2 still prove it).
- The `systemd-cryptsetup attach` helper WEDGES on its ask-password FIFO after a
  failed consult even with a closed stdin (measured) — use the CLI's
  `open --token-only`.
- Revoke a machine: `luksKillSlot` its slot (authenticate with a DIFFERENT slot's
  credential; never kill the last working slot). A missing binding fails the
  consult FAST and the vault stays locked — the foreign-machine behavior.
- HA posture (documented in the container README + the public guide repo;
  cluster live-proof = run-first): the physical-chip fleet (a shared image enrolled
  per node, active-passive under a cluster HA manager) or the vTPM carrier (PVE's
  `tpmstate0`; KubeVirt's persistent TPM state = a since-v1.0 feature with actively
  maintained live-migration fixes).

---

## Appendix A — LUK-01 verification transcript (2026-10-11, thing1)

```text
== host facts ==
cryptsetup 2.7.0 flags: UDEV BLKID KEYRING FIPS KERNEL_CAPI HW_OPAL 
mke2fs 1.47.0 (5-Feb-2023)
(binaries in /usr/sbin; user PATH omits sbin — use absolute path or sudo)
== create 64 MB scratch container ==
container: 67108864 bytes
== luksFormat fast profile (unprivileged, file-backed) ==
luksFormat: OK
== geometry (finding-3 evidence) ==
Version:       	2
Metadata area: 	16384 [bytes]
Keyslots area: 	16744448 [bytes]
	PBKDF:      pbkdf2
== open + mkfs + mount + canary ===
canary written
== roundtrip canary ==
roundtrip: OK
== test-passphrase variants ==
file-key match: OK
stdin raw-key match (no newline): OK
No key available with this passphrase.
stdin with trailing newline: REJECTED — proves --key-file uses raw bytes incl. newline (echo vs echo -n matters)
== negative control ==
No key available with this passphrase.
```

(Scratch passphrase placeholder `smoke-luk01-2026`, 64 MB container, fast profile, wiped after
capture.)

### A.2 — LUK-03 full-loop matrix (2026-10-11)

Runner: `scripts/ops/luks_verify.sh` — file-backed, scratch-only, rerunnable anytime. First
run went out with a builder bug (key material staged AFTER the format/open rows that consume
it → 12 cascade FAILs on a raw container); fixed by staging keys in the materials section —
the rerun that landed:

```text
== LUKS2 full-loop verification matrix (scratch: /tmp/luk_verify.NKLKpK) ==
[PASS      ] container-file
[PASS      ] format-fast
[PASS      ] header-geometry-parse
[PASS      ] luksOpen
[PASS      ] canary-roundtrip
[PASS      ] add-keyfile-slot2
[PASS      ] test-pass-default
[PASS      ] negative-control
[PASS      ] test-pass-stdin
[PASS      ] raw-bytes-newline
[PASS      ] test-pass-slot2
[PASS      ] rotate-stage-slot5
[PASS      ] rotate-test-slot5
[PASS      ] rotate-kill-slot0
[PASS      ] rotate-readd-slot0
[PASS      ] header-backup
[PASS      ] header-dump-verify
[PASS      ] detached-format
[PASS      ] detached-no-builtin-header
[PASS      ] detached-luksOpen
[PASS      ] detached-header-dump
== matrix: 21 PASS / 0 FAIL / 0 SKIP ==
VERDICT: ALL-CHECKS-OK (exit 0)
```

Notes: `shellcheck` was not installed on the run host (skipped, recorded). The `raw-bytes-newline`
row passes EITHER way with the doc-accurate message — the file-formatted container rejects the
newline-terminated variant (raw-byte semantics, section 2), which is what the landing run showed.

## Appendix B — source link inventory (live-verified 2026-10-11)

| URL | Role from source | Status today |
|---|---|---|
| `https://cryptony.app/seed-phase-generator/` | BIP-39 mnemonic generator | HTTP 200 |
| `https://dlepex.github.io/7w/index.html` | "7w" deterministic passphrase generator | HTTP 200 |
| `https://upload.wikimedia.org/wikipedia/commons/2/2c/TerryFoxToronto19800712.JPG` | sample image for the key-file derivation demo | HTTP 200 |

Recorded with their 2026-10-11 verification date per the standing policy (every URL live-checked
before landing; re-verify on any future reuse).

## Appendix C — corrections ledger (source -> this guide)

| # | Source behavior | This guide |
|---|---|---|
| 1 | Secure profile pins `--pbkdf-memory 4194304` (4 GiB) while its note recommends `1048576` (1 GiB) | 1 GiB documented default; 4 GiB = explicit RAM-rich variant (section 1) |
| 2 | "Add to slot 0 using key file from slot 3" starts with `luksKillSlot 0`, destroying the slot with no warning | Renamed **rotation**, staged add + test first, confirmation gate before any kill (section 3) |
| 3 | Header removal wipes a fixed first 4 MB (header area needs ~16.5 MiB) | Wipe length derives from `luksDump` geometry parsing (section 5) |
| 4 | BIP-39 seed -> web-tool -> passphrase pipeline presented as a routine flow | Methodology + warning only; no seed/passphrase material; offline local derivation if ever required (section 9) |
| 5 | Arch/pacman assumed; probes on this host were run against a sbin-omitting user PATH | Host facts corrected: packages were already installed; PATH artifact documented; absolute paths used throughout (section 0) |
| 6 | `echo -n` used inconsistently across the sheet's stdin examples; trailing newline shown in some hexdumps | Raw-bytes rule states `echo` vs `echo -n` changes the key; verified by rejection test (section 2) |