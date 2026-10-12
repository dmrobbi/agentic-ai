# LUKS container method — executive summary

_Companion to the verified host guide `docs/LUKS_OPS.md` (re-authored in-house; the
workflow arc inspired by cyberanchor's gist `6535a5b38ceb4c57986d4c8324e0a94c`, no
license — nothing copied from it). Measured on thing1 (Ubuntu 24.04) on 2026-10-11:
cryptsetup 2.7.0, e2fsprogs 1.47.0. All claims below are backed by the run transcript
and the 21/21 PASS verification matrix._

## What it is

LUKS2 is Linux's standard on-disk encryption for a block-like container — either a real
block device or, as the fleet runs it, a plain `.img` file. The method turns the
container into an encrypted volume: everything written to it becomes ciphertext at rest,
and the encrypted volume only becomes readable through one of the credentials (a
passphrase or a key file) registered in its header. Nothing about the data inside is
guessable from the outside; without a valid credential the container is an opaque,
random-looking file.

## How it works

1. **Master key**: on format, cryptsetup generates a random master key (drawn from
   `/dev/random`/`/dev/urandom`; on kernels >= 5.6 both are non-blocking in practice) and
   wraps it with XTS-AES over the payload area — that master-key boundary is what actually
   protects the data.
2. **Keyslots**: the header carries up to 32 keyslot regions (LUKS2; LUKS1 had 8). Each
   populated slot stores the master key encrypted under a key derived from that slot's
   credential by a deliberately slow KDF — slot 0 on the fast profile uses PBKDF2-SHA256
   with 1,000,000 forced iterations; the secure profile uses Argon2id (SHA-512) with a
   1 GiB memory cost, parallel 8, 5000 ms time budget. Any single working slot unlocks
   the volume; slots are storage regions, not a priority order.
3. **Unlock**: a credential is checked against the header (or a specific slot); on
   success the kernel's dm-crypt layer presents a plaintext mapper device
   (`/dev/mapper/<name>`) that the system treats like any volume — `mkfs.ext4`, `mount`,
   use, `umount`, `luksClose`.
4. **Header as the crown jewel**: the header (two metadata copies + the keyslots area,
   ~16.5 MiB on the verified host) is the only way in. Backups of it are a full unlock
   oracle — they belong offline, chmod 600, on separate media. Destroying it erases
   access by design; a wipe of that region must derive its length from `luksDump`
   geometry, never from a magic constant (the reference sheet's "first 4 MB" leaves most
   of the header recoverable).
5. **Per-operation permissions**: file-backed containers need no root for
   `luksFormat`, `luksAddKey`, `luksKillSlot`, `luksDump`, `luksHeaderBackup/Restore`,
   and `open --test-passphrase` — cryptsetup edits the file directly. Root is only
   required for mapper activation: `luksOpen`/`luksClose` and the following
   `mkfs`/`mount`.

## The two verified profiles

| | FAST | SECURE |
|---|---|---|
| cipher | XTS-AES, 256-bit | XTS-AES, 512-bit |
| header hash | SHA-256 | SHA-512 |
| PBKDF | PBKDF2, 1M force-iterations | Argon2id, 1 GiB memory, parallel 8, 5000 ms |
| trade | fast format + unlock on any CPU | slow, memory-hard: punishes GPU/offline guessing |
| use when | scratch/test volumes, lab loops | anything meant to hold real secrets |

The fleet default for the secure profile = 1 GiB Argon2id memory (the reference sheet
contradicted itself: a 4 GiB pin vs a 1 GiB recommendation; 4 GiB stays documented as an
explicit RAM-rich variant only).

## Verification posture (how we know it works)

- **Full-loop matrix**: `scripts/ops/luks_verify.sh` runs 21 checks end-to-end —
  format both profiles, open/format/mount, canary round-trip, slot add, per-key-type
  passphrases, rotation (stage → test → kill → re-add), header backup + dump-verify,
  detached-header create/open/mount, negative controls. Last recorded run:
  **21 PASS / 0 FAIL / 0 SKIP** (2026-10-11).
- **Verified trapdoors** (proven live, now standing rules): sudo + process-substitution
  key files fail (sudo drops inherited fds — stage a real 0600 key file); `--key-file`
  reads raw bytes including any trailing newline — `echo -n` vs `echo` genuinely produces
  two different keys.
- **Negative controls are part of the matrix**: wrong credentials must keep being
  rejected.

## What the fleet changed from the reference sheet

1. 1 GiB Argon2id as the default; 4 GiB as an explicit variant.
2. Slot 0 replacements renamed **rotation** with a staged add + test + confirmation
   gate; a kill never authenticates with the slot being killed, and the last working
   slot is never killed.
3. Header wipe length derives from `luksDump` geometry (+1 MiB margin), never "4 MB".
4. No BIP-39/seed-phrase coupling of any kind — wallet material stays away from disk
   keys; if an engagement ever requires it: offline host, purpose-generated mnemonic,
   local on-box derivation, never a third-party web tool.
5. Absolute `/usr/sbin` paths throughout (this host's user PATH omits sbin — a bare
   `cryptsetup` failure there is a PATH artifact, not a missing package).
6. The image-derived-key envelope is documented as a **decoy/deception layer**
   (obscurity, not secrecy) around a real key — never a replacement.

## Where everything lives

- Verified host guide: `docs/LUKS_OPS.md` (landed `2eab785`; appendix A carries the
  transcripts, appendix C the corrections ledger).
- Verification script: `scripts/ops/luks_verify.sh` (landed `736f355`).
- Chassis planner: `agentic_ai/agents/cyber/luks_ops.py` (`LuksOpsMixin`, landed
  `6ed28f9`/`cf3c240` on 2026-10-12) — planner-only ops on both kali chassis
  generations; results are review artifacts, nothing executes; block-device ops stay
  consent-gated by the standing rail.

<!-- project: idm.wezzel.com/crab-meat-repos/agentic-ai -->