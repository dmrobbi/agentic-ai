"""LuksOpsMixin - LUKS2 container-ops planning for the kali chassis.

Planner-only functionality: every op builds dicts/lists/strings for
review - nothing here executes anything or imports execution machinery.
Block-device reality stays consent-gated: the plans cover FILE-BACKED
containers under a scratch root; block-device ops require owner-signed
consent outside these planner results (the consent rail rides every
plan dict and luks_method_notes()).

Methodology re-authored in-house from docs/LUKS_OPS.md (itself an
in-house re-authoring inspired by cyberanchor's LUKS gist
6535a5b38ceb4c57986d4c8324e0a94c, no license - nothing copied
verbatim). The planner reproduces the doc's corrected shapes only:
1 GiB Argon2id default (finding 1), rotation-named slot rotation with a
confirmation gate (finding 2), geometry-derived header wipe lengths
(finding 3), no mnemonic/seed material anywhere (finding 4), absolute
sbin paths on this Ubuntu host (finding 5), and the raw-bytes key-file
rule (correction 6).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

LUKS_KNOWN_PROFILES = ("fast", "secure")

# Finding 1: default pbkdf-memory = 1 GiB (1048576 KiB); the gist's
# 4 GiB pin (4194304 KiB) is an explicit RAM-rich variant, never the
# default (Argon2id parallel-8 at 4 GiB thrashes a 4 GB host).
LUKS_SECURE_MEMORY_DEFAULT_KIB = 1048576
LUKS_SECURE_MEMORY_VARIANT_KIB = 4194304

# Finding 3: header wipe length derives from luksDump geometry. The
# fallback floor stands only with parsed=False: a LUKS2 header is at
# least two metadata copies plus the keyslots area (~16.5 MiB on the
# verified host: 16384 bytes metadata x2 + 16744448 keyslots). The
# source sheet's fixed "first 4 MB" wipe leaves most of the header
# recoverable - plans below the 16 MiB floor are rejected outright.
LUKS2_METADATA_DEFAULT_BYTES = 16384
LUKS2_KEYSLOTS_DEFAULT_BYTES = 16744448
LUKS2_HEADER_WIPE_MARGIN_BYTES = 1048576
LUKS2_HEADER_MIN_BYTES = 16 * 1024 * 1024
LUKS2_HEADER_FALLBACK_BYTES = (
    2 * LUKS2_METADATA_DEFAULT_BYTES + LUKS2_KEYSLOTS_DEFAULT_BYTES
    + LUKS2_HEADER_WIPE_MARGIN_BYTES)

# Finding 5: absolute sbin paths (this host's user PATH omits /usr/sbin).
LUKS_BIN = "/usr/sbin/cryptsetup"
MKFS_BIN = "/usr/sbin/mkfs.ext4"

LUKS_MAX_SLOTS = 32  # LUKS2 key-slot id space (0..31); slots are regions, not priority

LUKS_SLOT_OP_KINDS = ("add", "rotate_slot_0", "kill_slot")


class LuksOpsMixin:
    """LUKS2 container-ops planning methods; safe on any host object.

    The ops consult the host's ``validate_target`` when the host
    provides it (silent fallback when it does not). Nothing executes:
    results are planner dicts/lists/strings; any real run passes the
    host agent's standing execution gates and the consent rail
    (scratch-only file-backed containers; block devices need
    owner-signed consent).
    """

    # -- input guards ------------------------------------------------------
    @staticmethod
    def _luks_scrub_target(target: Any) -> str:
        """Reject none/empty/non-string inputs, shell metacharacters,
        separators, control characters and traversal shapes; return the
        stripped token."""
        if not isinstance(target, str):
            raise ValueError("target must be a string")
        t = target.strip()
        if not t:
            raise ValueError("target is empty")
        if any(c in t for c in (";", "&", "|", "$", "`", "\n", "\r", "\x00")):
            raise ValueError("target contains shell metacharacters")
        if t.startswith("..") or "./" in t or "/../" in t or ".\\" in t:
            raise ValueError("target contains traversal shapes")
        return t

    @staticmethod
    def _luks_scrub_name(name: Any, kind: str) -> str:
        """Scrub a path-segment NAME (container/key/mapper files) and
        additionally reject separators - names never carry paths."""
        t = LuksOpsMixin._luks_scrub_target(name)
        if "/" in t:
            raise ValueError(f"{kind} name must not contain '/'")
        if any(c.isspace() for c in t):
            raise ValueError(f"{kind} name must not contain whitespace")
        return t

    def _luks_guard(self, target: Any) -> str:
        """Scrub, then consult the host's validate_target when the host
        provides it (getattr silence keeps bare hosts usable)."""
        t = self._luks_scrub_target(target)
        validate_target = getattr(self, "validate_target", None)
        if validate_target is not None and not validate_target(t):
            raise ValueError("target rejected by the host's validate_target")
        return t

    def _luks_guard_name(self, name: Any, kind: str) -> str:
        """Scrub a path-segment name, then consult the host's
        validate_target when the host provides it."""
        t = self._luks_scrub_name(name, kind)
        validate_target = getattr(self, "validate_target", None)
        if validate_target is not None and not validate_target(t):
            raise ValueError("target rejected by the host's validate_target")
        return t

    @staticmethod
    def _luks_under_scratch(scratch: Any, name: str) -> str:
        """Join a scrubbed NAME under the scratch root, refusing
        traversal before resolution; returns the joined absolute path
        string."""
        s = Path(scratch).resolve()
        if not s.is_dir():
            raise ValueError("scratch root must exist and be a directory")
        p = (s / name).resolve()
        if p != s and s not in p.parents:
            raise ValueError("path escapes the scratch root")
        return str(p)

    # -- lifecycle plans ---------------------------------------------------
    def plan_luks_create(self, scratch: str, container_name: str,
                         profile: str = "secure",
                         memory_variant: bool = False,
                         size_mb: int = 64) -> Dict[str, Any]:
        """Container-creation plan for one of the two verified profiles.

        Returns a planner dict: profile params (the doc's corrected
        shapes), the container path (under the scratch root), and the
        ordered command rows; nothing runs.
        """
        if profile not in LUKS_KNOWN_PROFILES:
            raise ValueError(
                f"unknown profile {profile!r}; known profiles: "
                f"{', '.join(sorted(LUKS_KNOWN_PROFILES))}")
        if not isinstance(size_mb, int) or not 1 <= size_mb <= 4096:
            raise ValueError("size_mb must be an integer in 1..4096")
        name = self._luks_guard_name(container_name, "container")
        container = self._luks_under_scratch(scratch, name)
        params: Dict[str, Any] = {"type": "luks2", "cipher": "aes-xts-plain64"}
        cmd: List[str]
        if profile == "fast":
            params.update({"key_size": 256, "hash": "sha256",
                           "pbkdf": "pbkdf2",
                           "pbkdf_force_iterations": 1000000,
                           "random": "use-random"})
            cmd = [
                "dd if=/dev/urandom of=" + container
                + f" bs=1M count={size_mb} status=none",
                f"{LUKS_BIN} luksFormat --type luks2 "
                "--cipher aes-xts-plain64 --key-size 256 --hash sha256 "
                "--pbkdf pbkdf2 --pbkdf-force-iterations 1000000 "
                "--use-random " + container + " --key-file=key --batch-mode",
            ]
        else:
            mem = (LUKS_SECURE_MEMORY_VARIANT_KIB if memory_variant
                   else LUKS_SECURE_MEMORY_DEFAULT_KIB)
            params.update({"key_size": 512, "hash": "sha512",
                           "pbkdf": "argon2id", "pbkdf_memory_kib": mem,
                           "pbkdf_parallel": 8, "iter_time_ms": 5000,
                           "sector_size": 4096,
                           "keyslot_cipher": "aes-xts-plain64",
                           "keyslot_key_size": 512,
                           "keyslots_size": "16m",
                           "metadata_size": "256k", "random": "use-random"})
            cmd = [
                "dd if=/dev/urandom of=" + container
                + f" bs=1M count={size_mb} status=none",
                f"{LUKS_BIN} luksFormat --type luks2 "
                "--cipher aes-xts-plain64 --key-size 512 --hash sha512 "
                f"--pbkdf argon2id --pbkdf-memory {mem} "
                "--pbkdf-parallel 8 --iter-time 5000 --use-random "
                "--sector-size 4096 "
                "--keyslot-cipher aes-xts-plain64 --keyslot-key-size 512 "
                "--luks2-keyslots-size 16m --luks2-metadata-size 256k "
                + container + " --key-file=key --batch-mode",
            ]
        return {"profile": profile, "params": params, "container": container,
                "commands": cmd,
                "notes": ("file-backed container under a scratch root "
                          "(no root needed for format); block-device ops "
                          "need owner-signed consent; --key-file reads "
                          "raw bytes incl. any trailing newline"),
                "consent_rail": "scratch-only; no block-device ops"}

    def plan_luks_open_close(self, scratch: str, container_name: str,
                             key_name: str = "key",
                             mapper_name: str = "cryptvol") -> Dict[str, Any]:
        """Lifecycle plan: open (root), mkfs, mount, use, unmount, close
        (root). Rows carry their root requirement; nothing runs."""
        container = self._luks_under_scratch(scratch,
                                             self._luks_guard_name(
                                                 container_name,
                                                 "container"))
        key = self._luks_under_scratch(scratch,
                                       self._luks_guard_name(key_name, "key"))
        mapper = self._luks_guard_name(mapper_name, "mapper")
        mp = "/mnt/" + mapper
        return {"container": container, "mapper": mapper,
                "rows": [
                    {"requires_root": True,
                     "cmd": f"sudo {LUKS_BIN} luksOpen {container}"
                            f" {mapper} --key-file={key}"},
                    {"requires_root": True,
                     "cmd": f"sudo {MKFS_BIN} -q /dev/mapper/{mapper}"},
                    {"requires_root": True,
                     "cmd": f"sudo mkdir -p {mp} && sudo mount"
                            f" /dev/mapper/{mapper} {mp}"},
                    {"requires_root": True,
                     "cmd": f"sudo umount {mp} && sudo {LUKS_BIN}"
                            f" luksClose {mapper}"},
                ],
                "notes": ("sudo + process-substitution key files fail "
                          "(sudo drops inherited fds) - stage a real "
                          "0600 key file; whole-file key semantics; "
                          "mkfs/mount own the freshly formatted volume"),
                "consent_rail": "scratch-only; no block-device ops"}

    def plan_luks_slot_ops(self, scratch: str, container_name: str, ops: List[str],
                           confirm: bool = False, auth_key_file: Optional[str] = None,
                           staging_slot: int = 5, target_slot: int = 0,
                           rotate_to: int = 0) -> Dict[str, Any]:
        """Slot-plan op: add / rotate_slot_0 / kill_slot sequences.

        Destructive rows (rotation's kill, explicit kills) are planned
        ONLY with confirm=True; without it the dict marks them
        requires_confirmation with a skipped note (finding 2: the
        source's "add to slot 0" destroys the slot silently - renamed
        rotation, staged add + test first). A kill authenticates with a
        DIFFERENT slot's credential (auth_key_file), never the slot
        being killed; the last-working-slot refusal rides the notes.
        """
        container = self._luks_under_scratch(scratch,
                                             self._luks_guard_name(
                                                 container_name,
                                                 "container"))
        if not isinstance(ops, (list, tuple)) or not ops:
            raise ValueError("ops must be a non-empty list")
        auth = None
        if auth_key_file is not None:
            auth = self._luks_under_scratch(
                scratch, self._luks_guard_name(auth_key_file, "auth key"))

        def _slot_ok(n: int) -> bool:
            return isinstance(n, int) and 0 <= n < LUKS_MAX_SLOTS

        for n in (staging_slot, target_slot, rotate_to):
            if not _slot_ok(n):
                raise ValueError(
                    f"slot out of range (0..{LUKS_MAX_SLOTS - 1}): {n}")
        rows: List[Dict[str, Any]] = []
        for op in ops:
            if op == "add":
                rows.append({
                    "op": "add", "requires_confirmation": False,
                    "cmd": (f"printf '%s' '<new-passphrase>' | {LUKS_BIN}"
                            f" luksAddKey {container} --key-slot"
                            f" {staging_slot} "
                            + (f"--key-file={auth} " if auth else "--key-file=- ")
                            + "--new-keyfile=- --batch-mode"),
                    "note": ("stage the new credential; prove it with "
                             "open --test-passphrase before any kill"),
                })
            elif op == "rotate_slot_0":
                if not confirm:
                    rows.append({
                        "op": "rotate_slot_0", "requires_confirmation": True,
                        "skipped": ("rotation removes the old slot-0 "
                                    "credential; plan the kill only with "
                                    "confirm=True after the staged key "
                                    "tests"),
                    })
                    continue
                if not auth:
                    raise ValueError(
                        "rotation kill needs auth_key_file from a DIFFERENT "
                        "slot than the one being killed")
                rows.append({
                    "op": "rotate_slot_0", "requires_confirmation": False,
                    "cmd": (f"{LUKS_BIN} luksKillSlot {container}"
                            f" {target_slot} --key-file={auth} --batch-mode"),
                    "note": ("remove the old credential only AFTER the "
                             f"slot {staging_slot} key tests; re-add "
                             f"slot {target_slot} explicitly if it must "
                             "be reclaimed; never kill the last working "
                             "slot"),
                })
            elif op == "kill_slot":
                if not _slot_ok(target_slot):
                    raise ValueError(
                        f"slot out of range (0..{LUKS_MAX_SLOTS - 1}): "
                        f"{target_slot}")
                if not confirm:
                    rows.append({
                        "op": "kill_slot", "slot": target_slot,
                        "requires_confirmation": True,
                        "skipped": ("destructive; plan only with "
                                    "confirm=True; never kill the last "
                                    "working slot"),
                    })
                    continue
                if not auth:
                    raise ValueError(
                        "kill_slot needs auth_key_file from a DIFFERENT "
                        "slot than the one being killed")
                rows.append({
                    "op": "kill_slot", "slot": target_slot,
                    "requires_confirmation": False,
                    "cmd": (f"{LUKS_BIN} luksKillSlot {container}"
                            f" {target_slot} --key-file={auth} --batch-mode"),
                    "note": "confirm the removal target before running",
                })
            else:
                raise ValueError(
                    f"unknown slot op {op!r}; supported ops: "
                    f"{', '.join(sorted(LUKS_SLOT_OP_KINDS))}")
        return {"container": container, "rows": rows, "confirm": confirm,
                "notes": ("any single populated slot activates the "
                          "volume; keep a recovery key on a free slot "
                          "BEFORE rotating or killing; slots are "
                          "storage regions, not priority"),
                "consent_rail": "scratch-only; no block-device ops"}

    # -- header geometry ---------------------------------------------------
    def plan_header_wipe(self, scratch: str, container_name: str,
                         luks_dump_text: Optional[str] = None
                         ) -> Dict[str, Any]:
        """Geometry-derived header wipe plan (finding 3).

        Parses luksDump's metadata/keyslots area lines; wipe length =
        2*metadata + keyslots + the 1 MiB margin. With no dump text the
        plan falls back to the floor with parsed=False and the
        must-parse warning; parsed plans below the 16 MiB floor are
        rejected as misparses.
        """
        name = self._luks_guard_name(container_name, "container")
        container = self._luks_under_scratch(scratch, name)
        parsed = False
        meta = ks = 0
        if luks_dump_text is not None:
            mtext = re.search(r"Metadata area:\s+(\d+)",
                              luks_dump_text)
            ktext = re.search(r"Keyslots area:\s+(\d+)",
                              luks_dump_text)
            if mtext and ktext:
                meta, ks = int(mtext.group(1)), int(ktext.group(1))
                parsed = True
        if parsed:
            wipe = 2 * meta + ks + LUKS2_HEADER_WIPE_MARGIN_BYTES
            if wipe < LUKS2_HEADER_MIN_BYTES:
                raise ValueError(
                    "parsed header geometry below the 16 MiB LUKS2 floor - "
                    "treat as a misparse and re-derive from luksDump")
        else:
            wipe = LUKS2_HEADER_FALLBACK_BYTES
        return {
            "container": container, "parsed": parsed,
            "wipe_bytes": wipe,
            "commands": [
                "dd if=/dev/zero of=" + container
                + f" bs=1M count={wipe // LUKS2_HEADER_WIPE_MARGIN_BYTES}"
                + " conv=notrunc status=none",
            ],
            "warning": ("deleting the header makes the content "
                        "unreachable by design; luksHeaderBackup "
                        "first if the wipe must stay reversible; "
                        + ("derive the length from luksDump before "
                           "trusting any constant" if not parsed else
                           "geometry parsed from luksDump")),
            "consent_rail": "scratch-only; no block-device ops",
        }

    # -- header backup / detached headers ---------------------------------
    def plan_header_backup_restore(self, scratch: str, container_name: str,
                                   backup_name: str = "header.bak"
                                   ) -> Dict[str, Any]:
        """Header backup/restore plan with the unlock-oracle warning."""
        container = self._luks_under_scratch(scratch,
                                             self._luks_guard_name(
                                                 container_name,
                                                 "container"))
        backup = self._luks_under_scratch(
            scratch, self._luks_guard_name(backup_name, "backup"))
        return {"container": container, "backup": backup,
                "rows": [
                    {"requires_root": False,
                     "cmd": f"{LUKS_BIN} luksHeaderBackup {container}"
                            f" --header-backup-file {backup}"},
                    {"requires_root": False,
                     "cmd": f"{LUKS_BIN} luksHeaderRestore {container}"
                            f" --header-backup-file {backup}"},
                ],
                "notes": ("a header backup is a full unlock oracle for "
                          "every keyslot it carries; store OFFLINE, "
                          "chmod 600, on media separate from the "
                          "container"),
                "consent_rail": "scratch-only; no block-device ops"}

    def plan_detached_header(self, scratch: str, container_name: str,
                             profile: str = "secure",
                             header_name: str = "header.bin",
                             memory_variant: bool = False,
                             size_mb: int = 64) -> Dict[str, Any]:
        """Detached-header plan: create with --header, open with
        --header, extract via luksHeaderBackup, verify via luksDump."
        """
        base = self.plan_luks_create(scratch, container_name, profile,
                                     memory_variant, size_mb)
        header = self._luks_under_scratch(
            scratch, self._luks_guard_name(header_name, "header"))
        arcs = [
            ("create", self.plan_luks_create(scratch, container_name,
                                             profile, memory_variant,
                                             size_mb)["commands"][-1]
             .replace("--key-file=key",
                      f"--header {header} --key-file=key")),
            ("open-close", self.plan_luks_open_close(
                scratch, container_name)["rows"][0]["cmd"]
                .replace("luksOpen", "luksOpen --header " + header)),
            ("extract", f"{LUKS_BIN} luksHeaderBackup {base['container']}"
                        f" --header-backup-file {header}"),
            ("verify", f"{LUKS_BIN} luksDump --header {header}"
                       f" {base['container']}"),
        ]
        return {"container": base["container"], "header": header,
                "profile": profile, "arcs": [
                    {"step": s, "cmd": c} for s, c in arcs],
                "notes": ("without the header file the container is "
                          "inert; two header copies on separate media; "
                          "test a RESTORE (restore-then--test-passphrase) "
                          "before relying on detached storage"),
                "consent_rail": "scratch-only; no block-device ops"}

    # -- checklists and methodology ---------------------------------------
    def luks_test_passphrase_checklist(self, scratch: str,
                                       container_name: str,
                                       key_name: str = "key",
                                       slot: Optional[int] = None
                                       ) -> List[Dict[str, Any]]:
        """The open --test-passphrase checklist; references name paths,
        never secret material passed through the planner."""
        container = self._luks_under_scratch(scratch,
                                             self._luks_guard_name(
                                                 container_name,
                                                 "container"))
        key = self._luks_under_scratch(scratch,
                                       self._luks_guard_name(key_name, "key"))
        if slot is not None and not (isinstance(slot, int)
                                     and 0 <= slot < LUKS_MAX_SLOTS):
            raise ValueError(
                f"slot out of range (0..{LUKS_MAX_SLOTS - 1}): {slot}")
        slot_row = ("" if slot is None else f" --key-slot {slot}")
        return [
            {"requires_root": False,
             "cmd": f"{LUKS_BIN} open --test-passphrase {container}",
             "check": "interactive passphrase still unlocks"},
            {"requires_root": False,
             "cmd": f"{LUKS_BIN} open --test-passphrase {container}"
                    f" --key-file={key}",
             "check": "key file unlocks (raw bytes: trailing newline "
                      "counts; echo vs echo -n changes the key)"},
            {"requires_root": False,
             "cmd": f"{LUKS_BIN} open --test-passphrase {container}"
                    f"{slot_row} --key-file={key}",
             "check": "specific slot authenticates the key it holds"},
            {"requires_root": False,
             "cmd": ("printf '%s' '<wrong-pass>' | "
                     f"{LUKS_BIN} open --test-passphrase {container} "
                     "--key-file=-"),
             "check": "negative control still REJECTS"},
        ]

    def luks_method_notes(self) -> Dict[str, Any]:
        """The in-house methodology summary: the five findings, the two
        verified trapdoors, the BIP-39 warning (no secret material),
        and the image-derived-key envelope (obscurity, decoy layer)."""
        return {
            "findings": [
                "1: 1 GiB Argon2id memory is the default; 4 GiB is an "
                "explicit RAM-rich variant (the source's own note "
                "contradicted its own pin)",
                "2: the 'add to slot 0' flow begins with luksKillSlot 0 - "
                "it destroys the slot first; treat as rotation with a "
                "confirmation gate and a tested staged key",
                "3: header wipe length derives from luksDump geometry; a "
                "fixed 4 MB overwrite leaves the bulk of a LUKS2 header "
                "(16.5+ MiB) recoverable",
                "4: BIP-39 mnemonic-to-passphrase flows couple two "
                "high-value secrets and route them through a browser "
                "context - methodology + warning only; no seed, "
                "mnemonic, or derivative material exists in this fleet",
                "5: absolute sbin paths everywhere (this host's user PATH "
                "omits /usr/sbin; a bare `cryptsetup` failure there is a "
                "PATH artifact, not a missing package)",
            ],
            "verified_trapdoors": [
                "sudo + process-substitution key files fail (sudo drops "
                "inherited fds; /dev/fd/N is unresolvable there) - use a "
                "real 0600 key file",
                "--key-file reads RAW BYTES, trailing newline included; "
                "here-strings append newline; printf '%s' does not - the "
                "two produce different keys by design",
            ],
            "bip39_stance": (
                "do not couple wallet-recovery material to disk "
                "encryption; if a flow REQUIRES it: offline live-USB "
                "host, a purpose-generated mnemonic, local on-box KDF, "
                "and never a mnemonic in use as a wallet; this fleet "
                "carries no example material"),
            "image_key_envelope": (
                "generic form: prefix-marker || staged image bytes || "
                "suffix-marker, SHA-512 pinned on BOTH the image and the "
                "derived key; classify as obscurity-not-secrecy - a "
                "decoy/deception layer around a real key, never a "
                "replacement; never re-download third-party media at "
                "use time"),
            "consent_rail": (
                "file-backed scratch containers only; block-device ops "
                "require owner-signed consent; planner results never "
                "execute"),
        }
