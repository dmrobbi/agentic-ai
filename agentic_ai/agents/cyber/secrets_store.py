"""Secrets-store wiring (KA-094): fleet-agent credentials ride the OpenClaw
secrets pattern (masked flows) - NEVER environment variables and NEVER
command-line arguments.

DESIGN CONTRACT (accepted design, task [94]):
  - credentials live in a NAMED store: a 0600 JSON file for file_path-backed
    stores, or an INJECTED reader callable; agents never receive credential
    values through env/argv - the op holds a reference string instead;
  - callers hold refs: get_ref(name) -> "SECRETREF:<NAME>" is the handle
    that flows through plans/logs/op returns (idempotent: feeding a formed
    ref back yields the same ref; nested/ref-mangled names are rejected);
  - values are resolved ONLY at use-site: resolve(ref) is the one
    sanctioned plaintext path, called by the op that actually consumes the
    credential (e.g. builds an auth header); a ref with the wrong prefix is
    REJECTED, a missing/corrupt store reads as None;
  - anything ELSE an op returns is MASKED: refs only from get_ref, masked
    entries ("****"+last4, or "****" when shorter) from get_masked, lifecycle
    dicts from describe_flow, masked acks from put - pinned by
    tests/test_secrets_store.py::test_no_plaintext_in_op_returns.

DEFAULT FILE READER + 0600 PERMISSION NOTES:
  With no injected reader the store reads a JSON file shaped
  {"schema": "openclaw_secrets_store/v1", "values": {<name>: <value>, ...}}
  at file_path. Missing file, corrupt JSON, non-dict JSON, a missing
  "values" subdict, or a non-string entry all TOLERATE to None (never raise
  on read). Such a store file holds credential PLAINTEXTS by design, so it
  must stay owner-only: put() opens with strict 0600 os.open flags and
  re-applies chmod 0600 after every write (umask-hardened, O_NOFOLLOW when
  the platform has it). Operators keep the file on a private mount and back
  it up out-of-band; nothing here is a secret manager for a multi-user
  machine. put merges over prior "values" contents (corrupt prior contents
  are tolerated and reset fresh); put requires a file_path-backed store.

READER FAULT POLICY: an injected reader fault RAISES (the use-site sees
it, per use-site resolution); file-store faults read as None (tolerated).
An injected reader that returns a non-None non-string is a store-contract
violation raising a ValueError that names the type, never the value.

PURE MODULE: no execution facilities (process spawning, interpreter eval,
dynamic exec), no network dialing, no environment/argument reads, no print
or log facilities; values are never logged or printed and reprs mask the
store. The reader is the one spec-mandated injection point; the
point; the file_path JSON reader is the spec-mandated default."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

REF_PREFIX = "SECRETREF:"
SECRETS_SCHEMA = "openclaw_secrets_store/v1"
NAME_RE = r"[A-Za-z0-9._\-]{1,64}"
MASK = "****"
MASK_MIN_LAST4 = 8  # values shorter than this mask fully; longer keep last4
FILE_FLAGS_BASE = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
FILE_FLAGS = FILE_FLAGS_BASE | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def scrub_secret_name(name: Any) -> str:
    """The shared input gate for secret names (wp_scrub_target pattern)."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("secret name must be a non-empty string")
    scrubbed = name.strip()
    if not re.fullmatch(NAME_RE, scrubbed):
        raise ValueError(
            "rejected secret name (A-Za-z0-9 dot dash underscore, 1..64): %r"
            % (name[:32],))
    return scrubbed


def _reader_violation(value: Any) -> ValueError:
    """Store-contract error naming the type only - never the value."""
    return ValueError(
        "injected reader returned %s; contract is value-or-None"
        % type(value).__name__)


class SecretsStore:
    """Named credential store for fleet agents (masked flows; never env/args).

    reader, when injected, is callable(name) -> value-or-None and WINS all
    reads; otherwise the file reader applies to file_path (missing/corrupt
    tolerated to None). file_path is also the ONLY write path: put() needs
    it. Values resolve at use-site via resolve(); every other op returns
    refs or masked entries only.
    """

    def __init__(self, reader: Any = None, file_path: Any = None,
                 **_legacy: Any) -> None:
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if reader is not None and not callable(reader):
            raise ValueError(
                "reader must be a callable(name) -> value-or-None, got %s"
                % type(reader).__name__)
        if file_path is not None and not isinstance(file_path, (str, bytes,
                                                                os.PathLike)):
            raise ValueError(
                "file_path must be a filesystem path or None, got %s"
                % type(file_path).__name__)
        self.reader = reader
        self.file_path = (None if file_path is None
                          else os.fspath(file_path))

    @staticmethod
    def _ref_name(ref: Any) -> str:
        """Validate one 'SECRETREF:' handle and return the store name."""
        if not isinstance(ref, str) or not ref.startswith(REF_PREFIX):
            shown = (ref[:32] if isinstance(ref, str)
                     else type(ref).__name__)
            raise ValueError(
                "resolve takes a '%s'-prefixed ref, got: %r" % (REF_PREFIX,
                                                                shown))
        return scrub_secret_name(ref[len(REF_PREFIX):])

    def _read(self, name: str) -> Optional[str]:
        """Route one name lookup: injected reader wins; file reader next."""
        if self.reader is not None:
            value = self.reader(name)
            if value is None:
                return None
            if not isinstance(value, str):
                raise _reader_violation(value)
            return value
        return self._file_read(name)

    def _file_read(self, name: str) -> Optional[str]:
        """Tolerant JSON file lookup: any store-side fault reads as None."""
        if self.file_path is None:
            return None
        try:
            data = json.loads(
                Path(self.file_path).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return None  # missing/corrupt store file tolerated
        if not isinstance(data, dict):
            return None
        values = data.get("values")
        if not isinstance(values, dict):
            return None
        value = values.get(name)
        return value if isinstance(value, str) else None

    def get_ref(self, name: Any, **_legacy: Any) -> str:
        """The only credential handle for plans/op returns: 'SECRETREF:<NAME>'."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if isinstance(name, str) and name.startswith(REF_PREFIX):
            # idempotent: a formed ref maps to itself (remainder re-validated)
            scrub_secret_name(name[len(REF_PREFIX):])
            return name
        return REF_PREFIX + scrub_secret_name(name)

    def resolve(self, ref: Any, **_legacy: Any) -> Optional[str]:
        """Use-site primitive: one ref -> one value-or-None from the store.

        The ONLY public path that may return plaintext, and only to the
        caller that consumes it right here; wrong-prefix refs are rejected
        and missing values read as None. Injected-reader faults raise.
        Never log the return; it is the credential.
        """
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        name = self._ref_name(ref)
        return self._read(name)

    @staticmethod
    def mask(value: Any, **_legacy: Any) -> str:
        """'****'+last4 for values of len>=8; '****' when shorter or None."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if value is None:
            return MASK
        if not isinstance(value, str):
            raise ValueError(
                "mask takes a text value or None, got %s"
                % type(value).__name__)
        if len(value) < MASK_MIN_LAST4:
            return MASK
        return MASK + value[-4:]

    def get_masked(self, name: Any, **_legacy: Any) -> Dict[str, Any]:
        """Masked status entry for one secret (never returns plaintext)."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        scrubbed = scrub_secret_name(name)
        value = self._read(scrubbed)
        return {
            "name": scrubbed,
            "masked": MASK if value is None else self.mask(value),
            "present": value is not None,
        }

    def put(self, name: Any, value: Any, **_legacy: Any) -> Dict[str, Any]:
        """Persist one credential into the 0600 file store (masked ack).

        File-store write ONLY: requires file_path; a reader-only store
        refuses. Missing prior file starts fresh; corrupt prior contents
        are tolerated and reset. Writes {"schema": ..., "values": {...}}
        via strict-0600 os.open flags plus a post-write chmod 0600. Never
        logs the value; the ack carries the ref and the masked form.
        """
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if self.file_path is None:
            raise ValueError("put requires a file_path-backed secrets store")
        scrubbed = scrub_secret_name(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("put takes a non-empty text value")
        prior: Dict[str, str] = self._load_file_values()
        prior[scrubbed] = value
        fd = os.open(str(self.file_path), FILE_FLAGS, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"schema": SECRETS_SCHEMA, "values": prior},
                          handle, indent=2, sort_keys=True)
            os.chmod(str(self.file_path), 0o600)  # umask-hardened strict 0600
        except BaseException:
            raise  # never unlink a secrets file mid-flight; surface the fault
        return {"written": True, "name": scrubbed,
                "ref": REF_PREFIX + scrubbed, "masked": self.mask(value)}

    def _load_file_values(self) -> Dict[str, str]:
        """Prior string entries from the file store (corrupt tolerated, reset)."""
        if self.file_path is None or not Path(self.file_path).exists():
            return {}
        try:
            loaded = json.loads(
                Path(self.file_path).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        values = loaded.get("values")
        if not isinstance(values, dict):
            return {}
        return {key: val for key, val in values.items()
                if isinstance(key, str) and isinstance(val, str)}

    def describe_flow(self, **_legacy: Any) -> Dict[str, Any]:
        """Register -> request (masked entry) -> resolve-at-use-site lifecycle."""
        del _legacy  # legacy callers may pass extras; absorbed, never forwarded
        if self.reader is not None:
            store_kind = "injected-reader"
        elif self.file_path is not None:
            store_kind = "file-0600-json"
        else:
            store_kind = "unbound"
        steps: List[Dict[str, Any]] = [
            {"step": "register", "actor": "owner",
             "detail": "the credential value is written once into the named "
                       "secrets store (0600 JSON file via put); agents "
                       "never receive the value through env or argv"},
            {"step": "request", "actor": "agent ops",
             "detail": "ops hold SECRETREF:<NAME> handles; humans and logs "
                       "see only the masked entry (**** + last4) from "
                       "get_masked, never the value"},
            {"step": "resolve-at-use-site", "actor": "consuming op",
             "detail": "resolve(ref) fetches the value only inside the op "
                       "that actually uses it; every op result returned to "
                       "callers stays masked"},
        ]
        notes: List[str] = [
            "credentials never travel via environment variables or argv",
            "values are never logged or printed; reprs mask the store",
            "only resolve() returns plaintext, only to the use-site caller",
            "missing or corrupt store files read as None (tolerated)",
        ]
        return {"flow": "openclaw secrets pattern", "store": store_kind,
                "steps": steps, "notes": notes,
                "ref_prefix": REF_PREFIX, "schema": SECRETS_SCHEMA}

    def __repr__(self) -> str:
        reader = "injected" if self.reader is not None else "default"
        return "SecretsStore(reader=%s, file_path=%r)" % (reader,
                                                          self.file_path)
