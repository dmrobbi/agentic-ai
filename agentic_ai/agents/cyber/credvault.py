"""Credential vaulting (KA-056): the VAULT CONTRACT for planner logic.

Contract:
- Credential VALUES live only in a caller-supplied env file: `KEY=VALUE`
  lines, `#` comment lines ignored, blank lines ignored, first `=` splits,
  both sides trimmed (the mailbox reports@ env-file convention).
- Plans carry opaque credential REFERENCES, never values: `@cred:<KEY>@`.
  The reference token binds 1:1 to the env-file KEY.
- `cred_ref(name)` builds the token; `build_command(argv, secret_names)`
  emits the command string in which every argument that exactly names a
  declared credential becomes its reference. The emit path never touches
  values because it is never given any.
- `build_plan(command)` validates a refs-form command line and extracts
  the required-refs manifest (order of first appearance, deduplicated).
- `resolve(plan, env_path)` is the exec-time seam and the ONLY file read
  in this module: values come strictly from the PATH PASSED IN BY THE
  CALLER. Success returns an executor-facing value map ("env") plus a
  values-free "audit" projection; the "env" map must never be logged,
  serialized, or passed anywhere beyond the process runner. The command
  is never materialized - it keeps its reference form.
- Missing or unreadable env files, malformed env-file content, and
  unsatisfied references resolve to a deterministic plain-dict error
  ("ok": False) at the seam - never an exception there. parse_env_file
  itself raises EnvFileError (line numbers and key names only, never raw
  line or value content) so the pure parse stays directly testable;
  read_env_file converts that into the error dict.
- `redact(payload, values)` is the scrub path that proves emitted and
  returned dict surfaces never embed resolved values: every literal
  occurrence of any secret VALUE becomes REDACTED. It is also the safety
  net for caller-supplied literals that build_plan cannot detect.
- Planner purity: no chassis import, no wall clock, no execution, eval,
  or network facilities (source-scan pinned in the tests).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

REF_PREFIX = "@cred:"
REF_SUFFIX = "@"
NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
REF_PATTERN = re.compile(r"@cred:([A-Za-z0-9_.-]+)@")

REDACTED = "<redacted>"
ERROR_KIND = "credvault_env_file_error"
REASON_NOT_FOUND = "not_found"
REASON_UNREADABLE = "unreadable"
REASON_MALFORMED = "malformed"
REASON_UNSATISFIED = "unsatisfied"


class EnvFileError(ValueError):
    """Env-file content violates the documented KEY=VALUE contract.

    Messages carry line numbers and key names only - never raw line or
    value content - so error paths cannot leak secret values.
    """


@dataclass(frozen=True)
class VaultPlan:
    """A planned command line plus its required-references manifest.

    `command` carries placeholder references only - the emit helpers are
    never handed values - and `required` lists the env-file keys needed
    at exec time, in order of first appearance, deduplicated.
    """

    command: str
    required: Tuple[str, ...]


@dataclass(frozen=True)
class EnvFile:
    """Outcome of the single read seam: entries, or a failure."""

    entries: Optional[Dict[str, str]]
    error: Optional[Dict[str, Any]]


def _env_error(reason: str, detail: str, env_path: Any) -> Dict[str, Any]:
    """Deterministic values-free error dict (path and key names only)."""
    return {
        "ok": False,
        "error": ERROR_KIND,
        "reason": reason,
        "detail": detail,
        "env_path": str(env_path),
    }


def cred_ref(name: str) -> str:
    """Opaque credential reference for `name`: token `@cred:<name>@`.

    The token equals the env-file KEY binding: at exec time a reference
    resolves only when the caller-supplied env file defines that key.
    Raises ValueError for any name outside [A-Za-z0-9_.-]+ (also rejects
    non-strings) so no crafted name can smuggle separators into plans or
    env files.
    """
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "invalid credential name: expected non-empty [A-Za-z0-9_.-]+"
        )
    return REF_PREFIX + name + REF_SUFFIX


def build_command(argv: Iterable[str], secret_names: Iterable[str]) -> VaultPlan:
    """Emit the vaulted planner command line.

    Each argv element that EXACTLY names a declared credential becomes
    that credential's opaque reference; every other element passes
    through untouched (exact arg match only - suffixed or embedded names
    are not credentials). Values can never appear because this path is
    never given any. The manifest lists references actually present in
    the command, in order of first appearance, deduplicated;
    declared-but-unused names are omitted. Raises ValueError for any
    invalid declared name and TypeError for non-string argv elements.
    """
    declared: List[str] = []
    for name in secret_names:
        cred_ref(name)  # validates every declared name up front
        if name not in declared:
            declared.append(name)
    tokens: List[str] = []
    required: List[str] = []
    for arg in argv:
        if not isinstance(arg, str):
            raise TypeError("build_command expects a string argv")
        if arg in declared:
            if arg not in required:
                required.append(arg)
            tokens.append(cred_ref(arg))
        else:
            tokens.append(arg)
    return VaultPlan(command=" ".join(tokens), required=tuple(required))


def build_plan(command: str) -> VaultPlan:
    """Validate a planner-written refs-form command line and extract its
    required-refs manifest (order of first appearance, deduplicated).

    Raises ValueError on malformed reference tokens (unclosed token,
    empty name, or invalid name) and TypeError on non-string input -
    caller-contract errors propagate. Values are not inspected here (the
    planner does not hold any); redact() is the guaranteed scrub for any
    literal a caller managed to embed in the command line.
    """
    if not isinstance(command, str):
        raise TypeError("build_plan expects a string command")
    residue = REF_PATTERN.sub("", command)
    if REF_PREFIX in residue:
        raise ValueError(
            "malformed credential reference in command: unclosed token, "
            "empty name, or invalid name"
        )
    required: List[str] = []
    for match in REF_PATTERN.finditer(command):
        name = match.group(1)
        if name not in required:
            required.append(name)
    return VaultPlan(command=command, required=tuple(required))


def plan_audit(plan: VaultPlan) -> Dict[str, Any]:
    """Values-free, JSON-safe projection of a plan for records/audit."""
    return {"command": plan.command, "required": list(plan.required)}


def parse_env_file(text: str) -> Dict[str, str]:
    """Pure parse of env-file CONTENT (mailbox env-file convention).

    `KEY=VALUE` lines; `#` comment lines, blank lines, and lines without
    `=` are skipped; the first `=` splits; both sides trimmed (leading
    and trailing whitespace is not part of values). Deterministic:
    raises EnvFileError for an empty key or conflicting duplicate
    entries - the message names the line number and the key, never the
    raw line, so a malformed value cannot leak through an error path.
    An identical duplicate line is accepted as one entry.
    """
    if not isinstance(text, str):
        raise TypeError("parse_env_file expects env-file content text")
    entries: Dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise EnvFileError(
                f"malformed env file: empty key at line {lineno}"
            )
        if key in entries and entries[key] != value:
            raise EnvFileError(
                f"malformed env file: conflicting duplicate entry for "
                f"key {key!r} at line {lineno}"
            )
        entries[key] = value
    return entries


def read_env_file(env_path: Any) -> EnvFile:
    """The single file-read seam in this module: reads the PATH PASSED
    IN BY THE CALLER through the env-file contract and parses it.

    Never raises: a missing file, an unreadable path, and malformed
    content all become a deterministic values-free error dict on
    `error` (with `entries` set to None) - the shape resolve() reports.
    """
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return EnvFile(
            entries=None,
            error=_env_error(REASON_NOT_FOUND, "env file not found", env_path),
        )
    except (OSError, ValueError) as exc:
        return EnvFile(
            entries=None,
            error=_env_error(
                REASON_UNREADABLE,
                "env file unreadable: " + exc.__class__.__name__,
                env_path,
            ),
        )
    try:
        entries = parse_env_file(text)
    except EnvFileError as exc:
        return EnvFile(
            entries=None,
            error=_env_error(REASON_MALFORMED, str(exc), env_path),
        )
    return EnvFile(entries=entries, error=None)


def resolve(plan: VaultPlan, env_path: Any) -> Dict[str, Any]:
    """Exec-time resolution: the ONLY place values enter this module.

    Reads the caller-provided env-file path via read_env_file, then
    delivers exactly the plan's required references.

    Success: {"ok": True, "env": {ref: value, ...}, "audit": {...}}.
    The "env" map is executor-facing only - it feeds the process runner
    - and must never be logged, serialized, or returned anywhere else.
    The command is never materialized: it keeps its reference form; a
    values-free view lives under "audit".

    Failure: deterministic error dict ("ok": False; "reason" is
    not_found, unreadable, malformed, or unsatisfied; "detail" names
    paths and key names only; required refs listed under "required").
    Never raises at the seam - except TypeError for a non-VaultPlan
    caller-contract breach.
    """
    if not isinstance(plan, VaultPlan):
        raise TypeError("resolve() expects a VaultPlan from build_plan()")
    loaded = read_env_file(env_path)
    if loaded.error is not None:
        return dict(loaded.error, required=list(plan.required))
    entries = loaded.entries or {}
    missing = [name for name in plan.required if name not in entries]
    if missing:
        return dict(
            _env_error(
                REASON_UNSATISFIED,
                "required references missing from env file: "
                + ", ".join(missing),
                env_path,
            ),
            required=list(plan.required),
        )
    empties = [name for name in plan.required if entries[name] == ""]
    if empties:
        return dict(
            _env_error(
                REASON_UNSATISFIED,
                "empty value for required references: " + ", ".join(empties),
                env_path,
            ),
            required=list(plan.required),
        )
    env_map = {name: entries[name] for name in plan.required}
    return {
        "ok": True,
        "env": env_map,
        "audit": {
            "command": plan.command,
            "required": list(plan.required),
            "resolved_count": len(env_map),
            "env_path": str(env_path),
        },
    }


def redact(payload: Any, values: Mapping[str, str]) -> Any:
    """Deep scrub for anything that may reach logs, audit, or plans:
    every literal occurrence of any secret VALUE becomes REDACTED.

    Supported shapes: str, Mapping, list, tuple, set, frozenset, and
    scalars (returned untouched). Mapping keys are scrubbed too; entries
    whose keys collide after scrubbing merge (scrubbing is lossy by
    design). Empty and whitespace-only values are ignored so a blank
    credential cannot scrub entire payloads. Longer values are replaced
    before shorter ones so a value contained in another cannot survive.
    """
    scrubbers = sorted(
        (value for value in dict.fromkeys(values.values()) if value.strip()),
        key=len,
        reverse=True,
    )

    def scrub(text: str) -> str:
        cleaned = text
        for value in scrubbers:
            if value in cleaned:
                cleaned = cleaned.replace(value, REDACTED)
        return cleaned

    if isinstance(payload, str):
        return scrub(payload)
    if isinstance(payload, Mapping):
        return {
            (scrub(key) if isinstance(key, str) else key): redact(item, values)
            for key, item in payload.items()
        }
    if isinstance(payload, list):
        return [redact(item, values) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact(item, values) for item in payload)
    if isinstance(payload, (set, frozenset)):
        return type(payload)(redact(item, values) for item in payload)
    return payload