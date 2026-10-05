"""Egress guard (KA-055): static classification of network-touching commands.

Contract:
- `eg_scrub_command(command)` scrubs an UNTRUSTED command string before
  any parsing (raises ValueError on injection shapes, documented below).
  `classify_egress(command)` then parses it into per-target rows, and
  `egress_gate(...)` decides go / no-go as a house `(bool, reason)` tuple.
- `classify_egress` returns the classification dict:
    {"command_scrubbed": str, "verb": str, "network_touching": bool,
     "targets": ({"raw", "host", "shape", "egress_class",
                  "required_auth"}, ...)}
  Targets are deduplicated on (raw, shape) and preserve first-appearance
  order. `shape` is one of "url" | "ip" | "cidr" | "hostport" |
  "hostpath" | "name" | "unknown".
- Per target, `egress_class` is "rfc1918" (private), "external",
  "localhost", or "unset" (unresolvable / unclassifiable), and
  `required_auth` is "lab_staging" (rfc1918), "owner_auth_tag" (external
  AND unset - the conservative default below), or "none" (localhost).
  `AUTH_TAG` is the designated owner tag value the gate demands.
- `egress_gate(classification_or_command, lab_staged=..., auth_tags=...)`
  returns `(go, reason)` only when EVERY target is covered: rfc1918 rows
  require lab_staged=True; external AND unset rows require AUTH_TAG in
  auth_tags; localhost rows pass unconditionally. Failures are
  fail-closed: the FIRST uncovered target (row order) names the reason.
  A `network_touching=False` classification always plans as go.
  The gate accepts either the classification dict (recommended flow:
  classify once, then gate) or a raw command string; anything else, and
  any malformed / inconsistent classification dict, raises ValueError.

CLASSIFICATION RULES (static string work only - never executes it, never
resolves a name, no lookups of any kind):
- The command string scrubs first (rejects shell chaining / expansion /
  redirect metacharacters `; | &`, backticks, `$(...)`, subshell parens,
  `<` / `>` redirection, backslash escapes, control characters, and
  over-length strings). Quoted strings inside are legal, but a shell
  metacharacter is rejected even hidden inside quotes, because a quoted
  separator would hide extra commands from static parsing.
- Every shell-argv token (via shlex) plus every quote-stripped
  whitespace piece of the raw string (so targets inside quoted
  subcommand payloads like `bash -c 'wget http://host/x'` are still
  seen) is scanned:
    1. URL route: an absolute URL with one of NETWORK_URL_SCHEMES counts
       by its netloc HOST only. Userinfo decoys such as
       `http://10.0.0.1@evil.com` classify from `evil.com` - never from
       the userinfo, in either decoy direction; a non-literal host then
       plans as unset per the DNS strategy below.
    2. Literal-IP route: valid IPv4/IPv6 addresses, also after
       `[v6]`, `[v6]:port`, `user@host`, `user@host:path` and
       `host:digits` reductions, classify from their own value.
    3. CIDR route: `a.b.c.d/p` (or IPv6) scan targets classify private
       only when the network lies fully inside RFC1918 (or the IPv6
       ULA analog fc00::/7); anything else is external.
    4. IP-shaped tokens that ipaddress cannot parse (leading-zero /
       octal tricks like `010.0.0.1`, oversized octets) are NEVER
       classified private by shape: they become "unset" rows demanding
       the owner tag (fail-closed).
    5. Name route: in a network-tool command (verb in NETWORK_TOOLS)
       every other positional-shaped token (option values included) is
       treated as a possible target - except the verb token itself
       (argv[0]), which is never a name row (a tool name is not an
       endpoint). This planner may OVER-demand the owner tag on
       option values of network tools - that is the intended
       fail-closed bias (an unknown shape is never waived).
- Loopback: 127.0.0.0/8, ::1, and localhost / *.localhost names.
- Private: RFC1918 (10/8, 172.16/12, 192.168/16) plus IPv6 ULA
  fc00::/7. Link-local / metadata space (169.254.169.254 etc.) is
  external and demands the tag - never waved through.
- Not statically visible: a command with no URL, IP, CIDR, host:port,
  host:path, or name-row token is reported network_touching=False.
  Name-only payloads inside wrappers are out of scope (nothing is
  resolved), but explicit URL- or IP-shaped pieces anywhere in the
  string are still caught (see the piece scan above).
- NETWORK_TOOLS is a documented snapshot of common endpoint-first
  tools; multi-subcommand tools (git, docker, ...) are deliberately
  absent - their explicit URLs / IP literals / CIDRs are still caught
  by the global routes; only bare-NAME targets are not.

DNS RESOLUTION STRATEGY (the module's core posture, stated explicitly):
- NO name resolution happens at plan time. Classification is pure
  string + stdlib-ipaddress work: no DNS lookups, no hostname
  resolution, no I/O (pinned by source-scan in the tests).
- A literal IP is classified from its own bytes. A non-literal
  hostname is UNRESOLVABLE at plan time, so it plans as class "unset"
  and demands external-grade authorization (the owner auth tag,
  AUTH_TAG) - the most restrictive treatment. Classification refuses
  to guess internal-ness from a name: DNS can point a friendly label
  anywhere, so nothing unresolved ever plans as "private".
- Consequence: lab machines must be targeted by their literal RFC1918
  address (then lab staging covers them), or the owner authorizes the
  unresolved name explicitly by providing AUTH_TAG. This makes name
  aliasing / DNS rebinding evasion inert at plan time.

Purity: no chassis import, no clock, no command execution, no network
calls of any kind; stdlib shlex / re / ipaddress / urllib.parse (used
for static URL-host extraction only). Wiring the guard into an
execution gate is an integration task's decision; this module carries
the semantics only.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

__all__ = (
    "AUTH_TAG",
    "CLASSIFICATION_KEYS",
    "CLASS_EXTERNAL",
    "CLASS_LOCALHOST",
    "CLASS_RFC1918",
    "CLASS_UNSET",
    "NETWORK_TOOLS",
    "NETWORK_URL_SCHEMES",
    "REQ_LAB_STAGING",
    "REQ_NONE",
    "REQ_OWNER_TAG",
    "TARGET_KEYS",
    "classify_egress",
    "eg_scrub_command",
    "egress_gate",
)

# The one owner-issued tag that clears an external (or unset) target.
AUTH_TAG = "EGRESS-AUTH"
# Scrub budget: commands beyond this length are rejected outright.
MAX_COMMAND_CHARS = 4096

CLASS_RFC1918 = "rfc1918"
CLASS_EXTERNAL = "external"
CLASS_LOCALHOST = "localhost"
CLASS_UNSET = "unset"
REQ_LAB_STAGING = "lab_staging"
REQ_OWNER_TAG = "owner_auth_tag"
REQ_NONE = "none"

TARGET_KEYS = ("raw", "host", "shape", "egress_class", "required_auth")
CLASSIFICATION_KEYS = (
    "command_scrubbed", "verb", "network_touching", "targets"
)

# egress_class -> the authorization it demands (pinned consistency
# contract; the gate validates and rejects inconsistent dicts).
_CLASS_REQ: Dict[str, str] = {
    CLASS_RFC1918: REQ_LAB_STAGING,
    CLASS_EXTERNAL: REQ_OWNER_TAG,
    CLASS_UNSET: REQ_OWNER_TAG,
    CLASS_LOCALHOST: REQ_NONE,
}

# Endpoint-first tools: their bare positional tokens are name-row
# candidates. Documented snapshot, deliberately small; multi-
# subcommand tools (git, docker, ...) rely on explicit URL / IP routes.
NETWORK_TOOLS: FrozenSet[str] = frozenset({
    "curl", "wget", "wget2", "ping", "ping6", "ssh", "scp", "sftp",
    "ftp", "telnet", "rsync", "nc", "netcat", "ncat", "socat", "nmap",
    "dig", "nslookup", "host", "whois", "traceroute", "tracepath", "mtr",
})

NETWORK_URL_SCHEMES: FrozenSet[str] = frozenset({
    "http", "https", "ftp", "ftps", "sftp", "ssh", "rsync", "telnet",
    "ldap", "ldaps", "ws", "wss", "git", "git+http", "git+https",
    "git+ssh",
})

_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
# Strict RFC1918 plus the IPv6 ULA analog; link-local / metadata space
# is deliberately NOT here (it demands the owner tag).
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

_QUAD_RE = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")
_BRACKET_RE = re.compile(r"\A\[([^[\]]+)\](?::(\d+))?\Z")
_NAME_RE = re.compile(r"\A[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
FORBIDDEN_META = (";", "|", "&", "`", "$", "(", ")", "<", ">", "\\")


def eg_scrub_command(command: Any) -> str:
    """Scrub an untrusted command string before any static parsing.

    Rejects non-string, empty, control-character-bearing, shell-chain
    or expansion metacharacter, and over-length input with ValueError;
    returns the stripped command otherwise.
    """
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    scrubbed = command.strip()
    if CTRL_RE.search(scrubbed):
        raise ValueError(
            "rejected command with control characters: %r" % scrubbed
        )
    for meta in FORBIDDEN_META:
        if meta in scrubbed:
            raise ValueError(
                "rejected command with shell metacharacter %r" % meta
            )
    if len(scrubbed) > MAX_COMMAND_CHARS:
        raise ValueError(
            "rejected over-long command (>%d chars)" % MAX_COMMAND_CHARS
        )
    return scrubbed


def _ip_literal(token: str) -> Optional[ipaddress.IPv4Address]:
    """Parse the token as a literal IP address; None when not one."""
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def _host_class(host: str) -> Tuple[str, str]:
    """(egress_class, required_auth) for a scrubbed host label."""
    addr = _ip_literal(host)
    if addr is None:
        label = host.strip(".").lower() if host else ""
        if label == "localhost" or label.endswith(".localhost"):
            return CLASS_LOCALHOST, REQ_NONE
        return CLASS_UNSET, REQ_OWNER_TAG
    if any(addr in net for net in _LOOPBACK_NETS):
        return CLASS_LOCALHOST, REQ_NONE
    if any(addr in net for net in _PRIVATE_NETS):
        return CLASS_RFC1918, REQ_LAB_STAGING
    return CLASS_EXTERNAL, REQ_OWNER_TAG


def _cidr_class(net: ipaddress.IPv4Network) -> Tuple[str, str]:
    """(egress_class, required_auth) for a parsed CIDR target."""
    for nets, cls, req in (
        (_LOOPBACK_NETS, CLASS_LOCALHOST, REQ_NONE),
        (_PRIVATE_NETS, CLASS_RFC1918, REQ_LAB_STAGING),
    ):
        for candidate in nets:
            if net.version != candidate.version:
                continue
            try:
                if net.subnet_of(candidate):  # type: ignore[union-attr]
                    return cls, req
            except (TypeError, ValueError):
                continue
    return CLASS_EXTERNAL, REQ_OWNER_TAG


def _url_host(token: str) -> Optional[str]:
    """The netloc HOST of an absolute network-URL token, else None."""
    try:
        parsed = urlparse(token)
    except ValueError:
        return None
    if parsed.scheme.lower() not in NETWORK_URL_SCHEMES or not parsed.netloc:
        return None
    # parsed.hostname strips userinfo and port (and lowercases). A
    # decoy userinfo never influences the class.
    host = parsed.hostname
    if not host:
        return None
    return host


def _plain_name(token: str) -> bool:
    """Hostname-shaped AND carrying at least one letter (pure digit /
    no-letter tokens are never name rows: ports, counts, timestamps)."""
    return bool(_NAME_RE.match(token)) and any(c.isalpha() for c in token)


def _reduce_target_token(token: str, network_verb: bool) -> Optional[Tuple[str, str, bool]]:
    """Reduce one scanned token to (host, shape, force_unset) or None.

    The host is the string the egress class is decided from; shape is
    the documented taxonomy slug; force_unset marks IP-shaped-but-
    unparseable tokens, which never classify private by shape.
    """
    # 1. URL route (must precede colon reductions: scheme://host:port)
    url_host = _url_host(token)
    if url_host is not None:
        return url_host, "url", False
    # 2. Full-token literal IP
    if _ip_literal(token) is not None:
        return token, "ip", False
    # 3. IP-shaped but unparseable (octal tricks, big octets): unset
    if _QUAD_RE.match(token):
        return token, "unknown", True
    # 4. Bracketed IPv6 (bare or :port)
    m = _BRACKET_RE.match(token)
    if m is not None and _ip_literal(m.group(1)) is not None:
        shape = "hostport" if m.group(2) is not None else "ip"
        return m.group(1), shape, False
    # 5. user@host[:port|:path] reductions (scp / rsync / git remotes)
    if "@" in token:
        remote = token.rsplit("@", 1)[1]
        sub = _reduce_target_token(remote, network_verb)
        if sub is not None:
            return sub[0], sub[1], sub[2]
        return None
    # 6. CIDR scan target
    if "/" in token:
        try:
            ipaddress.ip_network(token, strict=False)
        except (ValueError, TypeError):
            net = None
        else:
            return token, "cidr", False
    # 7. host:digits (hostport) and host:path (hostpath) reductions;
    #    skipped for URL-ish tokens (they contain "://" already).
    if "://" not in token and ":" in token:
        left, _, right = token.partition(":")
        if right.isdigit() and (":" not in left):
            if _ip_literal(left) is not None or _plain_name(left):
                return left, "hostport", False
        elif ":" not in right and _ip_literal(left) is not None:
            # scp / rsync style host:path with a literal-IP host
            return left, "hostpath", False
        elif (":" not in right and _plain_name(left)
              and ("/" in right or "." in right)):
            return left, "hostpath", False
    # 8. Bare-name route: only inside endpoint-first network tools.
    if network_verb and _plain_name(token):
        return token, "name", False
    return None


def _row(raw: str, host: str, shape: str, eclass: str, req: str) -> Dict[str, str]:
    target: Dict[str, str] = {
        "raw": raw,
        "host": host,
        "shape": shape,
        "egress_class": eclass,
        "required_auth": req,
    }
    return target


def _scan_piece(token: str, network_verb: bool) -> Optional[Dict[str, str]]:
    """Classify one token; None when it is not a network target."""
    if not token or token.startswith("-"):
        return None
    reduced = _reduce_target_token(token, network_verb)
    if reduced is None:
        return None
    host, shape, force_unset = reduced
    if force_unset:
        # IP-shaped-but-unparseable: documented fail-closed treatment.
        eclass, req = CLASS_UNSET, REQ_OWNER_TAG
    elif shape == "cidr":
        try:
            net = ipaddress.ip_network(host, strict=False)
        except (ValueError, TypeError):
            eclass, req = CLASS_UNSET, REQ_OWNER_TAG
        else:
            eclass, req = _cidr_class(net)
    else:
        eclass, req = _host_class(host)
    return _row(token, host, shape, eclass, req)


def classify_egress(command: Any) -> Dict[str, Any]:
    """Scrub and statically classify a command's network targets.

    Returns the classification dict; raises ValueError on scrub or
    shell-quoting failures. Pure: no execution, no resolvable names.
    """
    scrubbed = eg_scrub_command(command)
    try:
        argv = shlex.split(scrubbed)
    except ValueError as exc:
        raise ValueError(
            "unparseable command (shell quoting): %s" % exc
        ) from None
    verb = (argv[0].lower() if argv else "")
    pieces: List[str] = list(argv)
    for piece in scrubbed.split():
        if len(piece) > 1 and piece[0] == piece[-1] and piece[0] in "'\"":
            piece = piece[1:-1]
        pieces.append(piece)
    network_verb = verb in NETWORK_TOOLS
    targets: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for index, piece in enumerate(pieces):
        if piece in seen:
            continue
        seen.add(piece)
        # The verb slot (argv[0]) is never a bare-name target row:
        # a tool name is not an endpoint. Its URL/IP/CIDR/colon
        # routes stay active (a command may START at its target).
        slot_verb = network_verb and index != 0
        row = _scan_piece(piece, slot_verb)
        if row is not None:
            targets.append(row)
    return {
        "command_scrubbed": scrubbed,
        "verb": verb,
        "network_touching": bool(targets),
        "targets": tuple(targets),
    }


def _scrub_auth_tags(auth_tags: Iterable[str]) -> FrozenSet[str]:
    """Validate owner-provided auth tags; malformed input FAILS the
    gate loudly (a silently-dropped tag would fake authorization)."""
    if isinstance(auth_tags, str):
        auth_tags = (auth_tags,)
    tags: Set[str] = set()
    try:
        tag_list = list(auth_tags)
    except TypeError:
        raise ValueError("auth_tags must be an iterable of tag strings") from None
    for tag in tag_list:
        if not isinstance(tag, str) or not _TAG_RE.match(tag.strip()):
            raise ValueError(
                "auth tag must be a plain word (letters, digits, . _ -), got %r"
                % (tag,)
            )
        tags.add(tag.strip())
    return frozenset(tags)


def _validate_classification(classification: Dict[str, Any]) -> Tuple[Tuple[Dict[str, str], ...], bool]:
    """Strict validation of a classification dict from external hands.
    Returns (rows, network_touching) or raises ValueError."""
    if not isinstance(classification, dict):
        raise ValueError("classification must be a classify_egress dict")
    rows = classification.get("targets")
    touching = classification.get("network_touching")
    if not isinstance(rows, (tuple, list)) or not isinstance(touching, bool):
        raise ValueError(
            "classification dict must come from classify_egress "
            "(missing 'targets' / 'network_touching')"
        )
    rows = tuple(rows)
    if touching != bool(rows):
        raise ValueError(
            "inconsistent classification: network_touching=%r with %d target(s)"
            % (touching, len(rows))
        )
    for row in rows:
        if not isinstance(row, dict) or not {"raw", "egress_class", "required_auth"} <= set(row):
            raise ValueError("malformed target row: %r" % (row,))
        klass = row["egress_class"]
        req = row["required_auth"]
        if klass not in _CLASS_REQ or req != _CLASS_REQ[klass]:
            raise ValueError(
                "inconsistent target row (class/auth mismatch): %r" % (row,)
            )
    return rows, touching


def egress_gate(
    classification_or_command: Union[str, Dict[str, Any]],
    *,
    lab_staged: bool = False,
    auth_tags: Iterable[str] = (),
) -> Tuple[bool, str]:
    """Decide go/no-go for an egress plan: a house (bool, reason) tuple.

    RFC1918 targets require lab_staged=True; external and unset targets
    require AUTH_TAG in auth_tags; localhost passes. Fail-closed: the
    first uncovered target names the reason.
    """
    if isinstance(classification_or_command, str):
        classification = classify_egress(classification_or_command)
    elif isinstance(classification_or_command, dict):
        classification = classification_or_command
    else:
        raise ValueError(
            "classification must be a classify_egress dict or a command string"
        )
    rows, touching = _validate_classification(classification)
    if not isinstance(lab_staged, bool):
        raise ValueError("lab_staged must be a bool")
    tags = _scrub_auth_tags(auth_tags)
    if not touching:
        return True, "go: no egress targets detected"
    for row in rows:
        raw = row["raw"]
        req = row["required_auth"]
        if req == REQ_NONE:
            continue
        if req == REQ_LAB_STAGING:
            if not lab_staged:
                return False, "no-go: target '%s' requires lab staging" % raw
            continue
        if AUTH_TAG not in tags:
            return False, (
                "no-go: target '%s' requires owner auth tag '%s'"
                % (raw, AUTH_TAG)
            )
    return True, "go: %d egress target(s) authorized" % len(rows)