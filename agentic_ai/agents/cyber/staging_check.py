"""Staging verification (KA-063): a pure in-staging gate for engagement targets.

Contract:
- `stage_check(targets, declaration, config=...)` statically decides whether
  every given target spec lies inside the caller-supplied lab/staging
  declaration, returning a deterministic `StageVerdict` (`as_dict()` is the
  JSON-ready decision dict). `targets` is one spec string or an iterable of
  specs (a plain string is just a batch of one). `declaration` is a
  compiled `LabDeclaration`, the raw {"ranges", "dns_suffixes", "hosts"}
  dict form, or None (= nothing declared). `config` is an injected
  `StagingConfig` (None = `DEFAULT_STAGING_CONFIG`).
- `staging_gate(targets_or_verdict, declaration, config=...)` is the house
  (bool, reason) go/no-go view over the same decision, wording mirrors the
  wave's egress guard gate shape (KA-055). It also accepts a finished
  StageVerdict (decide once, gate many); hand-built verdicts are validated
  and inconsistent ones raise ValueError.
- `compile_declaration(...)` compiles/validates the declaration once for
  reuse; every stage_check / staging_gate call re-validates whatever it is
  handed - caller data is never trusted silently.

WHAT COUNTS AS IN-STAGING (documented semantics):
- The declaration is the ONLY staging authority and carries three
  independent channels; a target plans in-staging when ANY applicable
  channel matches (union semantics, first match wins in channel order):
  1. `ranges` - declared lab networks. An IP target matches when its
     address lies inside a declared network; a CIDR target matches only
     when it lies FULLY inside one (same address family).
  2. `dns_suffixes` - declared lab DNS suffixes. A name-shaped host
     matches when it equals a suffix or ends in "." + suffix (label
     boundary enforced, case-insensitive, trailing dots stripped).
  3. `hosts` - the hosts registry, a mapping name -> declared addresses.
     Name targets match an exact, normalized registry key only (the
     registry is the caller's attestation of a lab host, never a DNS
     guess); IP targets additionally match an address the caller
     registered for some name (restrict with StagingConfig). A CIDR
     target never matches the registry or a suffix channel.
- CONSERVATIVE DEFAULT: an unmatched target is NEVER in-staging, so an
  empty declaration matches nothing and unrecognized target shapes
  always plan NOT in-staging. Failure reasons name the FIRST unmatched
  target; per-target rows carry full audit detail.
- RFC1918 POSTURE (consistent with the wave's egress guard): lab staging
  is private-space posture. Declared ranges and registered addresses
  must lie fully inside RFC1918 (+ IPv6 ULA fc00::/7) - the same
  supersets the egress guard treats as lab-eligible. Declaring public,
  link-local, loopback, or multicast space as staging raises ValueError.
  An RFC1918 address OUTSIDE the declared ranges still plans NOT
  in-staging: rfc1918-ness alone grants nothing here.
- NAME TARGETS ARE NEVER RESOLVED: no lookups of any kind. A name plans
  in-staging only through channels the caller explicitly declared or
  registered - mirroring the egress guard's refusal to guess
  internal-ness from a label (unresolved names are attested or tagged,
  never presumed private).

TARGET-SPEC REDUCTIONS (static string work only - a target spec is never
executed and never contacted): an absolute network-URL counts by its
netloc HOST only (userinfo decoys such as http://10.0.0.1@evil.example
classify from the real host, never from the user:pass part); literal IPs,
including bracketed [v6] and [v6]:port; CIDR; user@host and
user@host:path reductions; host:port and host:path; then bare hostname
shape. IP-shaped tokens that ipaddress cannot parse (octal tricks like
"010.0.0.1") are ALWAYS shape "unknown" and never staged - the egress
guard's documented fail-closed treatment, mirrored here. Row shape slugs:
"url" | "ip" | "cidr" | "hostport" | "hostpath" | "name" | "unknown".

Batch semantics: specs deduplicate on the scrubbed string (first
appearance preserved), cap at MAX_TARGETS_PER_CHECK specs, and pass only
when EVERY row is in-staging; the decision keeps per-target rows so the
caller can audit exactly what matched and through which channel.

Purity: no chassis import, no clock, no command execution, no name
resolution, and no network I/O of any kind; stdlib re / ipaddress /
urllib.parse (used for static URL-host extraction only). Wiring the gate
into an execution path is an integration task's decision; this module
carries the semantics only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    Union,
)
from urllib.parse import urlparse

__all__ = (
    "DECISION_KEYS",
    "DEFAULT_STAGING_CONFIG",
    "LabDeclaration",
    "MAX_DECLARATION_ITEMS",
    "MAX_TARGET_CHARS",
    "MAX_TARGETS_PER_CHECK",
    "NETWORK_URL_SCHEMES",
    "POSTURE_NETS",
    "SHAPE_CIDR",
    "SHAPE_HOSTPATH",
    "SHAPE_HOSTPORT",
    "SHAPE_IP",
    "SHAPE_NAME",
    "SHAPE_UNSET",
    "SHAPE_URL",
    "StageVerdict",
    "StagingConfig",
    "TARGET_KEYS",
    "VIA_RANGE",
    "VIA_REGISTRY",
    "VIA_SUFFIX",
    "compile_declaration",
    "staging_gate",
    "stage_check",
    "stg_scrub_target",
)

# RFC1918 + IPv6 ULA: the private-space lab posture shared with the
# wave's egress guard (KA-055). Declared ranges and registered addresses
# must live fully inside these; anything else can NEVER be staged.
POSTURE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# Scrub / batch budgets (same spirit as the egress guard's command cap).
MAX_DECLARATION_ITEMS = 256
MAX_TARGETS_PER_CHECK = 256
MAX_TARGET_CHARS = 4096

SHAPE_IP = "ip"
SHAPE_CIDR = "cidr"
SHAPE_NAME = "name"
SHAPE_URL = "url"
SHAPE_HOSTPORT = "hostport"
SHAPE_HOSTPATH = "hostpath"
SHAPE_UNSET = "unknown"

VIA_RANGE = "declared_range"
VIA_SUFFIX = "dns_suffix"
VIA_REGISTRY = "hosts_registry"

TARGET_KEYS = ("raw", "host", "shape", "in_staging", "matched_via", "matched")
DECISION_KEYS = ("targets", "in_staging", "reason")

# Mirror of the egress guard's NETWORK_URL_SCHEMES (kept local on
# purpose: pure modules stay self-contained; the schemes must agree
# because both modules reduce absolute URLs the same way).
NETWORK_URL_SCHEMES: FrozenSet[str] = frozenset({
    "http", "https", "ftp", "ftps", "sftp", "ssh", "rsync", "telnet",
    "ldap", "ldaps", "ws", "wss", "git", "git+http", "git+https",
    "git+ssh",
})

_QUAD_RE = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")
_BRACKET_RE = re.compile(r"\A\[([^[\]]+)\](?::\d+)?\Z")
_NAME_RE = re.compile(r"\A[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_DECLARATION_KEYS = frozenset({"ranges", "dns_suffixes", "hosts"})


def stg_scrub_target(target: Any) -> str:
    """Scrub an untrusted single target spec before any reduction.

    Rejects non-string, blank, control-character-bearing, and
    over-length input with ValueError; returns the stripped spec
    otherwise. Same fail-closed style as the egress guard's scrub.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target spec must be a non-empty string")
    scrubbed = target.strip()
    if _CTRL_RE.search(scrubbed):
        raise ValueError(
            "rejected target spec with control characters: %r" % scrubbed
        )
    if len(scrubbed) > MAX_TARGET_CHARS:
        raise ValueError(
            "rejected over-long target spec (>%d chars)" % MAX_TARGET_CHARS
        )
    return scrubbed


def _ip_literal(token: str) -> Optional[_Address]:
    """Parse a scrubbed token as a literal IP address; None when not."""
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def _plain_name(token: str) -> bool:
    """Hostname-shaped AND carrying at least one letter (pure digit /
    no-letter strings are registry tags at best, never lab hostnames)."""
    return bool(_NAME_RE.match(token)) and any(c.isalpha() for c in token)


def _norm_name(name: str) -> str:
    """Case-insensitive DNS name form: lowercased, dots trimmed."""
    return name.strip(".").lower()


def _url_host(token: str) -> Optional[str]:
    """The netloc HOST of an absolute network-URL token, else None.

    parsed.hostname strips userinfo and port (and lowercases): a decoy
    userinfo (http://10.0.0.1@evil.example) never influences matching.
    """
    try:
        parsed = urlparse(token)
    except ValueError:
        return None
    if parsed.scheme.lower() not in NETWORK_URL_SCHEMES or not parsed.netloc:
        return None
    host = parsed.hostname
    if not host:
        return None
    return host


def _reduce_target(spec: str) -> Optional[Tuple[str, str]]:
    """Reduce a scrubbed target spec to (host, shape) or None.

    Reductions mirror the wave's egress guard where the routes overlap;
    route order is significant. Unlike the egress guard there is no
    command verb here - a target spec is a target by definition, so the
    bare-name route is unconditional. None means the spec is not a
    recognizable target shape (it will plan NOT in-staging).
    """
    # 1. URL route: classify by the netloc host only (decoy-safe; also
    #    strips :port and bracketed [v6] for us).
    url_host = _url_host(spec)
    if url_host is not None:
        return url_host, SHAPE_URL
    # 2. Full-token literal IP (v4 or bare v6).
    if _ip_literal(spec) is not None:
        return spec, SHAPE_IP
    # 3. IP-shaped but unparseable (octal tricks, oversized octets):
    #    always "unknown", never staged (egress guard fail-closed mirror).
    if _QUAD_RE.match(spec):
        return spec, SHAPE_UNSET
    # 4. Bracketed IPv6, bare or with :port.
    m = _BRACKET_RE.match(spec)
    if m is not None and _ip_literal(m.group(1)) is not None:
        return m.group(1), (SHAPE_HOSTPORT if ":" in spec[1:] else SHAPE_IP)
    # 5. user@host[:port|:path] reductions (rsync / scp-style specs).
    if "@" in spec:
        remote = spec.rsplit("@", 1)[1]
        sub = _reduce_target(remote)
        if sub is not None:
            return sub
        return None
    # 6. CIDR scan target (host bits tolerated; normalized on match).
    if "/" in spec:
        try:
            ipaddress.ip_network(spec, strict=False)
        except (ValueError, TypeError):
            net = None
        else:
            return spec, SHAPE_CIDR
    # 7. host:digits (hostport) and host:path (hostpath) reductions,
    #    skipped for scheme-ful strings (route 1 owns those shapes).
    if "://" not in spec and ":" in spec:
        left, _, right = spec.partition(":")
        if right.isdigit() and (":" not in left):
            if _ip_literal(left) is not None or _plain_name(left):
                return left, SHAPE_HOSTPORT
        elif ":" not in right and _ip_literal(left) is not None:
            return left, SHAPE_HOSTPATH
        elif (":" not in right and _plain_name(left)
              and ("/" in right or "." in right)):
            return left, SHAPE_HOSTPATH
    # 8. Bare hostname route (a trailing-dot FQDN form is normalized
    #    first - "host." is the same DNS name as "host"; note pure-IP
    #    specs with a trailing dot still fail here: names need a letter).
    if _plain_name(_norm_name(spec)):
        return spec, SHAPE_NAME
    return None


def _parse_network(item: Any) -> _Network:
    """Validate one declared-range item; ValueError when not a network."""
    if not isinstance(item, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        raise ValueError(
            "declared range must be a string or network object, got %r"
            % (item,)
        )
    try:
        return ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
        raise ValueError(
            "invalid declared range %r: %s" % (item, exc)
        ) from None


def _net_in_posture(net: _Network) -> bool:
    """True when the network lies fully inside the RFC1918/ULA posture."""
    for candidate in POSTURE_NETS:
        if net.version != candidate.version:
            continue
        try:
            if net.subnet_of(candidate):
                return True
        except (TypeError, ValueError):
            continue
    return False


def _addr_in_posture(addr: _Address) -> bool:
    """True when the address lies inside the RFC1918/ULA posture."""
    for net in POSTURE_NETS:
        if addr.version == net.version and addr in net:
            return True
    return False


def _parse_address(item: Any) -> _Address:
    """Validate one registered-address item; ValueError when not an IP."""
    if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return item
    if isinstance(item, str):
        try:
            return ipaddress.ip_address(item.strip())
        except ValueError as exc:
            raise ValueError(
                "invalid registered address %r: %s" % (item, exc)
            ) from None
    raise ValueError(
        "registered address must be a string or IP address object, got %r"
        % (item,)
    )


def _as_item_iter(values: Any, channel: str) -> Tuple[Any, ...]:
    """Wrap a channel's raw value into a tuple of items (None = empty)."""
    if values is None:
        return ()
    if isinstance(values, str):
        return (values,)
    if isinstance(values, (list, tuple, set, frozenset)):
        return tuple(values)
    raise ValueError("%s channel must be a string or an iterable" % channel)


def _compile_ranges(values: Any) -> Tuple[_Network, ...]:
    """Validate + normalize + dedupe declared ranges (input order kept)."""
    items = _as_item_iter(values, "ranges")
    nets: List[_Network] = []
    seen: Set[str] = set()
    for item in items:
        net = _parse_network(item)
        if not _net_in_posture(net):
            raise ValueError(
                "declared range %s is outside the RFC1918/ULA lab posture"
                % (item,)
            )
        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(net)
    if len(nets) > MAX_DECLARATION_ITEMS:
        raise ValueError(
            "declared ranges exceed %d entries" % MAX_DECLARATION_ITEMS
        )
    return tuple(nets)


def _compile_suffixes(values: Any) -> Tuple[str, ...]:
    """Validate + normalize + dedupe declared DNS suffixes."""
    items = _as_item_iter(values, "dns_suffixes")
    suffixes: List[str] = []
    seen: Set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise ValueError(
                "DNS suffix must be a string, got %r" % (item,)
            )
        norm = _norm_name(item.strip())
        if not _plain_name(norm):
            raise ValueError(
                "invalid DNS suffix %r (hostname-shaped, at least one "
                "letter; wildcards not allowed)" % (item,)
            )
        if norm not in seen:
            seen.add(norm)
            suffixes.append(norm)
    if len(suffixes) > MAX_DECLARATION_ITEMS:
        raise ValueError(
            "DNS suffixes exceed %d entries" % MAX_DECLARATION_ITEMS
        )
    return tuple(suffixes)


def _compile_hosts(registry: Any) -> Dict[str, Tuple[_Address, ...]]:
    """Validate + normalize the hosts registry; keys are hostnames,
    values are registered lab addresses (RFC1918/ULA, attestation data).
    Duplicate normalized keys merge their address lists in input order;
    an empty value stays an attested name with no known addresses."""
    if registry is None:
        return {}
    if not isinstance(registry, Mapping):
        raise ValueError(
            "hosts registry must be a mapping of name -> addresses, got %r"
            % (registry,)
        )
    if len(registry) > MAX_DECLARATION_ITEMS:
        raise ValueError(
            "hosts registry exceeds %d entries" % MAX_DECLARATION_ITEMS
        )
    compiled: Dict[str, Tuple[_Address, ...]] = {}
    for raw_name, raw_addrs in registry.items():
        if not isinstance(raw_name, str):
            raise ValueError(
                "hosts registry keys must be strings, got %r" % (raw_name,)
            )
        name = _norm_name(raw_name.strip())
        if not _plain_name(name):
            raise ValueError(
                "hosts registry key %r is not a hostname (register "
                "addresses as VALUES, never as keys)" % (raw_name,)
            )
        if isinstance(raw_addrs, (str, ipaddress.IPv4Address,
                                  ipaddress.IPv6Address)):
            addrs: Tuple[Any, ...] = (raw_addrs,)
        elif raw_addrs is None:
            addrs = ()
        elif isinstance(raw_addrs, (list, tuple, set, frozenset)):
            addrs = tuple(raw_addrs)
        else:
            raise ValueError(
                "registered addresses for %r must be a string or an "
                "iterable, got %r" % (raw_name, raw_addrs)
            )
        parsed: List[_Address] = []
        seen: Set[str] = set()
        for item in addrs:
            addr = _parse_address(item)
            if not _addr_in_posture(addr):
                raise ValueError(
                    "registered address %s for %r is outside the "
                    "RFC1918/ULA lab posture" % (addr, raw_name)
                )
            if str(addr) not in seen:
                seen.add(str(addr))
                parsed.append(addr)
        if name in compiled:
            merged = list(compiled[name])
            have = {str(a) for a in merged}
            for addr in parsed:
                if str(addr) not in have:
                    have.add(str(addr))
                    merged.append(addr)
            compiled[name] = tuple(merged)
        else:
            compiled[name] = tuple(parsed)
    return compiled


@dataclass(frozen=True)
class LabDeclaration:
    """Compiled caller-supplied lab/staging declaration (injected config).

    Built through `compile_declaration` or validated on construction:
    `ranges` is a tuple of private-posture networks (RFC1918 + ULA),
    `dns_suffixes` a tuple of normalized suffix strings, and `hosts` a
    dict of normalized name -> tuple of private-posture addresses (an
    empty tuple is an attested name with no declared addresses).
    """

    ranges: Any = ()
    dns_suffixes: Any = ()
    hosts: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ranges", _compile_ranges(self.ranges))
        object.__setattr__(
            self, "dns_suffixes", _compile_suffixes(self.dns_suffixes)
        )
        object.__setattr__(self, "hosts", _compile_hosts(self.hosts))


def compile_declaration(
    ranges: Any = (),
    dns_suffixes: Any = (),
    hosts: Any = None,
) -> LabDeclaration:
    """Compile and validate a caller-supplied lab/staging declaration.

    Ranges and addresses must lie inside the RFC1918/ULA lab posture and
    parse cleanly (host bits tolerated on ranges; strict-normalized);
    suffixes and registry keys must be hostname-shaped names; registry
    values are string-or-object addresses or an iterable of them. Any
    malformed or posture-violating item raises ValueError - caller data
    is never trusted silently, and nothing is auto-corrected into
    staging coverage.
    """
    return LabDeclaration(
        ranges=ranges, dns_suffixes=dns_suffixes, hosts=hosts
    )


def _coerce_declaration(declaration: Any) -> LabDeclaration:
    """Normalize the declaration argument to a compiled LabDeclaration.

    Accepts LabDeclaration (re-validated), the raw triple dict with only
    the documented keys (missing keys = empty channels - a safe-direction
    default; unknown keys raise), or None (= nothing declared: every
    target plans NOT in-staging).
    """
    if declaration is None:
        return LabDeclaration()
    if isinstance(declaration, LabDeclaration):
        return LabDeclaration(
            ranges=declaration.ranges,
            dns_suffixes=declaration.dns_suffixes,
            hosts=declaration.hosts,
        )
    if isinstance(declaration, Mapping):
        unknown = set(declaration) - _DECLARATION_KEYS
        if unknown:
            raise ValueError(
                "unknown declaration key(s): %s" % sorted(unknown)
            )
        return LabDeclaration(
            ranges=declaration.get("ranges", ()),
            dns_suffixes=declaration.get("dns_suffixes", ()),
            hosts=declaration.get("hosts"),
        )
    raise ValueError(
        "declaration must be a LabDeclaration, the raw triple dict, or None"
    )


@dataclass(frozen=True)
class StagingConfig:
    """Injected policy knobs for the staging gate.

    Defaults carry the documented semantics; knobs may only TIGHTEN:
    - allow_registry_ip_match (True): IP targets may be staged by an
      address the caller registered in the hosts registry. Set False to
      demand that IP targets match declared ranges even when the caller
      attested the address under some lab hostname.
    """

    allow_registry_ip_match: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.allow_registry_ip_match, bool):
            raise ValueError("allow_registry_ip_match must be a bool")


DEFAULT_STAGING_CONFIG = StagingConfig()


@dataclass(frozen=True)
class StageVerdict:
    """Deterministic staging decision over a (deduplicated) target batch.

    `targets` preserves first-appearance order as pure row dicts
    (TARGET_KEYS), `in_staging` is True only when EVERY row matched, and
    `reason` is the deterministic go/no-go message. `as_dict()` is the
    JSON-ready decision dict (DECISION_KEYS).
    """

    targets: Tuple[Dict[str, Any], ...]
    in_staging: bool
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        """The deterministic decision dict (pure, JSON-serializable)."""
        return {
            "targets": self.targets,
            "in_staging": self.in_staging,
            "reason": self.reason,
        }


def _row(
    raw: str,
    host: str,
    shape: str,
    via: Optional[str],
    matched: Optional[str],
) -> Dict[str, Any]:
    """One decision row; in_staging follows from the channel hit."""
    return {
        "raw": raw,
        "host": host,
        "shape": shape,
        "in_staging": via is not None,
        "matched_via": via,
        "matched": matched,
    }


def _match_ip(
    addr: _Address,
    decl: LabDeclaration,
    config: StagingConfig,
) -> Optional[Tuple[str, str]]:
    """(via, matched) for a literal-IP host; None when nothing matched.

    Ranges first (first declared match wins), then - when permitted -
    the addresses the caller registered in the hosts registry. A name
    channel never blesses an IP: names are attested for name targets.
    """
    for net in decl.ranges:
        if net.version == addr.version and addr in net:
            return VIA_RANGE, str(net)
    if config.allow_registry_ip_match:
        for name, addrs in decl.hosts.items():
            for registered in addrs:
                if registered == addr:
                    return VIA_REGISTRY, name
    return None


def _match_name(
    name: str,
    decl: LabDeclaration,
) -> Optional[Tuple[str, str]]:
    """(via, matched) for a name-shaped host; None when nothing matched.

    Suffixes first (label-boundary match), then EXACT registry keys -
    a registry key never absorbs subdomains (declare a suffix for that).
    """
    for suffix in decl.dns_suffixes:
        if name == suffix or name.endswith("." + suffix):
            return VIA_SUFFIX, suffix
    if name in decl.hosts:
        return VIA_REGISTRY, name
    return None


def _match_cidr(
    net: _Network,
    decl: LabDeclaration,
) -> Optional[Tuple[str, str]]:
    """(via, matched) for a CIDR target: only a fully-contained network
    inside a same-family declared range counts (no overlap blessing)."""
    for declared in decl.ranges:
        if net.version != declared.version:
            continue
        try:
            if net.subnet_of(declared):
                return VIA_RANGE, str(declared)
        except (TypeError, ValueError):
            continue
    return None


def _validate_verdict(verdict: Any) -> StageVerdict:
    """Strict validation of a StageVerdict from external hands; a lying
    or malformed dict-of-a-verdict raises ValueError (fail-closed)."""
    if not isinstance(verdict, StageVerdict):
        raise ValueError("verdict must be a stage_check StageVerdict")
    rows = verdict.targets
    if (
        not isinstance(rows, tuple)
        or not isinstance(verdict.in_staging, bool)
        or not isinstance(verdict.reason, str)
    ):
        raise ValueError("malformed StageVerdict: %r" % (verdict,))
    for row in rows:
        if (
            not isinstance(row, dict)
            or not set(TARGET_KEYS) <= set(row)
            or not isinstance(row["in_staging"], bool)
        ):
            raise ValueError("malformed target row: %r" % (row,))
    if verdict.in_staging != all(row["in_staging"] for row in rows):
        raise ValueError(
            "inconsistent StageVerdict: in_staging disagrees with rows"
        )
    return verdict


def stage_check(
    targets: Any,
    declaration: Any = None,
    config: Any = None,
) -> StageVerdict:
    """Statically decide whether target specs lie inside the declared
    lab/staging environment."""
    if config is None:
        config = DEFAULT_STAGING_CONFIG
    elif not isinstance(config, StagingConfig):
        raise ValueError("config must be a StagingConfig instance or None")
    decl = _coerce_declaration(declaration)

    if isinstance(targets, str):
        specs: Tuple[Any, ...] = (targets,)
    elif isinstance(targets, (list, tuple, set, frozenset)):
        specs = tuple(targets)
    elif hasattr(targets, "__iter__"):
        specs = tuple(targets)
    else:
        raise ValueError(
            "targets must be a target-spec string or an iterable of them"
        )
    if len(specs) > MAX_TARGETS_PER_CHECK:
        raise ValueError(
            "rejected oversized target batch (>%d specs)"
            % MAX_TARGETS_PER_CHECK
        )

    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for spec in specs:
        scrubbed = stg_scrub_target(spec)
        if scrubbed in seen:
            continue
        seen.add(scrubbed)
        reduced = _reduce_target(scrubbed)
        if reduced is None:
            host, shape = scrubbed, SHAPE_UNSET
        else:
            host, shape = reduced
        hit: Optional[Tuple[str, str]] = None
        if shape == SHAPE_CIDR:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except (ValueError, TypeError):
                net = None
            if net is not None:
                hit = _match_cidr(net, decl)
        elif shape != SHAPE_UNSET:
            addr = _ip_literal(host)
            if addr is not None:
                hit = _match_ip(addr, decl, config)
            else:
                hit = _match_name(_norm_name(host), decl)
        if hit is not None:
            via, matched = hit
        else:
            via, matched = None, None
        rows.append(_row(scrubbed, host, shape, via, matched))

    blocked = next((row for row in rows if not row["in_staging"]), None)
    if blocked is None:
        in_staging = True
        reason = (
            "go: no target(s) to stage"
            if not rows
            else "go: %d target(s) inside the declared staging environment"
            % len(rows)
        )
    else:
        in_staging = False
        reason = (
            "no-go: target '%s' is not inside the declared staging "
            "environment" % blocked["raw"]
        )
    return StageVerdict(
        targets=tuple(rows), in_staging=in_staging, reason=reason
    )


def staging_gate(
    targets_or_verdict: Any,
    declaration: Any = None,
    config: Any = None,
) -> Tuple[bool, str]:
    """Decide go/no-go for destructive-or-external steps against the
    declared lab/staging environment.

    Accepts raw target(s) plus a declaration/config (decided through
    stage_check) or a finished StageVerdict (validated; declaration and
    config are then ignored). Returns the house (bool, reason) tuple:
    go only when EVERY target is in-staging, otherwise the first
    unmatched target names the reason.
    """
    if isinstance(targets_or_verdict, StageVerdict):
        verdict = _validate_verdict(targets_or_verdict)
    else:
        verdict = stage_check(targets_or_verdict, declaration, config)
    return verdict.in_staging, verdict.reason