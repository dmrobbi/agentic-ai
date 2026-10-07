"""IOC extractor (KA-084): engagement executions/outputs text (one blob
or a list of blobs) -> a clean, typed IOC list shaped for a SOC feed.
Pure planner: nothing here touches a process, the network, a store, or
the filesystem (source-scanned); the clock is a PARAMETER - the
result's "generated" stays None until the caller injects an aware
datetime.

RESULT SHAPE:
  {"generated": None | <UTC ISO-8601 +00:00 stamp from the injected
                aware datetime; naive/non-datetime refused>,
   "iocs": [ {"type": <str>, "value": <str>, "source_hint": <str|None>},
             ... ] in discovery order (urls then their authority hosts,
             then emails plus their companion domains, then paths,
             then the plain-text scans: standalone domains, ips,
             hashes),
   "counts": {"total": <int emitted>,
              "by_type": {<every house IOC type>: <int emitted>}},
   "warnings": [<str>, ...]}

HOUSE RULES:
- Dedupe per (type, value); the first occurrence wins and carries the
  one source_hint the caller passed.
- Hard cap of 25 KEPT distinct values PER TYPE; overflow beyond the
  cap is announced in warnings, never silent.
- Control characters are scrubbed FIRST: each becomes one space, so
  hostile tokens split instead of merging.
- Defanged syntax (hxxp(s)://, [.] and friends) is UNDEFANGED
  explicitly before extraction and the substitution count is
  announced in warnings; the module's own pattern literals necessarily
  contain dot char classes - that is fine.
- URL credentials (userinfo before the host) are stripped from the
  emitted value and the source hint notes the redaction in place.
- Domains are FQDN-shaped: at least one dot plus an alphanumeric-only
  label set; bare TLDs, underscore labels and version-suffixed
  library names are refused. IP candidates reject 0-x lead octets,
  255.255.255.255 and malformed octets; ipv6 parses strict via the
  stdlib address checker (no network facilities of any kind).
- NO payload/hostile-string literal blobs beyond the compiled
  patterns; tests pin extraction on realistic benign examples.

Type vocabulary: ipv4, ipv6, domain, url, email, md5, sha1, sha256,
path_posix, path_win32.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- contract constants (the drift alarm; the tests pin them) ------------

IO_TYPES: Tuple[str, ...] = (
    "ipv4", "ipv6", "domain", "url", "email",
    "md5", "sha1", "sha256", "path_posix", "path_win32",
)
IOC_CAP = 25
CRED_NOTE = "credentials-redacted"

# url/posix/win32 values get a trailing-punctuation haircut; domain,
# email, ip and hash values are regex-structured and never need one.
_URL_STRIP = ".,;!?\")'"
_POSIX_STRIP = ".,;:!?"
_WIN32_STRIP = ".,;:!?)"

WARN_NONSTR_ITEM = "input blob %d is not a string; skipped"
WARN_DEFANGED = "defanged syntax normalized: %d substitution(s)"
WARN_CAP = "%s: cap %d reached, %d distinct value(s) dropped"

# --- compiled patterns (module-level, the only literals here) ------------

CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# defanged -> plain text forms (the house ask: undefang explicitly)
DEFANG_HTTPS_RE = re.compile(r"(?i)\bhxxps(?=://)")
DEFANG_HTTP_RE = re.compile(r"(?i)\bhxxp(?=://)")
DEFANG_DOT_RE = re.compile(r"(?i)\[\.\]|\(\.\)|\[dot\]|\(dot\)")
DEFANG_COLON_RE = re.compile(r"\[:\]|\(\:\)")

# ipv4: four dotted digit groups; per-octet validation happens below
IPV4_RE = re.compile(
    r"(?<![0-9.A-Za-z])"
    r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})"
    r"(?!\.?[0-9])")

# ipv6: a hex-colon-dot run that carries at least one colon; the
# stdlib address checker then decides well-formedness (basic rule:
# everything emitted IS well-formed, prose is not)
IPV6_CAND_RE = re.compile(
    r"(?<![0-9A-Fa-f:.A-Za-z])"
    r"[0-9A-Fa-f:.]{2,45}"
    r"(?![0-9A-Fa-f:.])")

# md5/sha1/sha256: exact-length hex runs, never substrings of longer
# hex strings (lookarounds anchor the run on non-hex on both sides)
MD5_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
SHA1_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
SHA256_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")

# domain label: alphanumeric start/stop, hyphens inside only
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"

DOMAIN_VALUE_RE = re.compile(
    r"^(?:" + _DOMAIN_LABEL + r"\.)+[A-Za-z]{2,}$")

# domain: FQDN-shaped only; the (?!\.[0-9]) tail refuses versioned
# library names ("libc.so.6"). Email companion domains are taken
# explicitly from the email match (the part after its last @), so the
# domain scan can run on email-masked text without losing them.
DOMAIN_RE = re.compile(
    r"(?<![\w.\-])"
    r"(?:" + _DOMAIN_LABEL + r"\.)+[A-Za-z]{2,}"
    r"(?!\.[0-9])")

# email: plain local part + FQDN-shaped domain (verbatim out)
EMAIL_RE = re.compile(
    r"(?<![\w@.\-])"
    r"[A-Za-z0-9._%+\-]+@"
    r"(?:" + _DOMAIN_LABEL + r"\.)+[A-Za-z]{2,}")

# url: a real scheme, an optional userinfo before the host, a dotted
# host (single-label authorities are dropped) or a bracketed ipv6,
# then the path tail. The tail refuses the colon so ports stay in the
# authority slice; userinfo is g2 and is dropped from the value.
URL_RE = re.compile(
    r"(?i)(?<![\w/@.\-])"
    r"(https?|ftps?)://"
    r"(?:([^/\s?<>\[\]#]+)@)?"
    r"("
    r"(?=[A-Za-z0-9.\-]*\.)[A-Za-z0-9.\-]+(?::[0-9]{1,5})?"
    r"|\[[0-9A-Fa-f:.]{1,45}\](?::[0-9]{1,5})?"
    r")"
    r"([^\s<>:\"'`]*)")

# paths: printable minus the separators each syntax bars; posix wants
# a '/'-root or '~/'-root chain of segments, win32 a drive or UNC root
_PATH_SEG = r"[A-Za-z0-9_.\-+@%~]+"
_WIN32_SEG = r"[^\x00-\x20\\/:*?\"<>|]+"
POSIX_PATH_RE = re.compile(
    r"(?<![\w.\-/])"
    r"(?:/" + _PATH_SEG + r"(?:/" + _PATH_SEG + r")*"
    r"|~/" + _PATH_SEG + r"(?:/" + _PATH_SEG + r")*"
    r")")
WIN32_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9\\])"
    r"(?:[A-Za-z]:(?:\\" + _WIN32_SEG + r")+"
    r"|\\\\[A-Za-z0-9_.\-]+(?:\\" + _WIN32_SEG + r")+"
    r")")


# --- input gates -----------------------------------------------------------

def scrub_control_chars(text: Any) -> str:
    """The shared input gate: control characters each become one space
    (tokens split, never merge); everything else passes verbatim."""
    if not isinstance(text, str):
        raise ValueError("scrub_control_chars needs a string, got: %r"
                         % (text,))
    return CTRL_CHARS_RE.sub(" ", text)


def _undefang(text: str) -> Tuple[str, int]:
    """Undefang the explicit house forms; returns (text, count)."""
    total = 0
    for pattern, replacement in (
            (DEFANG_HTTPS_RE, "https"),
            (DEFANG_HTTP_RE, "http"),
            (DEFANG_DOT_RE, "."),
            (DEFANG_COLON_RE, ":"),
    ):
        text, count = pattern.subn(replacement, text)
        total += count
    return text, total


def _input_blobs(text: Any) -> Tuple[List[str], List[str]]:
    """A string or a string list -> (strings, per-item warnings);
    anything else is a caller error."""
    if isinstance(text, str):
        return [text], []
    if isinstance(text, (list, tuple)):
        blobs: List[str] = []
        warnings: List[str] = []
        for index, blob in enumerate(text):
            if isinstance(blob, str):
                blobs.append(blob)
            else:
                warnings.append(WARN_NONSTR_ITEM % (index,))
        return blobs, warnings
    raise ValueError(
        "text must be a string or a list of strings, got: %r" % (text,))


def _utc_stamp(now: Optional[datetime]) -> Optional[str]:
    """The injected clock -> a UTC +00:00 ISO stamp (or None)."""
    if now is None:
        return None
    if not isinstance(now, datetime):
        raise ValueError(
            "clock must be an aware datetime or None, got: %r" % (now,))
    if now.utcoffset() is None:
        raise ValueError(
            "clock must be timezone-aware (the SOC feed stamps UTC "
            "+00:00), got naive: %r" % (now,))
    return now.astimezone(timezone.utc).isoformat()


# --- per-type validators ---------------------------------------------------

def _valid_ipv4(value: str) -> bool:
    """Four octets 0-255; the 0-x lead and the whole-net broadcast are
    refused."""
    parts = value.split(".")
    if len(parts) != 4 or not all(
            part.isdigit() and len(part) <= 3 for part in parts):
        return False
    octets = [int(part) for part in parts]
    if octets[0] == 0 or value == "255.255.255.255":
        return False
    return all(octet <= 255 for octet in octets)


def _valid_ipv6(value: str) -> bool:
    """Strict parse, zone ids refused."""
    if not value or "%" in value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return parsed.version == 6


def _valid_domain(value: str) -> bool:
    """FQDN-shaped: labels plus an alphabetic TLD, no bare TLD."""
    if not value:
        return False
    return DOMAIN_VALUE_RE.fullmatch(value) is not None


def _valid_posix_path(candidate: str) -> bool:
    """Segment sanity: every segment non-empty with one non-dot char
    (so '.', '..', and '/a/./b' are out)."""
    if not candidate or POSIX_PATH_RE.fullmatch(candidate) is None:
        return False
    segments = candidate.split("/")[1:]
    if not segments:
        return False
    return all(
        segment and any(char not in "." for char in segment)
        for segment in segments)


def _valid_win32_path(candidate: str) -> bool:
    """Re-shape check after the punctuation haircut."""
    if not candidate:
        return False
    return WIN32_PATH_RE.fullmatch(candidate) is not None


# --- url helpers ------------------------------------------------------------

def _host_type(host: str) -> Optional[str]:
    """Route a url authority's host to the right IOC type (or None)."""
    if not host:
        return None
    if ":" in host:
        return "ipv6" if _valid_ipv6(host) else None
    if _valid_domain(host):
        return "domain"
    if "." in host and _valid_ipv4(host):
        return "ipv4"
    return None


def _blank_spans(text: str, spans: List[Tuple[int, int]]) -> str:
    """Blank matched spans with same-length spaces (indices preserved
    between the scan source and the masked copy)."""
    chars = list(text)
    for start, end in spans:
        for position in range(start, end):
            chars[position] = " "
    return "".join(chars)


def _authority_host(authority: str) -> str:
    """The host of an authority slice: brackets first, then a trailing
    :port for dotted authorities only (v6 tails like ...:1 survive)."""
    if authority.startswith("[") and "]" in authority:
        return authority[1:authority.index("]")].rstrip(".")
    if ":" in authority:
        before, _, maybe_port = authority.rpartition(":")
        if maybe_port.isdigit() and "." in before:
            authority = before
    return authority.rstrip(".")


def _source_with_note(source_hint: Optional[str]) -> str:
    """The source hint carrying the credentials redaction note."""
    if source_hint:
        return "%s; %s" % (source_hint, CRED_NOTE)
    return CRED_NOTE


# --- the extractor ----------------------------------------------------------

def extract_iocs(
    text: Any,
    source_hint: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Extract a clean, typed, deduped IOC list from engagement text for
    the SOC feed (dict: generated/iocs/counts/warnings).

    text is one string blob or a list of them; per-blob malformation
    never raises (it lands in warnings), while a malformed container, a
    non-string source_hint or a non-aware injected clock raise
    ValueError naming the offender. The clock stays optional: with
    now=None the "generated" field stays None (planner purity - no
    clock is called here).
    """
    if source_hint is not None and not isinstance(source_hint, str):
        raise ValueError("source_hint must be a string or None, got: %r"
                         % (source_hint,))
    generated = _utc_stamp(now)
    blobs, warnings = _input_blobs(text)

    raw = "\n".join(blobs)
    raw = scrub_control_chars(raw)
    raw, defang_count = _undefang(raw)
    if defang_count:
        warnings.append(WARN_DEFANGED % (defang_count,))

    kept = {ioc_type: 0 for ioc_type in IO_TYPES}
    overflow = {ioc_type: 0 for ioc_type in IO_TYPES}
    seen: set = set()
    iocs: List[Dict[str, Any]] = []

    def add(ioc_type: str, value: Any, ioc_source: Optional[str]) -> None:
        if not isinstance(value, str) or not value:
            return
        key = (ioc_type, value)
        if key in seen:
            return
        if kept[ioc_type] >= IOC_CAP:
            overflow[ioc_type] += 1
            return
        seen.add(key)
        kept[ioc_type] += 1
        iocs.append({"type": ioc_type, "value": value,
                     "source_hint": ioc_source})

    # (a) urls: emit the cleaned value, route the authority's host
    url_spans: List[Tuple[int, int]] = []
    for match in URL_RE.finditer(raw):
        scheme, userinfo, authority, tail = match.groups()
        host = _authority_host(authority)
        value = (scheme + "://" + authority + tail).rstrip(_URL_STRIP)
        url_spans.append((match.start(), match.end()))
        url_source = (
            _source_with_note(source_hint) if userinfo else source_hint)
        add("url", value, url_source)
        host_type = _host_type(host)
        if host_type:
            add(host_type, host, source_hint)

    # (b) t2: urls blanked; emails emitted with their companion domain
    url_blank = _blank_spans(raw, url_spans)
    email_spans: List[Tuple[int, int]] = []
    for match in EMAIL_RE.finditer(url_blank):
        email_text = match.group(0)
        email_spans.append((match.start(), match.end()))
        add("email", email_text, source_hint)
        add("domain", email_text[email_text.rfind("@") + 1:], source_hint)

    # (c) paths first, on the email-blanked text: filenames like
    # auth.log or evil.ps1 must not resurface as domains
    path_spans: List[Tuple[int, int]] = []
    for match in POSIX_PATH_RE.finditer(url_blank):
        candidate = match.group(0).rstrip(_POSIX_STRIP)
        if _valid_posix_path(candidate):
            path_spans.append((match.start(), match.end()))
            add("path_posix", candidate, source_hint)
    for match in WIN32_PATH_RE.finditer(url_blank):
        candidate = match.group(0).rstrip(_WIN32_STRIP)
        if _valid_win32_path(candidate):
            path_spans.append((match.start(), match.end()))
            add("path_win32", candidate, source_hint)

    # (d) plain scans on path-masked text: standalone domains, ips,
    # hashes - never read inside a url, email, or path token
    plain = _blank_spans(url_blank, email_spans + path_spans)
    for match in DOMAIN_RE.finditer(plain):
        add("domain", match.group(0), source_hint)
    for match in IPV4_RE.finditer(plain):
        parts = match.groups()
        joined = ".".join(parts)
        if _valid_ipv4(joined):
            add("ipv4", joined, source_hint)
    for match in IPV6_CAND_RE.finditer(plain):
        trimmed = match.group(0).strip(".")
        if ":" in trimmed and _valid_ipv6(trimmed):
            add("ipv6", trimmed, source_hint)
    for match in MD5_RE.finditer(plain):
        add("md5", match.group(0), source_hint)
    for match in SHA1_RE.finditer(plain):
        add("sha1", match.group(0), source_hint)
    for match in SHA256_RE.finditer(plain):
        add("sha256", match.group(0), source_hint)

    for ioc_type in IO_TYPES:
        if overflow[ioc_type]:
            warnings.append(
                WARN_CAP % (ioc_type, IOC_CAP, overflow[ioc_type]))

    return {
        "generated": generated,
        "iocs": iocs,
        "counts": {
            "total": len(iocs),
            "by_type": dict(kept),
        },
        "warnings": warnings,
    }