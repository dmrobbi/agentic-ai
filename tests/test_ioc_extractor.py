"""KA-084 tests - IOC extractor: the result contract (generated/iocs/
counts/warnings exact shapes), the injected-clock contract (None by
default, aware normalized to UTC +00:00, naive/non-datetime refused),
per-type extraction pins on realistic benign-shaped examples (ipv4
octet guards, strict ipv6, FQDN-shaped domains, scheme+authority urls,
userinfo redaction, emails plus their companion domains, exact-length
hex runs, posix and win32 paths), the undefang ask ([.] and hxxp
normalized with the substitution warning), dedupe per (type, value),
the 25-per-type cap with announced overflow, control-char scrubbing,
non-string blob routing, JSON round-trips, and the planner-purity +
no-payload-literal source scans. No network, no files, no processes -
by design."""

from __future__ import annotations

import importlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.ioc_extractor import (
    CRED_NOTE,
    IOC_CAP,
    IO_TYPES,
    WARN_CAP,
    WARN_DEFANGED,
    WARN_NONSTR_ITEM,
    extract_iocs,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 7, 19, 48, 0, tzinfo=UTC)  # arbitrary fixed clock
PLUS_2H = timezone(timedelta(hours=2))
# sha1("hello"), md5("hello"), sha256("the quick brown fox") - benign
# realistic-shaped corpus; no payload/listings in a unit-test sense
MD5 = "5d41402abc4b2a76b9719d911017c592"
SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
SHA256 = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"

RESULT_KEYS = {"generated", "iocs", "counts", "warnings"}
IOC_ROW_KEYS = {"type", "value", "source_hint"}


def by_type(result, ioc_type):
    """The emitted count of one IOC type (the count sheet)."""
    return result["counts"]["by_type"][ioc_type]


def rows_of(result, ioc_type):
    """The emitted values of one IOC type in discovery order."""
    return [row["value"] for row in result["iocs"]
            if row["type"] == ioc_type]


# --- the result contract ---------------------------------------------------


def test_result_shape_empty_exact():
    assert extract_iocs("") == {
        "generated": None,
        "iocs": [],
        "counts": {
            "total": 0,
            "by_type": {ioc_type: 0 for ioc_type in IO_TYPES},
        },
        "warnings": []}


def test_input_container_variants():
    str_blob = extract_iocs("1.2.3.4 and evil.example.com")
    list_blob = extract_iocs(["1.2.3.4 and evil.example.com"])
    split_blobs = extract_iocs(["1.2.3.4", "evil.example.com"])
    for result in (list_blob, split_blobs):
        assert result["counts"]["by_type"]["ipv4"] == 1
        assert result["counts"]["by_type"]["domain"] == 1
    assert split_blobs["iocs"] == [
        {"type": "domain", "value": "evil.example.com",
         "source_hint": None},
        {"type": "ipv4", "value": "1.2.3.4", "source_hint": None}]


def test_nonstr_items_route_to_warnings():
    result = extract_iocs(["1.2.3.4", 42, None, "evil.example.com"])
    assert result["warnings"] == [
        WARN_NONSTR_ITEM % (1,), WARN_NONSTR_ITEM % (2,)]
    assert result["counts"]["total"] == 2


@pytest.mark.parametrize("bad_text", [None, 42, {"a": 1}, 3.14])
def test_input_container_type_refused(bad_text):
    with pytest.raises(ValueError, match="text must be a string"):
        extract_iocs(bad_text)


def test_source_hint_default_none_and_carried():
    plain = extract_iocs("https://phish.example.com/x")
    assert all(row["source_hint"] is None for row in plain["iocs"])
    hinted = extract_iocs("https://phish.example.com/x",
                          source_hint="run-42")
    assert all(row["source_hint"] == "run-42" for row in hinted["iocs"])


def test_source_hint_non_string_refused():
    with pytest.raises(ValueError, match="source_hint must be a string"):
        extract_iocs("1.2.3.4", source_hint=42)


def test_result_and_row_key_sets():
    result = extract_iocs(
        "1.2.3.4 evil.example.com ops@soc.example.net "
        "5d41402abc4b2a76b9719d911017c592 "
        "https://a.example.com/x /tmp/x C:\\Temp\\x.ps1", now=NOW)
    assert set(result) == RESULT_KEYS
    for row in result["iocs"]:
        assert set(row) == IOC_ROW_KEYS


# --- the injected clock ----------------------------------------------------


def test_generated_none_without_clock():
    assert extract_iocs("1.2.3.4")["generated"] is None


def test_generated_aware_clock_stamped_and_normalized():
    assert extract_iocs("1.2.3.4", now=NOW)["generated"] == (
        "2026-10-07T19:48:00+00:00")
    shifted = extract_iocs(
        "1.2.3.4", now=datetime(2026, 10, 7, 14, 0, 0, tzinfo=PLUS_2H))
    assert shifted["generated"] == "2026-10-07T12:00:00+00:00"


@pytest.mark.parametrize("bad_clock", [
    datetime(2026, 10, 7, 19, 48, 0),  # naive
    "now", 42, []])
def test_generated_refuses_naive_and_non_datetime(bad_clock):
    with pytest.raises(ValueError, match="clock must be"):
        extract_iocs("1.2.3.4", now=bad_clock)


# --- ipv4 -------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "192.168.1.10", "8.8.8.8", "127.0.0.1", "100.200.100.200"])
def test_ipv4_hits(value):
    result = extract_iocs("beacon %s done" % value)
    assert rows_of(result, "ipv4") == [value]
    assert result["counts"]["total"] == 1


@pytest.mark.parametrize("bad", [
    "0.0.0.0",       # 0-x lead octet
    "0.1.2.3",
    "255.255.255.255",
    "999.1.2.3",     # malformed octet
    "255.256.255.1",
    "1.2.3.999",
    "1.2.3", "1.2.3.4.5", "5.6.7.8.9.10", "1234.1.1.1",
    "hello world"])
def test_ipv4_invalid_shapes_rejected(bad):
    result = extract_iocs("target %s" % bad)
    assert result["iocs"] == []
    assert result["counts"]["by_type"]["ipv4"] == 0


def test_ipv4_port_and_neighbors_split_off():
    result = extract_iocs("c2 10.0.0.5:8080 alive")
    assert rows_of(result, "ipv4") == ["10.0.0.5"]


# --- ipv6 -------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "::1", "2001:db8::1", "fe80::1", "fe80:0:0:0:0:0:0:1"])
def test_ipv6_hits(value):
    result = extract_iocs("host %s logged" % value)
    assert rows_of(result, "ipv6") == [value]


@pytest.mark.parametrize("bad", [
    "9:48:00", "aa:bb:cc:dd:ee:ff", "1:2:3", "foo::bar",
    "ip2001:db8::1"])
def test_ipv6_prose_and_lookalikes_rejected(bad):
    result = extract_iocs("line %s end" % bad)
    assert result["iocs"] == []


# --- domains ----------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "evil.example.com", "sub.deep.example.org", "a-b.example.com"])
def test_domain_hits(value):
    result = extract_iocs("phoned home to %s" % value)
    assert rows_of(result, "domain") == [value]


def test_domain_trailing_sentence_dot_not_carried():
    result = extract_iocs("visit evil.com.")
    assert rows_of(result, "domain") == ["evil.com"]


@pytest.mark.parametrize("bad", [
    "com",          # bare TLD
    "example",      # no dot at all
    "10.0.0.5",     # ip, no alphabetic TLD
    "1_2.x.com",    # underscore labels refused
    ".secret.com",  # hidden leading-dot host refused
    "libc.so.6"])   # version-suffixed library name refused
def test_domain_rejects(bad):
    result = extract_iocs("see %s now" % bad)
    assert by_type(result, "domain") == 0


def test_domain_ip_prefix_fqdn_both_extracted():
    result = extract_iocs("zone 10.0.0.5.evil.com")
    assert rows_of(result, "domain") == ["10.0.0.5.evil.com"]
    assert rows_of(result, "ipv4") == ["10.0.0.5"]


# --- urls -------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "https://phish.example.com/login",
    "http://c2.example.net:8080/gate?h=abc",
    "ftp://drop.example.net/pub/notes.txt"])
def test_url_hits_basic(value):
    result = extract_iocs("pull it from %s" % value)
    assert rows_of(result, "url") == [value]


def test_url_trailing_punctuation_stripped():
    result = extract_iocs("go to (https://phish.example.com/gate).")
    assert rows_of(result, "url") == ["https://phish.example.com/gate"]


def test_url_authority_hosts_routed():
    result = extract_iocs(
        "one http://10.0.0.99:8080/x two http://[2001:db8::1]:8080/y")
    assert rows_of(result, "url") == [
        "http://10.0.0.99:8080/x", "http://[2001:db8::1]:8080/y"]
    assert rows_of(result, "ipv4") == ["10.0.0.99"]     # port shed
    assert rows_of(result, "ipv6") == ["2001:db8::1"]   # brackets + port
    assert by_type(result, "domain") == 0


def test_url_single_label_authority_dropped():
    result = extract_iocs("open http://localhost/x")
    assert result["iocs"] == []


@pytest.mark.parametrize("source_hint", [None, "run-42"])
def test_url_userinfo_stripped_and_source_noted(source_hint):
    result = extract_iocs(
        "get ftp://user:secret@files.example.com/x",
        source_hint=source_hint)
    expected_source = (
        "run-42; %s" % CRED_NOTE if source_hint else CRED_NOTE)
    assert rows_of(result, "url") == ["ftp://files.example.com/x"]
    assert result["iocs"][0]["source_hint"] == expected_source
    assert "secret" not in json.dumps(result)  # the credential is gone


def test_no_scheme_means_no_url():
    result = extract_iocs("host example.com/path")
    assert rows_of(result, "url") == []
    assert rows_of(result, "domain") == ["example.com"]
    assert by_type(result, "path_posix") == 0


# --- emails -----------------------------------------------------------------


def test_email_hits_with_companion_domain():
    result = extract_iocs("mail the operator ops@soc.example.net today")
    assert rows_of(result, "email") == ["ops@soc.example.net"]
    assert rows_of(result, "domain") == ["soc.example.net"]


@pytest.mark.parametrize("value", [
    "first.last+tag@example.com", "OPS@EXAMPLE.COM"])
def test_email_variants_verbatim(value):
    result = extract_iocs("write to %s please" % value)
    assert rows_of(result, "email") == [value]


@pytest.mark.parametrize("bad", ["no@domain", "@nodot.com"])
def test_email_rejects(bad):
    result = extract_iocs("write %s now" % bad)
    assert rows_of(result, "email") == []


# --- hashes -----------------------------------------------------------------


@pytest.mark.parametrize("value,ioc_type", [
    (MD5, "md5"), (SHA1, "sha1"), (SHA256, "sha256")])
def test_hash_hits(value, ioc_type):
    result = extract_iocs("sample %s verified" % value)
    assert rows_of(result, ioc_type) == [value]
    assert result["counts"]["total"] == 1


def test_hash_dedupe_and_case_distinct():
    twice = extract_iocs("sample %s then %s again" % (MD5, MD5))
    assert rows_of(twice, "md5") == [MD5]  # deduped
    upper = extract_iocs("two %s and %s" % (MD5, MD5.upper()))
    assert rows_of(upper, "md5") == [MD5, MD5.upper()]  # verbatim, 2


@pytest.mark.parametrize("length", [31, 33, 63, 65])
def test_hash_wrong_lengths_rejected(length):
    result = extract_iocs("run " + "a" * length + " end")
    for ioc_type in ("md5", "sha1", "sha256"):
        assert by_type(result, ioc_type) == 0


def test_hashes_not_taken_from_urls():
    url = "https://mirror.example.com/f/%s/blob" % MD5
    result = extract_iocs(url)
    assert rows_of(result, "url") == [url]
    assert rows_of(result, "domain") == ["mirror.example.com"]
    for ioc_type in ("md5", "sha1", "sha256"):
        assert by_type(result, ioc_type) == 0


# --- paths ------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "/etc/passwd", "/var/log/auth.log", "~/eng/x.txt"])
def test_posix_path_hits(value):
    result = extract_iocs("wrote %s yesterday" % value)
    assert rows_of(result, "path_posix") == [value]


def test_posix_path_trailing_dot_stripped():
    result = extract_iocs("log /a/b. noted")
    assert rows_of(result, "path_posix") == ["/a/b"]


@pytest.mark.parametrize("bad", [
    "C:\\Windows\\system32",  # win32, not posix
    "/",       # bare root
    "/a/./b",  # dot segments refused
    "x/y",     # relative, no root
    "https://a.example.com/x"])  # urls masked; their paths are not paths
def test_posix_path_rejects(bad):
    result = extract_iocs("try %s here" % bad)
    assert by_type(result, "path_posix") == 0


@pytest.mark.parametrize("value", [
    "C:\\Users\\ops\\AppData\\Local\\Temp\\dropper.exe",
    "D:\\Tmp\\evil.ps1", "\\\\fileserver\\share\\implant.dll"])
def test_win32_path_hits(value):
    result = extract_iocs("dropper %s spotted" % value)
    assert rows_of(result, "path_win32") == [value]


def test_win32_space_truncation_and_drive_only():
    result = extract_iocs("ran C:\\Program Files\\x and drive C:")
    assert rows_of(result, "path_win32") == ["C:\\Program"]


# --- the undefang ask ---------------------------------------------------------


def test_defanged_ip_pinned():
    result = extract_iocs("payload at 127[.]0[.]0[.]1 seen")
    assert rows_of(result, "ipv4") == ["127.0.0.1"]
    assert result["warnings"] == [WARN_DEFANGED % (3,)]


def test_defanged_url_forms_pinned():
    result = extract_iocs(
        "see http[:]//phish(dot)example[.]com/x logged")
    assert rows_of(result, "url") == ["http://phish.example.com/x"]
    assert rows_of(result, "domain") == ["phish.example.com"]
    assert result["warnings"] == [WARN_DEFANGED % (3,)]
    for row in result["iocs"]:
        assert "hxxp" not in row["value"] and "[.]" not in row["value"]


def test_defang_case_and_defanged_plus_plain():
    case = extract_iocs("HXXPS://Phish[.]Example[.]Com/x")
    assert rows_of(case, "url") == ["https://Phish.Example.Com/x"]
    mixed = extract_iocs(
        "hxxps://c2[.]example[.]net/gate and 10.0.0.1 plain")
    assert rows_of(mixed, "url") == ["https://c2.example.net/gate"]
    assert rows_of(mixed, "domain") == ["c2.example.net"]
    assert rows_of(mixed, "ipv4") == ["10.0.0.1"]
    assert mixed["warnings"] == [WARN_DEFANGED % (3,)]


# --- counts, dedupe, cap ------------------------------------------------------


def test_counts_shape_invariants():
    result = extract_iocs(
        "1.2.3.4 evil.example.com 5d41402abc4b2a76b9719d911017c592 "
        "/tmp/x C:\\Temp\\x.ps1")
    assert set(result["counts"]["by_type"]) == set(IO_TYPES)
    assert result["counts"]["total"] == len(result["iocs"])
    assert sum(result["counts"]["by_type"].values()) == (
        result["counts"]["total"])


def test_dedupe_repeats_and_cross_route():
    repeat = extract_iocs(" ".join(["192.168.1.10"] * 5))
    assert rows_of(repeat, "ipv4") == ["192.168.1.10"]
    both = extract_iocs(
        "see https://phish.example.com/pay then phish.example.com again")
    assert rows_of(both, "domain") == ["phish.example.com"]  # one row


def test_cap_per_type_overflow_warned():
    blob = ", ".join("10.0.0.%d" % n for n in range(1, 27))  # 26 distinct
    result = extract_iocs(blob)
    assert by_type(result, "ipv4") == IOC_CAP
    assert result["counts"]["total"] == IOC_CAP
    assert len(result["iocs"]) == IOC_CAP
    assert result["warnings"] == [WARN_CAP % ("ipv4", IOC_CAP, 1)]


def test_cap_keeps_first_occurrences_and_counts_distinct_drops():
    blob = ("10.0.0.1, " * 5
            + ", ".join("10.0.0.%d" % n for n in range(101, 128)))
    result = extract_iocs(blob)
    assert rows_of(result, "ipv4") == (["10.0.0.1"]
                                       + ["10.0.0.%d" % n
                                          for n in range(101, 125)])
    assert result["warnings"] == [WARN_CAP % ("ipv4", IOC_CAP, 3)]


# --- JSON round-trip ----------------------------------------------------------


def test_result_survives_json_roundtrip():
    result = extract_iocs(
        "10.0.0.5 ops@soc.example.net aaf4c61ddcc5e8a2dabede0f3b482cd9a"
        "ea9434d", now=NOW)
    clone = json.loads(json.dumps(result))
    assert clone == result


# --- the mixed document (shape + discovery order) ------------------------------


def test_mixed_document_full_pin():
    result = extract_iocs(
        "Exec hit 10.0.0.5; beacon https://phish.example.com/pay from "
        "ops@soc.example.net; sha1 "
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d; drop /tmp/x.sh to "
        "C:\\Win\\Temp\\evil.ps1")
    assert result["iocs"] == [
        {"type": "url", "value": "https://phish.example.com/pay",
         "source_hint": None},
        {"type": "domain", "value": "phish.example.com",
         "source_hint": None},
        {"type": "email", "value": "ops@soc.example.net",
         "source_hint": None},
        {"type": "domain", "value": "soc.example.net",
         "source_hint": None},
        {"type": "path_posix", "value": "/tmp/x.sh",
         "source_hint": None},
        {"type": "path_win32", "value": "C:\\Win\\Temp\\evil.ps1",
         "source_hint": None},
        {"type": "ipv4", "value": "10.0.0.5", "source_hint": None},
        {"type": "sha1",
         "value": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
         "source_hint": None}]
    assert result["counts"]["total"] == 8
    assert result["counts"]["by_type"] == {
        "ipv4": 1, "ipv6": 0, "domain": 2, "url": 1, "email": 1,
        "md5": 0, "sha1": 1, "sha256": 0, "path_posix": 1,
        "path_win32": 1}
    assert result["warnings"] == []


# --- house constants (the drift alarm) -----------------------------------------


def test_constants_pins():
    assert IO_TYPES == ("ipv4", "ipv6", "domain", "url", "email",
                        "md5", "sha1", "sha256", "path_posix",
                        "path_win32")
    assert IOC_CAP == 25
    assert CRED_NOTE == "credentials-redacted"
    assert WARN_NONSTR_ITEM == "input blob %d is not a string; skipped"
    assert WARN_DEFANGED == (
        "defanged syntax normalized: %d substitution(s)")
    assert WARN_CAP == "%s: cap %d reached, %d distinct value(s) dropped"


# --- planner purity + no payload literals ---------------------------------------


def _module_source():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.ioc_extractor")
    return Path(module.__file__).read_text(encoding="utf-8")


def test_planner_purity_source_scan():
    source = _module_source()
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned


def test_no_hex_or_url_literals_in_module():
    source = _module_source()
    assert re.search(r"[0-9a-fA-F]{24,}", source) is None
    assert re.search(r"(?i)(?:https?|ftps?)://[A-Za-z0-9]", source) is None
    assert re.search(r"[A-Za-z]:\\\\", source) is None