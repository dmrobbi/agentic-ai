"""KA-063 tests - staging verification: the three caller-supplied channels
(declared ranges / DNS suffixes / hosts registry) and their union semantics,
the conservative not-in-staging default, the RFC1918+ULA lab posture shared
with the wave's egress guard, target-spec reductions (URL with userinfo
decoys, user@host, host:port, host:path, CIDR containment), fail-closed
hostile shapes, batch reason naming, decision-dict determinism, the house
(bool, reason) gate, and a module source-scan pin (no chassis import, no
clock reads, no exec facilities, no DNS/network). No network."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.staging_check import (
    DEFAULT_STAGING_CONFIG,
    DECISION_KEYS,
    MAX_TARGETS_PER_CHECK,
    POSTURE_NETS,
    StageVerdict,
    StagingConfig,
    TARGET_KEYS,
    VIA_RANGE,
    VIA_REGISTRY,
    VIA_SUFFIX,
    compile_declaration,
    staging_gate,
    stage_check,
    stg_scrub_target,
)

GO = "go: %d target(s) inside the declared staging environment"
NO_GO = "no-go: target '%s' is not inside the declared staging environment"

# The shared compiled declaration used across the matching tests:
# three ranges (v4 RFC1918 + v6 ULA), one DNS suffix, and a registry
# with an address-attested name and a name-only attestation.
LAB = compile_declaration(
    ranges=("10.50.0.0/16", "192.168.5.0/24", "fd12:3456::/48"),
    dns_suffixes=("lab.corp",),
    hosts={"vault.internal": (), "db.lab.corp": ("10.50.1.5",)},
)
REGISTRY_ONLY = compile_declaration(hosts={"db.lab.corp": ["10.50.1.5"]})

REASON_GO_ONE = "go: 1 target(s) inside the declared staging environment"


def test_posture_nets_pin_the_wave_rfc1918_posture():
    # exact supersets: RFC1918 + the IPv6 ULA analog (egress-guard parity)
    assert [str(n) for n in POSTURE_NETS] == [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]


def test_compile_parses_and_normalizes():
    assert [str(n) for n in LAB.ranges] == [
        "10.50.0.0/16", "192.168.5.0/24", "fd12:3456::/48",
    ]
    assert LAB.dns_suffixes == ("lab.corp",)
    assert {
        k: tuple(str(a) for a in v) for k, v in LAB.hosts.items()
    } == {"vault.internal": (), "db.lab.corp": ("10.50.1.5",)}
    # declared-range host bits are strict-normalized (strict=False)
    strict = compile_declaration(ranges=("10.50.0.9/16",))
    assert [str(n) for n in strict.ranges] == ["10.50.0.0/16"]
    # suffixes normalize case/trailing dots and dedupe, order preserved
    casey = compile_declaration(dns_suffixes=("LAB.CORP.", "lab.corp."))
    assert casey.dns_suffixes == ("lab.corp",)
    single = compile_declaration(ranges="10.50.0.0/16", dns_suffixes="corp.lab")
    assert [str(n) for n in single.ranges] == ["10.50.0.0/16"]
    assert single.dns_suffixes == ("corp.lab",)


def test_labdeclaration_direct_construction_validates():
    with pytest.raises(ValueError):
        compile_declaration(ranges=["8.8.8.0/24"])  # public space
    lab = compile_declaration(ranges=["10.50.0.0/16"])
    assert [str(n) for n in lab.ranges] == ["10.50.0.0/16"]


@pytest.mark.parametrize("bad", [
    "8.8.8.0/24",        # public
    "169.254.0.0/16",    # link-local / metadata space
    "127.0.0.0/8",       # loopback
    "224.0.0.0/4",       # multicast
])
def test_declared_range_posture_rejects(bad):
    with pytest.raises(ValueError):
        compile_declaration(ranges=[bad])


@pytest.mark.parametrize("bad", [
    "",
    "..",
    "*.lab.corp",    # wildcards never parse as lab suffixes
    "la b",
    "10.0.0.5",      # pure-numeric strings are not DNS names
    "-lab.corp",
])
def test_dns_suffix_shape_rejects(bad):
    with pytest.raises(ValueError):
        compile_declaration(dns_suffixes=[bad])


@pytest.mark.parametrize("hosts", [
    {"10.50.1.5": ()},        # addresses never register as KEYS
    {5: ()},                  # non-string key
    {"a b": ()},              # not a hostname
    {"ok.name": "10.50.1"},   # unparseable address
    {"ok.name": ["8.8.8.8"]},  # public address (posture violation)
    {"ok.name": 42},          # address value of a non-address type
])
def test_registry_validation_rejects(hosts):
    with pytest.raises(ValueError):
        compile_declaration(hosts=hosts)


@pytest.mark.parametrize("kwargs", [
    {"ranges": ["10.50.%d.0/24" % i for i in range(257)]},
    {"dns_suffixes": ["h%d.lab.corp" % i for i in range(257)]},
    {"hosts": {"h%d.lab.corp" % i: () for i in range(257)}},
])
def test_declaration_channel_cap_rejects(kwargs):
    with pytest.raises(ValueError):
        compile_declaration(**kwargs)


def test_raw_declaration_dict_unknown_keys_rejected():
    with pytest.raises(ValueError):
        stage_check("10.50.1.5", {"ranges": ["10.50.0.0/16"], "junk": 1})


def test_raw_declaration_dict_missing_keys_are_empty_channels():
    assert stage_check("10.50.1.5",
                       {"ranges": ["10.50.0.0/16"]}).in_staging is True
    assert stage_check("10.50.1.5", {"dns_suffixes": ["lab.corp"]}
                       ).in_staging is False


def test_first_declared_matching_range_wins():
    lab = compile_declaration(ranges=["10.0.0.0/8", "10.50.0.0/16"])
    row = stage_check("10.50.1.5", lab).targets[0]
    assert (row["matched_via"], row["matched"]) == (VIA_RANGE, "10.0.0.0/8")


def test_ip_inside_declared_range_is_staged():
    verdict = stage_check("10.50.3.7", LAB)
    assert verdict.in_staging is True
    assert verdict.reason == REASON_GO_ONE
    assert verdict.targets[0] == {
        "raw": "10.50.3.7",
        "host": "10.50.3.7",
        "shape": "ip",
        "in_staging": True,
        "matched_via": VIA_RANGE,
        "matched": "10.50.0.0/16",
    }


def test_neighbor_rfc1918_outside_declared_ranges_not_staged():
    # THE core conservative pin: RFC1918-ness alone grants nothing
    verdict = stage_check("10.51.3.7", LAB)
    assert verdict.in_staging is False
    assert verdict.reason == NO_GO % "10.51.3.7"
    row = verdict.targets[0]
    assert (row["shape"], row["in_staging"], row["matched_via"],
            row["matched"]) == ("ip", False, None, None)


@pytest.mark.parametrize("target", [
    "8.8.8.8",           # public
    "169.254.169.254",   # cloud metadata space
    "203.0.113.5",       # public TEST-NET
])
def test_nonposture_ips_never_staged(target):
    verdict = stage_check(target, LAB)
    assert verdict.in_staging is False
    assert verdict.reason == NO_GO % target


def test_ula_subnet_staged_and_mixed_family_never():
    assert stage_check("fd12:3456::1", LAB).in_staging is True
    assert stage_check("fd12:3457::1", LAB).in_staging is False
    v4only = compile_declaration(ranges=["10.50.0.0/16"])
    assert stage_check("fd12:3456::1", v4only).in_staging is False
    v6only = compile_declaration(ranges=["fd12:3456::/48"])
    assert stage_check("10.50.1.5", v6only).in_staging is False


def test_cidr_inside_declared_range_is_staged():
    row = stage_check("10.50.0.0/24", LAB).targets[0]
    assert (row["shape"], row["in_staging"], row["matched_via"],
            row["matched"]) == ("cidr", True, VIA_RANGE, "10.50.0.0/16")
    # host bits on the target CIDR are strict-normalized too
    assert stage_check("10.50.0.9/24", LAB).in_staging is True


def test_cidr_overlap_but_not_fully_contained_not_staged():
    for target in ("10.50.0.0/15", "192.168.0.0/16", "fd12:3456::/32"):
        assert stage_check(target, LAB).in_staging is False


def test_cidr_never_staged_by_name_channels():
    # the registry and DNS suffixes never bless networks
    assert stage_check("10.50.1.0/24", REGISTRY_ONLY).in_staging is False


def test_name_suffix_channel_wins_documented_order():
    # db.lab.corp is BOTH a declared suffix member and a registry key:
    # the suffix channel is consulted first (documented order)
    row = stage_check("db.lab.corp", LAB).targets[0]
    assert (row["shape"], row["in_staging"], row["matched_via"],
            row["matched"]) == ("name", True, VIA_SUFFIX, "lab.corp")


@pytest.mark.parametrize("target", [
    "web.lab.corp.",   # trailing-dot FQDN form
    "WEB.LAB.CORP",    # DNS case-insensitivity (host stays verbatim in row)
    "lab.corp",        # exact suffix equality counts
])
def test_dns_suffix_match_forms(target):
    verdict = stage_check(target, LAB)
    row = verdict.targets[0]
    assert row["in_staging"] is True
    assert row["matched_via"] == VIA_SUFFIX
    assert row["matched"] == "lab.corp"
    assert row["host"] == target  # reduced host verbatim for audit


@pytest.mark.parametrize("target", [
    "evillab.corp",            # no label boundary before the suffix
    "xlab.corp",               # same trap
    "lab.corp.evil.example",   # suffix position, not a suffix match
])
def test_label_boundary_traps_not_staged(target):
    assert stage_check(target, LAB).in_staging is False


def test_registry_attested_names_match_exactly():
    row = stage_check("vault.internal", LAB).targets[0]
    assert (row["in_staging"], row["matched_via"], row["matched"]) == (
        True, VIA_REGISTRY, "vault.internal")
    # registry lookups are case-insensitive on the normalized name
    assert stage_check("Vault.Internal", LAB).targets[0][
        "matched_via"] == VIA_REGISTRY
    # registry keys are EXACT: no subdomain absorption
    assert stage_check("sub.vault.internal", LAB).in_staging is False


def test_registry_name_target_with_addresses():
    row = stage_check("db.lab.corp", REGISTRY_ONLY).targets[0]
    assert (row["in_staging"], row["matched_via"], row["matched"]) == (
        True, VIA_REGISTRY, "db.lab.corp")


def test_registered_address_blesses_ip_target():
    row = stage_check("10.50.1.5", REGISTRY_ONLY).targets[0]
    assert (row["shape"], row["in_staging"], row["matched_via"],
            row["matched"]) == ("ip", True, VIA_REGISTRY, "db.lab.corp")


def test_registry_membership_does_not_bless_others():
    # names: exact keys only; addresses: only those actually registered
    assert stage_check("db.other.internal", REGISTRY_ONLY).in_staging is False
    assert stage_check("10.50.1.6", REGISTRY_ONLY).in_staging is False


def test_config_can_restrict_registry_ip_match():
    config = StagingConfig(allow_registry_ip_match=False)
    verdict = stage_check("10.50.1.5", REGISTRY_ONLY, config=config)
    assert verdict.in_staging is False
    # declared ranges keep working under the same config
    assert stage_check("10.50.1.5", LAB, config=config).in_staging is True


def test_none_config_uses_default():
    assert DEFAULT_STAGING_CONFIG.allow_registry_ip_match is True
    assert stage_check("10.50.1.5", REGISTRY_ONLY,
                       config=None).in_staging is True


@pytest.mark.parametrize("target,shape,matched", [
    ("http://10.50.2.4/x", "url", "10.50.0.0/16"),
    ("http://db.lab.corp:8080/health", "url", "lab.corp"),
    ("https://[fd12:3456::9]:8443/metrics", "url", "fd12:3456::/48"),
    ("10.50.3.9:22", "hostport", "10.50.0.0/16"),
    ("db.lab.corp:5432", "hostport", "lab.corp"),
    ("wez@10.50.7.2", "ip", "10.50.0.0/16"),
    ("wez@10.50.7.2:/srv/backups", "hostpath", "10.50.0.0/16"),
])
def test_reduction_routes_staged(target, shape, matched):
    row = stage_check(target, LAB).targets[0]
    assert (row["shape"], row["in_staging"], row["matched"]) == (
        shape, True, matched)


def test_url_userinfo_decoy_never_staged():
    # egress-guard parity: classify by the real host, never by userinfo
    verdict = stage_check("http://10.50.2.4@evil.example/x", LAB)
    row = verdict.targets[0]
    assert row["shape"] == "url"
    assert (row["in_staging"], row["matched_via"], row["matched"]) == (
        False, None, None)
    assert verdict.in_staging is False


@pytest.mark.parametrize("target", [
    "10.0.0.256",          # quad-shaped, invalid octet
    "010.050.001.005",     # octal trick
    "10.0.0.5.6",          # five quads
    "$PATH",               # expansion junk
    "has space",           # not a hostname
    "//10.50.1.5",         # scheme-less netloc: not a target shape
])
def test_unknown_shapes_fail_closed(target):
    verdict = stage_check(target, LAB)
    row = verdict.targets[0]
    assert row["shape"] == "unknown"
    assert (row["matched_via"], row["matched"]) == (None, None)
    assert verdict.in_staging is False


@pytest.mark.parametrize("bad", [
    "",
    "   ",
    None,
    42,
    b"10.50.1.5",
    "a\x00b",
    "10.50.1.5\t:22",   # interior control character
    "x" * 5000,
])
def test_target_scrub_rejects(bad):
    with pytest.raises(ValueError):
        stage_check(bad, LAB)
    with pytest.raises(ValueError):
        staging_gate(bad, LAB)


def test_scrub_strips_surrounding_whitespace():
    assert stg_scrub_target(" 10.50.1.5 ") == "10.50.1.5"
    # leading/trailing control chars are stripped away, interior ones
    # are rejected (test_target_scrub_rejects covers the interior case)


def test_batch_with_one_bad_spec_raises():
    with pytest.raises(ValueError):
        stage_check(["10.50.1.5", ""], LAB)


def test_batch_all_staged_reason_and_order():
    verdict = stage_check(["10.50.1.5", "db.lab.corp"], LAB)
    assert verdict.in_staging is True
    assert verdict.reason == "go: 2 target(s) inside the declared staging environment"
    assert [row["raw"] for row in verdict.targets] == [
        "10.50.1.5", "db.lab.corp"]


def test_batch_blocks_on_first_unmatched():
    verdict = stage_check(("10.50.1.5", "8.8.8.8", "9.9.9.9"), LAB)
    assert verdict.in_staging is False
    assert verdict.reason == NO_GO % "8.8.8.8"  # first UNmatched, not first row


def test_batch_dedupes_on_scrubbed_spec():
    verdict = stage_check(["10.50.1.5", " 10.50.1.5 "], LAB)
    assert [row["raw"] for row in verdict.targets] == ["10.50.1.5"]


def test_empty_batch_vacuously_staged():
    verdict = stage_check([], LAB)
    assert verdict.in_staging is True
    assert verdict.as_dict() == {
        "targets": (),
        "in_staging": True,
        "reason": "go: no target(s) to stage",
    }


def test_oversized_batch_rejected():
    specs = ["10.50.%d.3" % i for i in range(MAX_TARGETS_PER_CHECK + 1)]
    with pytest.raises(ValueError):
        stage_check(specs, LAB)


def test_decision_dict_exact_shape_and_keys():
    verdict = stage_check("10.50.3.7", LAB)
    assert verdict.as_dict() == {
        "targets": ({
            "raw": "10.50.3.7",
            "host": "10.50.3.7",
            "shape": "ip",
            "in_staging": True,
            "matched_via": VIA_RANGE,
            "matched": "10.50.0.0/16",
        },),
        "in_staging": True,
        "reason": REASON_GO_ONE,
    }
    assert tuple(verdict.as_dict()) == DECISION_KEYS
    assert tuple(verdict.targets[0]) == TARGET_KEYS


def test_verdict_is_deterministic_and_json_serializable():
    first = stage_check(["10.50.1.5", "db.lab.corp"], LAB)
    second = stage_check(("10.50.1.5", "db.lab.corp"), LAB)
    assert first.as_dict() == second.as_dict()
    # JSON round-trip: tuple rows unload as lists, so the serialized
    # form must be byte-stable across the round trip (list-of-dict batch)
    dumped = json.dumps(first.as_dict())
    assert json.dumps(json.loads(dumped)) == dumped


def test_none_declaration_is_conservative():
    for target in ("10.50.1.5", "db.lab.corp"):
        verdict = stage_check(target)  # nothing declared
        assert verdict.in_staging is False
        row = verdict.targets[0]
        assert (row["matched_via"], row["matched"]) == (None, None)


def test_gate_go_and_nogo():
    go, reason = staging_gate("db.lab.corp", LAB)
    assert go is True
    assert reason == "go: 1 target(s) inside the declared staging environment"
    go, reason = staging_gate("8.8.8.8", LAB)
    assert go is False
    assert reason == NO_GO % "8.8.8.8"


def test_gate_accepts_finished_verdict():
    verdict = stage_check("8.8.8.8", LAB)
    assert staging_gate(verdict) == (verdict.in_staging, verdict.reason)
    batch = stage_check(["10.50.1.5", "db.lab.corp"], LAB)
    assert staging_gate(batch) == (True, batch.reason)


@pytest.mark.parametrize("verdict", [
    StageVerdict(
        targets=({"raw": "x", "shape": "unknown", "in_staging": False},),
        in_staging=True, reason="lie",
    ),
    StageVerdict(targets=("not-a-row",), in_staging=True, reason="x"),
    StageVerdict(targets=(), in_staging=1, reason="x"),
    42,
])
def test_gate_validates_verdicts_fail_closed(verdict):
    with pytest.raises(ValueError):
        staging_gate(verdict)


@pytest.mark.parametrize("bad", [42, "yes", {}])
def test_config_must_be_staging_config(bad):
    with pytest.raises(ValueError):
        stage_check("10.50.1.5", LAB, config=bad)


def test_staging_config_knob_validation():
    with pytest.raises(ValueError):
        StagingConfig(allow_registry_ip_match="yes")


def test_string_declaration_rejected():
    # a bare string is not a compiled declaration or a triple dict
    with pytest.raises(ValueError):
        stage_check("10.50.1.5", "10.50.0.0/16")


def test_module_purity_source_scan():
    # planner purity by construction: no chassis import, no clock, no
    # exec facilities, no name resolution/network (stdlib reduce+match only)
    module = importlib.import_module("agentic_ai.agents.cyber.staging_check")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "from agentic_ai", "import agentic_ai",
        "subprocess", "eval(", "os.system", "exec(", "popen",
        "socket", "utcnow", "time.time", "urlopen",
        "gethostby", "getaddrinfo",
    ):
        assert forbidden not in source, forbidden