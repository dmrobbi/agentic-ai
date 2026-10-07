"""KA-090 tests - report redaction: the publishable-scrub shapes (exact
dict equality on policy order and dropped counts), every rule class
triggering (LAN/RFC1918+loopback+tailnet boundaries, house domains +
bare host tokens, /home/wez and /opt/soc- path runs, internal emails
including the bare "@wezzel.com" mention, uuid-derived ids), the
longest-anchor ordering, lookalike SURVIVORS (guards against partial
damage), determinism, markdown-shape preservation, policy replacement /
composition / validation, the OWNER gate (refusal without owner=True,
artifact handed back with owner=True - nothing posts anywhere), JSON
round-trips, and the planner-purity source scan. No network - the
module is pure text transformation by design."""

from __future__ import annotations

import copy
import importlib
import json
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.report_redaction import (
    DEFAULT_REDACTION_POLICY,
    GATE_REFUSAL_REASON,
    RULE_SPEC_KEYS,
    WARN_EMPTY_REPORT,
    WARN_EXTRA_KEYS_FMT,
    WARN_NO_RULES,
    publishable_report,
    redact_report,
)

RESULT_KEYS = {"publishable", "redacted_markdown", "dropped", "warnings"}

EXPECTED_RULES = {
    "lan_ips": "[REDACTED-LAN]",
    "internal_emails": "[REDACTED-EMAIL]",
    "internal_hostnames": "[REDACTED-HOST]",
    "home_opt_paths": "[REDACTED-PATH]",
    "soc_uuids": "[REDACTED-UUID]",
}

SMOKE_RAW = (
    "# Engagement Report\n"
    "10.4.7.9 (thing1) portal https://idm.wezzel.com/.\n"
    "Contact: dmrobbipens@gmail.com\n"
    "Evidence: /home/wez/.openclaw/eng/ENG-42/findings.md\n"
    "Ticket: 3f9a2b7c1d4e (open)\n"
    "Correlation: 71c29ef8-b23c-48ff-86fb-f4768886eab7")
SMOKE_SCRUBBED = (
    "# Engagement Report\n"
    "[REDACTED-LAN] ([REDACTED-HOST]) portal https://[REDACTED-HOST]/.\n"
    "Contact: [REDACTED-EMAIL]\n"
    "Evidence: [REDACTED-PATH]\n"
    "Ticket: [REDACTED-UUID] (open)\n"
    "Correlation: [REDACTED-UUID]")
SMOKE_DROPPED = [
    {"rule": "lan_ips", "count": 1},
    {"rule": "internal_emails", "count": 1},
    {"rule": "internal_hostnames", "count": 2},
    {"rule": "home_opt_paths", "count": 1},
    {"rule": "soc_uuids", "count": 2},
]
SMOKE_SECRETS = ("10.4.7.9", "thing1", "idm.wezzel.com", "dmrobbipens@",
                 "/home/wez", "3f9a2b7c1d4e",
                 "71c29ef8-b23c-48ff-86fb-f4768886eab7")


def unchanged(text, policy=None):
    """A text a policy must NOT touch: verbatim out, nothing dropped."""
    res = redact_report(text, policy)
    assert res["redacted_markdown"] == text
    assert res["dropped"] == []
    return res


# --- constants + result shape ------------------------------------------------


def test_default_policy_rule_order_and_tokens_pinned():
    assert tuple(DEFAULT_REDACTION_POLICY) == tuple(EXPECTED_RULES)
    got = {name: spec["token"]
           for name, spec in DEFAULT_REDACTION_POLICY.items()}
    assert got == EXPECTED_RULES
    assert RULE_SPEC_KEYS == ("token", "patterns")


def test_redact_result_shape_exact():
    res = redact_report(SMOKE_RAW)
    assert set(res) == RESULT_KEYS
    assert res["publishable"] is False
    assert res["redacted_markdown"] == SMOKE_SCRUBBED
    assert res["dropped"] == SMOKE_DROPPED


def test_publishable_flag_always_false_even_clean():
    for text in ("a clean public report", SMOKE_RAW, ""):
        assert redact_report(text)["publishable"] is False


def test_dropped_entry_shape():
    for entry in redact_report(SMOKE_RAW)["dropped"]:
        assert isinstance(entry, dict)
        assert set(entry) == {"rule", "count"}
        assert isinstance(entry["rule"], str)
        assert isinstance(entry["count"], int) and entry["count"] > 0


def test_counts_preserved_as_token_occurrences():
    res = redact_report("10.0.0.1 10.0.0.2 then thing1 gus2")
    assert res["redacted_markdown"] == (
        "[REDACTED-LAN] [REDACTED-LAN] then [REDACTED-HOST] "
        "[REDACTED-HOST]")
    assert res["dropped"] == [
        {"rule": "lan_ips", "count": 2},
        {"rule": "internal_hostnames", "count": 2}]
    md = res["redacted_markdown"]
    assert md.count("[REDACTED-LAN]") == 2
    assert md.count("[REDACTED-HOST]") == 2


def test_redact_is_deterministic():
    assert redact_report(SMOKE_RAW) == redact_report(SMOKE_RAW)
    assert (redact_report("10.0.0.1", DEFAULT_REDACTION_POLICY)
            == redact_report("10.0.0.1", None))


# --- rule class: lan_ips ------------------------------------------------------


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "127.0.0.1", "100.64.0.1", "100.127.255.254"])
def test_lan_ips_redacted(ip):
    res = redact_report(ip)
    assert res["redacted_markdown"] == "[REDACTED-LAN]"
    assert res["dropped"] == [{"rule": "lan_ips", "count": 1}]


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1",
    "11.0.0.1", "100.0.0.1", "1.10.0.1", "10.1.2.3.4"])
def test_lan_ip_boundaries_survive(ip):
    unchanged(ip)


def test_lan_ip_keeps_surroundings():
    assert redact_report(
        "gateway 192.168.1.100:8080 reached"
    )["redacted_markdown"] == "gateway [REDACTED-LAN]:8080 reached"


# --- rule class: internal_emails (BEFORE hostnames: whole-address) -----------


@pytest.mark.parametrize("email", [
    "dawn@wezzel.com", "ops@idm.wezzel.com", "dmrobbipens@gmail.com",
    "@wezzel.com"])
def test_internal_emails_redacted_whole(email):
    res = redact_report(email)
    assert res["redacted_markdown"] == "[REDACTED-EMAIL]"
    assert res["dropped"] == [{"rule": "internal_emails", "count": 1}]


@pytest.mark.parametrize("email", [
    "contact@example.com", "user@notwezzel.com", "user@wezzel.community",
    "ops@wezzel.comxx"])
def test_email_lookalikes_survive(email):
    unchanged(email)


def test_email_inside_sentence_redacts_whole():
    res = redact_report("mailto:dawn@wezzel.com, thanks")
    assert res["redacted_markdown"] == "mailto:[REDACTED-EMAIL], thanks"


# --- rule class: internal_hostnames -------------------------------------------


@pytest.mark.parametrize("host", [
    "wezzel.com", "idm.wezzel.com", "stsgym.com", "stsphotos.com",
    "thing1", "gus2"])
def test_house_hostnames_redacted(host):
    res = redact_report(host)
    assert res["redacted_markdown"] == "[REDACTED-HOST]"
    assert res["dropped"] == [{"rule": "internal_hostnames", "count": 1}]


@pytest.mark.parametrize("text,expected", [
    ("thing1:8881", "[REDACTED-HOST]:8881"),
    ("gus2-clone", "[REDACTED-HOST]-clone"),
    ("www.wezzel.com/x", "[REDACTED-HOST]/x")])
def test_host_redaction_keeps_surroundings(text, expected):
    res = redact_report(text)
    assert res["redacted_markdown"] == expected
    assert res["dropped"] == [{"rule": "internal_hostnames", "count": 1}]


def test_hostnames_case_insensitive():
    res = redact_report("WEZZEL.COM and Thing1")
    assert res["redacted_markdown"] == "[REDACTED-HOST] and [REDACTED-HOST]"
    assert res["dropped"] == [{"rule": "internal_hostnames", "count": 2}]


@pytest.mark.parametrize("host", [
    "example.com", "notwezzel.com", "wezzel.community", "gus3", "thing"])
def test_hostname_lookalikes_survive(host):
    unchanged(host)


# --- rule class: home_opt_paths ------------------------------------------------


@pytest.mark.parametrize("path", [
    "/home/wez", "/home/wez/projects/x.py",
    "/home/wez/.openclaw/tasks.jsonl", "/opt/soc-stack",
    "/opt/soc-stack/docker-compose.yml"])
def test_paths_redacted_whole(path):
    res = redact_report(path)
    assert res["redacted_markdown"] == "[REDACTED-PATH]"
    assert res["dropped"] == [{"rule": "home_opt_paths", "count": 1}]


def test_longest_path_anchor_wins():
    # /home/wez/.openclaw must consume the whole path: no ".openclaw"
    # residue may survive the shorter /home/wez anchor
    res = redact_report("/home/wez/.openclaw/tasks.jsonl")
    assert res["redacted_markdown"] == "[REDACTED-PATH]"
    assert ".openclaw" not in res["redacted_markdown"]


@pytest.mark.parametrize("path", [
    "/opt/soc", "/srv/soc-stack", "home/wez", "/home/wezzy"])
def test_path_lookalikes_survive(path):
    unchanged(path)


def test_path_case_sensitive_upper_home_survives():
    # Linux paths are case-sensitive: the policy stays exact
    unchanged("/HOME/wez")


# --- rule class: soc_uuids ------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("71c29ef8-b23c-48ff-86fb-f4768886eab7", "[REDACTED-UUID]"),
    ("71C29EF8-B23C-48FF-86FB-F4768886EAB7", "[REDACTED-UUID]"),
    ("e3b0c44298fc1c149afbf4c8996fb924", "[REDACTED-UUID]"),
    ("ticket ab12cd34ef56 closed",
     "ticket [REDACTED-UUID] closed")])
def test_uuids_redacted(text, expected):
    res = redact_report(text)
    assert res["redacted_markdown"] == expected
    assert res["dropped"] == [{"rule": "soc_uuids", "count": 1}]


@pytest.mark.parametrize("hexblob", [
    "e3b0c44298fc1c149afbf4c8996fb924736e27",   # 40-hex sha: whole kept
    "e3b0c44298fc1c149afbf4c8996fb924f",         # 33-hex
    "0f0f0f0f0f0f1",                            # 13-hex
    "e3b0c44298fc1c149afbf4c8996fb92",          # 31-hex
])
def test_uuid_guards_prevent_partial_damage(hexblob):
    unchanged(hexblob)


# --- the publishable gate --------------------------------------------------------


def test_gate_refuses_without_owner_by_default():
    res = redact_report("10.0.0.1 in the report")
    assert publishable_report(res) == {
        "published": False, "reason": "owner gate"}
    assert publishable_report(res, owner=False) == {
        "published": False, "reason": GATE_REFUSAL_REASON}


@pytest.mark.parametrize("falsy", [False, 0, None, ""])
def test_gate_refusal_is_the_default_for_falsy_owner(falsy):
    assert publishable_report("text", owner=falsy) == {
        "published": False, "reason": "owner gate"}


def test_gate_handback_shape_with_owner_true():
    res = redact_report("10.0.0.1 in the report")
    assert publishable_report(res, owner=True) == {
        "publishable": True,
        "artifact": "[REDACTED-LAN] in the report"}
    out = publishable_report(res, owner=True)
    assert out["artifact"] == res["redacted_markdown"]


def test_gate_accepts_plain_markdown_string():
    md = "[REDACTED-LAN] done by hand"
    assert publishable_report(md, owner=True) == {
        "publishable": True, "artifact": md}


@pytest.mark.parametrize("bad", [
    None, 42, [], {}, {"publishable": False}, {"redacted_markdown": 42}])
def test_gate_refuses_malformed_input(bad):
    with pytest.raises(ValueError, match="redacted must be"):
        publishable_report(bad)


def test_gate_does_not_mutate_its_input():
    res = redact_report("thing1")
    snapshot = copy.deepcopy(res)
    publishable_report(res)
    publishable_report(res, owner=True)
    assert res == snapshot


def test_gate_outputs_are_json_safe():
    res = redact_report("wezzel.com")
    for verdict in (publishable_report(res),
                    publishable_report(res, owner=True)):
        clone = json.loads(json.dumps(verdict))
        assert clone == verdict


# --- warnings ---------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\n\n"])
def test_empty_report_warns_and_returns_verbatim(blank):
    res = redact_report(blank)
    assert WARN_EMPTY_REPORT in res["warnings"]
    assert res["redacted_markdown"] == blank
    assert res["dropped"] == []


def test_clean_text_carries_no_warnings():
    assert unchanged("a perfectly public report")["warnings"] == []


def test_empty_policy_warns_no_rules():
    res = redact_report("10.0.0.1 stays visible", policy={})
    assert WARN_NO_RULES in res["warnings"]
    assert res["redacted_markdown"] == "10.0.0.1 stays visible"
    assert res["dropped"] == []


def test_extra_rule_spec_keys_absorbed_with_warning():
    policy = {"custom": {"token": "[REDACTED-CUSTOM]",
                         "patterns": ["ACME"], "desc": "note"}}
    res = redact_report("ACME site", policy)
    assert res["warnings"] == [WARN_EXTRA_KEYS_FMT % ("custom", ["desc"])]
    assert res["redacted_markdown"] == "[REDACTED-CUSTOM] site"


# --- policy semantics ---------------------------------------------------------------


def test_custom_policy_replaces_default():
    policy = {"custom_codename": {
        "token": "[REDACTED-CUSTOM]", "patterns": [r"TOPSECRETCODE"]}}
    res = redact_report("TOPSECRETCODE on 10.0.0.1 near thing1", policy)
    assert res["redacted_markdown"] == (
        "[REDACTED-CUSTOM] on 10.0.0.1 near thing1")
    assert res["dropped"] == [{"rule": "custom_codename", "count": 1}]


def test_policy_composition_extends_default():
    policy = {**DEFAULT_REDACTION_POLICY,
              "internal_codename": {
                  "token": "[REDACTED-CODENAME]",
                  "patterns": [r"\bPROJECT-ORION\b"]}}
    res = redact_report("PROJECT-ORION runs on gus2 at 10.0.0.1", policy)
    assert res["redacted_markdown"] == (
        "[REDACTED-CODENAME] runs on [REDACTED-HOST] at [REDACTED-LAN]")
    assert res["dropped"] == [
        {"rule": "lan_ips", "count": 1},
        {"rule": "internal_hostnames", "count": 1},
        {"rule": "internal_codename", "count": 1}]


def test_policy_none_equals_the_default_constant():
    text = "thing1 at 10.0.0.1, ops@wezzel.com, /opt/soc-stack, deadbeef"
    assert (redact_report(text, None)
            == redact_report(text, DEFAULT_REDACTION_POLICY))


# --- markdown preservation ------------------------------------------------------------


def test_markdown_shape_preserved():
    text = ("# Pentest Report ENG-9\n"
            "- internal host 10.0.0.1 up\n"
            "```\nnmap -sS 192.168.1.1\n```\n")
    res = redact_report(text)
    assert res["redacted_markdown"].count("\n") == text.count("\n")
    assert res["redacted_markdown"].startswith("# Pentest Report ENG-9\n")
    assert "nmap -sS [REDACTED-LAN]" in res["redacted_markdown"]
    assert "```\n" in res["redacted_markdown"]


def test_only_known_tokens_appear_in_output():
    md = redact_report(SMOKE_RAW)["redacted_markdown"]
    found = set(re.findall(r"\[REDACTED-[A-Z0-9]+\]", md))
    assert found == set(EXPECTED_RULES.values())


# --- json round-trips -------------------------------------------------------------------


def test_result_and_policy_survive_json_roundtrip():
    res = redact_report(SMOKE_RAW)
    clone = json.loads(json.dumps(res))
    assert clone == res
    policy = {**DEFAULT_REDACTION_POLICY,
              "custom_codename": {"token": "[REDACTED-CUSTOM]",
                                  "patterns": [r"\bACME-CORP\b"]}}
    clone_policy = json.loads(json.dumps(policy))
    text = "ACME-CORP at 10.0.0.1"
    assert redact_report(text, clone_policy) == (
        redact_report(text, policy))


# --- hostile inputs ------------------------------------------------------------------------


@pytest.mark.parametrize("bad_text", [None, 42, b"10.0.0.1", ["x"], {}])
def test_report_text_must_be_string(bad_text):
    with pytest.raises(ValueError, match="report_text must be a string"):
        redact_report(bad_text)


@pytest.mark.parametrize("bad_policy", [42, "lan_ips", [], ("a",)])
def test_policy_must_be_dict(bad_policy):
    with pytest.raises(ValueError, match="policy must be a dict"):
        redact_report("text", bad_policy)


@pytest.mark.parametrize("bad_spec", [
    42,
    {},
    {"patterns": []},
    {"token": None, "patterns": []},
    {"token": "  ", "patterns": []},
    {"token": "[X]", "patterns": "nope"},
    {"token": "[X]", "patterns": [42]},
    {"token": "[X]", "patterns": ["[unclosed"]},
    {"token": "[X]", "patterns": ["ok", "["]},
])
def test_malformed_rule_specs_refused(bad_spec):
    with pytest.raises(ValueError, match="policy rule 'custom'"):
        redact_report("text", {"custom": bad_spec})


@pytest.mark.parametrize("bad_name", [42, "   ", "", None])
def test_rule_names_must_be_non_blank_strings(bad_name):
    with pytest.raises(ValueError, match="rule names must be non-blank"):
        redact_report("text", {bad_name: {"token": "[X]",
                                          "patterns": []}})


# --- planner purity --------------------------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.report_redaction")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "urlopen", "socket", "requests",
                   "http.client", "open(", "Path(", "write_text"):
        assert banned not in source, banned
    for token in EXPECTED_RULES.values():
        assert token in source


def test_docstring_names_the_owner_gated_publish_target():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.report_redaction")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "bedimsecurity.com/capabilities/" in source