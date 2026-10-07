"""KA-077 tests - report email bridge: the mailbox env-file pattern
(the REPORTS_MAILBOX_ENV loader shape: KEY=VALUE content rules plus the
 SMTP/IMAP field contract), values-free plans (the credential reduces
to a reference token, redact() is the scrub net), the dry-send default
(composed dicts stay send_mode "dry"; the send seam raises by design),
the owner notification contract (explicit recipient > WAZUH_REPORTS_
RECIPIENT > refused), and the planner-purity source scan (exactly one
file-read seam; no process, network, environment, or wall-clock
facilities). No network; synthetic content only - never real
hostnames or secret material. Provenance: shapes are modeled on the
SOC mailbox loader contract pinned in OPT-77 (KA-077)."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.report_mail import (
    ADDRESS_CAP,
    BODY_CAP,
    CREDENTIAL_REF,
    DEFAULT_MAILBOX,
    ERROR_KIND,
    KIND_BATTERY,
    KIND_ENGAGEMENT,
    MAILBOX_ENV_DEFAULT,
    MAILBOX_ENV_VAR,
    NOT_IMPLEMENTED_MSG,
    REASON_MALFORMED,
    REASON_NOT_FOUND,
    REASON_UNREADABLE,
    RECIPIENT_FIELD,
    REDACTED,
    REQUIRED_FIELDS,
    SEND_MODE_DRY,
    SEVERITIES,
    SUBJECT_CAP,
    MailboxEnvError,
    compose_battery_mail,
    compose_report_mail,
    mailbox_plan,
    parse_mailbox_env,
    read_mailbox_env,
    redact,
    scrub_address,
    scrub_target,
    send_report_mail,
)

# --- synthetic content (no real hostnames, no real secret material) -------


PW = "v4mail-pw-s3cret"

ENV_LINES = [
    "# synthetic mailbox env - test content only",
    "SMTP_HOST=mail.example.internal",
    "SMTP_PORT=  4587  ",
    "IMAP_HOST=mail.example.internal",
    "IMAP_PORT=1493",
    "REPORTS_MAILBOX=reports@lab.example",
    "REPORTS_MAILBOX_PW=" + PW,
    "WAZUH_REPORTS_RECIPIENT=owner@lab.example",
    "no equals sign - skipped",
]
ENV_TEXT = "\n".join(ENV_LINES) + "\n"

ENTRIES = {
    "SMTP_HOST": "mail.example.internal",
    "SMTP_PORT": "4587",
    "IMAP_HOST": "mail.example.internal",
    "IMAP_PORT": "1493",
    "REPORTS_MAILBOX": "reports@lab.example",
    "REPORTS_MAILBOX_PW": PW,
    "WAZUH_REPORTS_RECIPIENT": "owner@lab.example",
}

PLAN_EXPECT = {
    "ok": True,
    "smtp_host": "mail.example.internal",
    "smtp_port": 4587,
    "imap_host": "mail.example.internal",
    "imap_port": 1493,
    "mailbox": "reports@lab.example",
    "credential": CREDENTIAL_REF,
    "default_recipient": "owner@lab.example",
}

REPORT = {
    "engagement_id": "ENG-001",
    "target": "10.44.0.20",
    "title": "Quarterly web engagement",
    "findings": [
        {"id": "F-001", "severity": "HIGH",
         "summary": "reflected xss in search",
         "evidence": "runs/evidence/xss.md"},
        {"id": "F-002", "severity": "low", "summary": ""},
    ],
    "notes": "retest scheduled",
}

REPORT_BODY = (
    "Quarterly web engagement\n"
    "target: 10.44.0.20\n"
    "findings: 2 composed, 0 skipped\n"
    "- [high] F-001: reflected xss in search\n"
    "  evidence: runs/evidence/xss.md\n"
    "- [low] F-002: (no summary)\n"
    "\n"
    "retest scheduled")

COMPOSED_REPORT_EXPECT = {
    "ok": True,
    "send_mode": "dry",
    "kind": KIND_ENGAGEMENT,
    "transport": None,
    "envelope": {
        "from": "reports@lab.example",
        "to": "ops@lab.example",
        "reply_to": None,
    },
    "subject": "Engagement report ENG-001 - 2 findings "
               "(target 10.44.0.20)",
    "body": REPORT_BODY,
    "credential": CREDENTIAL_REF,
    "mailbox": PLAN_EXPECT,
}

RUN = {
    "battery_id": "BAT-01",
    "target": "10.44.0.5",
    "completed": 7,
    "failed": 2,
    "skipped": 1,
    "notes": "guardrails raised on 2",
}

COMPOSED_BATTERY_EXPECT = {
    "ok": True,
    "send_mode": "dry",
    "kind": KIND_BATTERY,
    "transport": None,
    "envelope": {
        "from": "reports@lab.example",
        "to": "owner@lab.example",
        "reply_to": None,
    },
    "subject": "battery BAT-01 complete: 7 ok, 2 failed, 1 skipped",
    "body": "battery BAT-01 complete\n"
            "target: 10.44.0.5\n"
            "completed: 7\n"
            "failed: 2\n"
            "skipped: 1\n"
            "\n"
            "guardrails raised on 2",
    "credential": CREDENTIAL_REF,
    "mailbox": PLAN_EXPECT,
}


def _needles_absent(payload: object) -> None:
    dumped = json.dumps(payload)
    assert PW not in dumped, "secret value leaked into a returned surface"


# --- contract constants ----------------------------------------------------


def test_constants_match_mailbox_contract():
    assert MAILBOX_ENV_VAR == "REPORTS_MAILBOX_ENV"
    assert MAILBOX_ENV_DEFAULT == "/etc/agentic-soc/soc-mailbox.env"
    assert REQUIRED_FIELDS == (
        "SMTP_HOST", "SMTP_PORT", "IMAP_HOST", "IMAP_PORT",
        "REPORTS_MAILBOX", "REPORTS_MAILBOX_PW")
    assert RECIPIENT_FIELD == "WAZUH_REPORTS_RECIPIENT"
    assert DEFAULT_MAILBOX == "reports@bedimsecurity.com"
    assert CREDENTIAL_REF == "@mailbox-env:REPORTS_MAILBOX_PW@"
    assert REDACTED == "<redacted>"
    assert SEVERITIES == ("critical", "high", "medium", "low")
    assert SEND_MODE_DRY == "dry"
    assert KIND_ENGAGEMENT == "engagement_report"
    assert KIND_BATTERY == "battery_completion"
    assert SUBJECT_CAP == 240
    assert BODY_CAP == 200_000
    assert ADDRESS_CAP == 254


# --- the mailbox env-file convention ---------------------------------------


def test_parse_mailbox_env_follows_the_convention():
    assert parse_mailbox_env(ENV_TEXT) == ENTRIES
    # the first '=' splits; value side may carry more '='
    assert parse_mailbox_env("K=a=b\n") == {"K": "a=b"}
    # identical duplicates collapse into one entry
    assert parse_mailbox_env("K=v\nK=v\n") == {"K": "v"}


def test_parse_mailbox_env_rejects_malformed():
    with pytest.raises(MailboxEnvError) as exc_info:
        parse_mailbox_env("SMTP_HOST=x\n=line\n")
    assert "line 2" in str(exc_info.value)
    with pytest.raises(MailboxEnvError) as exc_info:
        parse_mailbox_env("A=1\nA=2\n")
    assert "line 2" in str(exc_info.value)
    assert "'A'" in str(exc_info.value)
    for bad in (None, 42, []):
        with pytest.raises(TypeError):
            parse_mailbox_env(bad)


def test_read_mailbox_env_missing_and_unreadable(tmp_path):
    missing = read_mailbox_env(tmp_path / "nope.env")
    assert missing == {
        "ok": False,
        "error": {"kind": ERROR_KIND, "reason": REASON_NOT_FOUND,
                  "detail": "mailbox env file not found"},
    }
    assert read_mailbox_env("")["error"]["reason"] == REASON_NOT_FOUND
    assert read_mailbox_env(None)["error"]["reason"] == REASON_UNREADABLE
    assert read_mailbox_env(42)["error"]["reason"] == REASON_UNREADABLE
    directory = tmp_path / "adir"
    directory.mkdir()
    assert read_mailbox_env(directory) == {
        "ok": False,
        "error": {"kind": ERROR_KIND, "reason": REASON_UNREADABLE,
                  "detail": "mailbox env file unreadable: "
                            "IsADirectoryError"},
    }


def test_read_mailbox_env_malformed_content(tmp_path):
    # the malformed VALUE is the synthetic secret: the error detail
    # must name the line, never the raw line
    path = tmp_path / "mailbox.env"
    path.write_text("SMTP_HOST=mail.example.internal\n=" + PW + "\n",
                    encoding="utf-8")
    result = read_mailbox_env(path)
    assert result["ok"] is False
    assert result["error"]["kind"] == ERROR_KIND
    assert result["error"]["reason"] == REASON_MALFORMED
    assert "line 2" in result["error"]["detail"]
    _needles_absent(result)


def test_read_mailbox_env_roundtrip(tmp_path):
    # the ONE legit place secret values surface: this seam's "entries"
    path = tmp_path / "mailbox.env"
    path.write_text(ENV_TEXT, encoding="utf-8")
    assert read_mailbox_env(path) == {"ok": True, "entries": ENTRIES}


# --- the values-free mailbox plan ------------------------------------------


def test_mailbox_plan_is_values_free():
    plan = mailbox_plan(ENTRIES)
    assert plan == PLAN_EXPECT
    _needles_absent(plan)
    # the optional recipient field: absent or blank -> None
    without = {k: v for k, v in ENTRIES.items() if k != RECIPIENT_FIELD}
    assert mailbox_plan(without)["default_recipient"] is None
    blank = dict(ENTRIES, **{RECIPIENT_FIELD: "   "})
    assert mailbox_plan(blank)["default_recipient"] is None


def test_mailbox_plan_requires_every_field():
    for field in REQUIRED_FIELDS:
        entries = {k: v for k, v in ENTRIES.items() if k != field}
        with pytest.raises(ValueError) as exc_info:
            mailbox_plan(entries)
        assert field in str(exc_info.value)
    for bad in (None, [], "mailbox.env", 42):
        with pytest.raises(ValueError):
            mailbox_plan(bad)


def test_mailbox_plan_rejects_bad_ports_and_hosts():
    for field in ("SMTP_PORT", "IMAP_PORT"):
        for bad in ("0", "70000", "not-a-port", "", None, True):
            entries = dict(ENTRIES, **{field: bad})
            with pytest.raises(ValueError):
                mailbox_plan(entries)
    for field in ("SMTP_HOST", "IMAP_HOST"):
        for bad in ("", "   ", "mail host\nsecond", None, 42, "h" * 256):
            entries = dict(ENTRIES, **{field: bad})
            with pytest.raises(ValueError):
                mailbox_plan(entries)
    for field in ("SMTP_PORT", "IMAP_PORT"):
        for good, parsed in (("587", 587), (993, 993)):
            entries = dict(ENTRIES, **{field: good})
            assert mailbox_plan(entries)[field.lower()] == parsed


def test_mailbox_plan_rejects_bad_addresses():
    for bad in ("", "   ", "no-at-sign", "a@nodots",
                "a@x.com\r\nBcc: v@z.co", "reports@lab.example extra",
                None, 42):
        entries = dict(ENTRIES, REPORTS_MAILBOX=bad)
        with pytest.raises(ValueError):
            mailbox_plan(entries)
    good = mailbox_plan(
        dict(ENTRIES, REPORTS_MAILBOX="Reports+Tag@Sub.Example.Co"))
    assert good["mailbox"] == "Reports+Tag@Sub.Example.Co"
    assert DEFAULT_MAILBOX == "reports@bedimsecurity.com"


# --- the dry-send composition contract --------------------------------------


def test_compose_report_mail_full_shape():
    composed = compose_report_mail(
        REPORT, mailbox=ENTRIES, recipient="ops@lab.example")
    assert composed == COMPOSED_REPORT_EXPECT
    _needles_absent(composed)


def test_compose_report_mail_planless_defaults():
    composed = compose_report_mail(REPORT, recipient="owner@lab.example")
    assert composed["envelope"]["from"] == DEFAULT_MAILBOX
    assert composed["mailbox"] is None
    assert composed["credential"] == CREDENTIAL_REF


def test_compose_report_mail_recipient_from_env_default():
    composed = compose_report_mail(REPORT, mailbox=ENTRIES)
    assert composed["envelope"]["to"] == "owner@lab.example"


def test_compose_report_mail_recipient_refused():
    with pytest.raises(ValueError) as exc_info:
        compose_report_mail(REPORT)
    assert "recipient" in str(exc_info.value)


def test_compose_report_mail_skips_malformed_findings():
    report = dict(REPORT, findings=[
        "not-a-dict",
        {"severity": "weird"},  # id missing AND severity bad
        {"id": "F 9", "severity": "high"},  # id malformed
        {"id": "F-003", "severity": "apocalyptic"},
        {"id": "F-004", "severity": "high", "summary": 42},
        {"id": "F-005", "severity": "high",
         "evidence": {"nested": True}},
        {"id": "F-006", "severity": "Medium", "summary": "   "},
    ])
    composed = compose_report_mail(report, recipient="ops@lab.example")
    body = composed["body"]
    assert "findings: 1 composed, 6 skipped" in body
    assert "- [medium] F-006: (no summary)" in body
    assert ("- skipped finding <missing-id>: "
            "record must be a dict" in body)
    assert ("- skipped finding <missing-id>: finding id missing; "
            "severity must be one of critical|high|medium|low, "
            "got: 'weird'" in body)
    assert ("- skipped finding <missing-id>: "
            "finding id malformed: 'F 9'" in body)
    assert ("- skipped finding F-003: severity must be one of "
            "critical|high|medium|low, got: 'apocalyptic'" in body)
    assert ("- skipped finding F-004: summary must be a string, "
            "got: 42" in body)
    assert len([ln for ln in body.splitlines()
                if ln.startswith("- skipped")]) == 6


def test_compose_report_mail_title_stays_in_body():
    hostile = dict(REPORT, title="T\r\nBcc: victim@evil.example")
    composed = compose_report_mail(hostile, recipient="ops@lab.example")
    assert "Bcc" not in composed["subject"]
    lines = composed["body"].splitlines()
    assert lines[0:2] == ["T", "Bcc: victim@evil.example"]


def test_compose_report_mail_rejects_hostile_records():
    for bad in (None, "x", 42, [],
                {"target": "10.0.0.1", "findings": []},
                {"engagement_id": "E-1", "findings": []},
                {"engagement_id": "E-1", "target": "10.0.0.1"}):
        with pytest.raises(ValueError):
            compose_report_mail(bad, recipient="o@x.co")
    for eid in ("", "E 1", "E\r\n1", None, 42):
        with pytest.raises(ValueError):
            compose_report_mail(
                dict(REPORT, engagement_id=eid), recipient="o@x.co")
    for target in ("", "   ", "10.0.0.1; rm -rf /",
                   "10.0.0.1 && cat /etc/passwd", "t\nBcc: x@y.z",
                   "..", None, 42):
        with pytest.raises(ValueError):
            compose_report_mail(
                dict(REPORT, target=target), recipient="o@x.co")
    for findings in ("str", {}, None, 42):
        with pytest.raises(ValueError):
            compose_report_mail(
                dict(REPORT, findings=findings), recipient="o@x.co")
    for title in (42, [], True):
        with pytest.raises(ValueError):
            compose_report_mail(
                dict(REPORT, title=title), recipient="o@x.co")


def test_send_mode_guard_refuses_non_dry():
    for bad in ("smtp", "queue", "DRY", None, 1, False):
        with pytest.raises(ValueError) as exc_info:
            compose_report_mail(
                REPORT, recipient="o@x.co", send_mode=bad)
        assert "dry" in str(exc_info.value)
        with pytest.raises(ValueError):
            compose_battery_mail(RUN, recipient="o@x.co", send_mode=bad)


# --- the owner notification (battery completion) ----------------------------


def test_compose_battery_mail_full_shape():
    composed = compose_battery_mail(RUN, mailbox=PLAN_EXPECT)
    assert composed == COMPOSED_BATTERY_EXPECT
    _needles_absent(composed)


def test_compose_battery_mail_target_optional():
    base = {k: v for k, v in RUN.items() if k != "target"}
    for extra in (None, {"target": None}, {"target": "   "}):
        run = base if extra is None else dict(base, **extra)
        composed = compose_battery_mail(run, recipient="o@x.co")
        assert "target" not in composed["body"]
        assert composed["subject"].endswith("1 skipped")
        assert composed["body"].startswith(
            "battery BAT-01 complete\ncompleted: 7")


def test_compose_battery_mail_rejects_hostile():
    for bad in ("", "B 1", "b\r\nid", None, 42):
        with pytest.raises(ValueError):
            compose_battery_mail(
                dict(RUN, battery_id=bad), recipient="o@x.co")
    for required in ("completed", "failed"):
        run = {k: v for k, v in RUN.items() if k != required}
        run.pop("target", None)
        with pytest.raises(ValueError) as exc_info:
            compose_battery_mail(run, recipient="o@x.co")
        assert required in str(exc_info.value)
    for slot in ("completed", "failed", "skipped"):
        for bad in (-1, 1.5, "7", None, True):
            with pytest.raises(ValueError):
                compose_battery_mail(
                    dict(RUN, **{slot: bad}), recipient="o@x.co")
    for notes in (42, [], True):
        with pytest.raises(ValueError):
            compose_battery_mail(
                dict(RUN, notes=notes), recipient="o@x.co")


# --- the owner-gated send seam (contract stub) -------------------------------


def test_send_seam_is_owner_gated_stub():
    composed = compose_report_mail(REPORT, recipient="o@x.co")
    with pytest.raises(NotImplementedError) as exc_info:
        send_report_mail(composed)
    assert str(exc_info.value) == NOT_IMPLEMENTED_MSG
    # the transport parameter is reserved for the owner-gated wiring
    with pytest.raises(NotImplementedError):
        send_report_mail(composed, transport=object())
    with pytest.raises(NotImplementedError):
        send_report_mail(
            compose_battery_mail(RUN, recipient="o@x.co"))


def test_send_seam_refuses_wrong_shapes():
    for bad in (None, "txt", 42, [], {}):
        with pytest.raises(ValueError):
            send_report_mail(bad)
    for twist in ({"ok": False},
                  {"ok": True, "send_mode": "smtp"},
                  {"ok": True, "send_mode": "dry"}):
        with pytest.raises(ValueError):
            send_report_mail(twist)


# --- the scrub net ----------------------------------------------------------


def test_redact_scrub_net():
    payload = {"a": PW + " tail",
               "nested": ["x", (PW, 3)],
               "keep": 5,
               "n": None}
    cleaned = redact(payload, PW)
    assert cleaned == {"a": "<redacted> tail",
                       "nested": ["x", ["<redacted>", 3]],
                       "keep": 5,
                       "n": None}
    assert payload["a"] == PW + " tail"  # input untouched
    assert redact("x y", ["x", "y"]) == "<redacted> <redacted>"
    assert redact("ab", "b") == "a<redacted>"
    for bad in ("", None, 42, ["ok", ""], ["ok", None]):
        with pytest.raises(ValueError):
            redact("x", bad)
    for bad_payload in ({1, 2}, object()):
        with pytest.raises(TypeError):
            redact(bad_payload, "x")


def test_returned_surfaces_stay_secret_free():
    surfaces = (
        mailbox_plan(ENTRIES),
        compose_report_mail(REPORT, mailbox=ENTRIES,
                            recipient="o@x.co"),
        compose_report_mail(REPORT, recipient="o@x.co"),
        compose_battery_mail(
            {k: v for k, v in RUN.items() if k != "target"},
            recipient="o@x.co"),
        redact({"deep": {"a": [PW]}}, PW),
    )
    for surface in surfaces:
        _needles_absent(surface)


# --- input gates (shared, hostile-string sweep) ------------------------------


def test_input_gates_reject_hostile_strings():
    for bad in ("", "   ", "a; rm -rf /", "a|b", "a&b", "a`b",
                "a$(b)", "(x)", "<x>", 'a"b', "a\nb", "a\r\nb",
                "..", None, 42):
        with pytest.raises(ValueError):
            scrub_target(bad)
    assert scrub_target(" 10.0.0.1 ") == "10.0.0.1"
    for bad in ("", "   ", "a b@x.co", "onlylocal", "a@nodots",
                "a@x.co\r\nBcc: v@z.co", "@x.co", "a@", None, 42):
        with pytest.raises(ValueError):
            scrub_address(bad)
    assert scrub_address(
        " reports@bedimsecurity.com ") == "reports@bedimsecurity.com"


# --- planner purity ----------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.report_mail")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for token in ("subprocess", "popen", "os.system", "eval(", "exec(",
                  "socket", "ssl", "urllib", "requests", "http.client",
                  "smtplib", "imaplib", "poplib", "os.environ", "getenv",
                  "import os", "utcnow", "time.time", "today()",
                  "datetime", "from agentic_ai", "import agentic_ai"):
        assert token not in source, token
    # exactly ONE file-read seam: the caller-provided env-file path
    assert source.count("open(") == 1