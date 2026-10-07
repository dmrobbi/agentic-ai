"""Screenshot-capture planner tests (KA-086): the screenshot planner is
pure - offline job planning and manifest validation only. These tests
never launch a browser, never touch the network, and never run a thing1
recipe: the capture run is owner-gated elsewhere."""

import hashlib
import pathlib
import warnings

import pytest

from agentic_ai.agents.cyber import screenshot_capture as sc
from agentic_ai.agents.cyber.screenshot_capture import (
    MANIFEST_ROW_KEYS,
    MAX_CAPTURE_JOBS,
    SCREENSHOT_BASE_DIR,
    VIEWPORT_CHOICES,
    VIEWPORT_DEFAULT,
    ScreenshotCaptureMixin,
    is_sha256_hex,
    plan_captures,
    sc_scrub_path,
    sc_scrub_text,
    sc_scrub_url,
    validate_manifest,
)

_MODULE_SOURCE = pathlib.Path(sc.__file__).read_text()


def _finding(n=1, **overrides):
    row = {
        "id": "F-%03d" % n,
        "url": "https://h%02d.example.com/page/%d" % (n, n),
    }
    row.update(overrides)
    return row


def _batch(count, **overrides):
    return [_finding(i + 1, **overrides) for i in range(count)]


def _rows(jobs, with_digest=True):
    out = []
    for job in jobs:
        row = {"job_id": job["job_id"], "out_path": job["out_path"],
               "status": "ok"}
        if with_digest:
            row["sha256"] = hashlib.sha256(
                ("png-bytes:" + job["job_id"]).encode()).hexdigest()
        out.append(row)
    return out


# --- planning ----------------------------------------------------------------


def test_plan_captures_shape():
    jobs = plan_captures([
        {"finding_id": "F-A1", "id": "legacy-falls-back",
         "url": "https://a.example.com/login"},
        _finding(2),
    ])
    assert [j["job_id"] for j in jobs] == ["shot-0001", "shot-0002"]
    job = jobs[0]
    assert set(job) == {"job_id", "url", "viewport", "full_page",
                        "selector_hint", "out_path", "reason_ref",
                        "requires_owner"}
    assert job["reason_ref"] == "F-A1"  # finding_id wins over id
    assert job["url"] == "https://a.example.com/login"
    assert jobs[1]["reason_ref"] == "F-002"
    assert job["viewport"] == VIEWPORT_DEFAULT == "1280x720"
    assert job["full_page"] is True
    assert job["selector_hint"] is None
    assert isinstance(job["requires_owner"], bool)


def test_plan_sequential_ids_and_out_paths():
    jobs = plan_captures(_batch(3))
    assert [j["job_id"] for j in jobs] == ["shot-0001", "shot-0002",
                                           "shot-0003"]
    assert [j["reason_ref"] for j in jobs] == ["F-001", "F-002", "F-003"]
    for job in jobs:
        assert job["out_path"] == "evidence/screens/%s.png" % job["job_id"]
        assert job["requires_owner"] is True
    assert len({j["url"] for j in jobs}) == 3


def test_plan_base_dirs():
    default = plan_captures([_finding()])
    assert default[0]["out_path"] == "evidence/screens/shot-0001.png"
    custom = plan_captures([_finding()], "engagements/2026/web/screens")
    assert custom[0]["out_path"] == \
        "engagements/2026/web/screens/shot-0001.png"
    normalized = plan_captures([_finding()], "evidence/screens/")
    assert normalized == default  # trailing slash scrubs to the same base


@pytest.mark.parametrize("base", [
    "../evidence",
    "/abs/screens",
    "screens\\traversal",
])
def test_plan_base_dir_escapes_rejected(base):
    with pytest.raises(ValueError):
        plan_captures([_finding()], base)


def test_plan_full_page_flags():
    assert plan_captures([_finding()])[0]["full_page"] is True
    explicit = plan_captures([_finding(full_page=False)])[0]
    assert explicit["full_page"] is False
    garbage = plan_captures([_finding(full_page=("yes",))])[0]
    assert garbage["full_page"] is True  # non-bool falls back to the default


def test_plan_selector_hints():
    plain = plan_captures([_finding()])[0]
    assert plain["selector_hint"] is None
    focused = plan_captures([_finding(selector="#login-form")])[0]
    assert focused["selector_hint"] == "#login-form"
    via_hint = plan_captures([_finding(selector_hint="img[alt=proof]")])[0]
    assert via_hint["selector_hint"] == "img[alt=proof]"
    blank = plan_captures([_finding(selector="   ")])[0]
    assert blank["selector_hint"] is None


def test_plan_skips_unusable_findings_without_raising():
    jobs = plan_captures([
        _finding(1, url="ftp://not-http"),
        None,
        _finding(2),
        {"url": "https://noid.example.com/x"},   # no usable finding id
        _finding(3, id=None),
        _finding(4, url=""),                     # blank url
        _finding(5, selector="div; drop table"),  # hostile selector
    ])
    assert [j["reason_ref"] for j in jobs] == ["F-002"]


def test_plan_viewports():
    assert plan_captures([_finding()])[0]["viewport"] == \
        VIEWPORT_DEFAULT == "1280x720"
    key = plan_captures([_finding(viewport="mobile")])[0]
    assert key["viewport"] == "390x844"
    canonical = plan_captures([_finding(viewport="1440x900")])[0]
    assert canonical["viewport"] == "1440x900"
    unknown = plan_captures([_finding(viewport="8k")])[0]
    assert unknown["viewport"] == VIEWPORT_DEFAULT
    non_str = plan_captures([_finding(viewport={"w": 1280, "h": 720})])[0]
    assert non_str["viewport"] == VIEWPORT_DEFAULT


@pytest.mark.parametrize("evil", [
    "example.com/path",
    "ftp://host/page",
    "https://host/page;x=1",
    "https://host/../../etc/pass",
    "https://host/page?q=a b",
])
def test_scrub_url_rejects_hostile(evil):
    with pytest.raises(ValueError):
        sc_scrub_url(evil)


def test_scrub_url_normalization():
    assert sc_scrub_url("HTTPS://Host.Example.COM/page#section") == \
        "https://Host.Example.COM/page"
    assert sc_scrub_url("https://host/path") == "https://host/path"
    with pytest.raises(ValueError):
        sc_scrub_url("https://")  # scheme without a host carries nothing


def test_scrub_text_rejects_hostile_and_blanks():
    with pytest.raises(ValueError):
        sc_scrub_text(None)
    with pytest.raises(ValueError):
        sc_scrub_text("a;b")
    with pytest.raises(ValueError):
        sc_scrub_text("  ")
    assert sc_scrub_text(" F-001 ") == "F-001"


@pytest.mark.parametrize("bad", [
    "/abs",
    "../up",
    "bad\\path",
])
def test_scrub_path_rejects_escapes(bad):
    with pytest.raises(ValueError):
        sc_scrub_path(bad)


def test_plan_cap_and_overflow():
    findings = _batch(30)
    with pytest.warns(UserWarning) as caught:
        jobs = plan_captures(findings)
    assert len(jobs) == MAX_CAPTURE_JOBS == 25
    assert len(caught) == 1
    assert [j["url"] for j in jobs] == [f["url"] for f in findings[:25]]
    assert jobs[-1]["job_id"] == "shot-0025"
    # exactly at cap: the job batch plans whole, no overflow notice
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert len(plan_captures(_batch(25))) == 25
        # usable-count overflow only: unusable rows never inflate the count
        mixed = _batch(25) + [{"id": "F-x1"}, {"id": "F-x2", "url": None}]
        assert len(plan_captures(mixed)) == 25
    assert plan_captures(None) == []
    assert plan_captures([]) == []


def test_public_constants_pinned():
    assert SCREENSHOT_BASE_DIR == "evidence/screens"
    assert MAX_CAPTURE_JOBS == 25
    assert MANIFEST_ROW_KEYS == ("job_id", "out_path", "status")
    assert VIEWPORT_CHOICES == {"desktop": "1280x720",
                                "laptop": "1440x900",
                                "mobile": "390x844"}


# --- manifest validation ------------------------------------------------------


def test_validate_ok_roundtrip():
    jobs = plan_captures(_batch(3))
    ok, reason = validate_manifest(_rows(jobs), jobs)
    assert ok is True and "ok" in reason and "evidence/screens" in reason
    assert validate_manifest(_rows(jobs, with_digest=False), jobs)[0] is True


def test_validate_missing_coverage_names_first_missing():
    jobs = plan_captures(_batch(3))
    ok, reason = validate_manifest(_rows(jobs)[1:], jobs)
    assert ok is False
    assert "shot-0001" in reason


def test_validate_excess_rows_rejected():
    jobs = plan_captures(_batch(2))
    rows = _rows(jobs)
    ok, reason = validate_manifest(
        [dict(rows[0], job_id="shot-9999")], jobs)
    assert ok is False and "unknown" in reason
    ok, reason = validate_manifest(rows + [rows[0]], jobs)
    assert ok is False and "repeats" in reason


@pytest.mark.parametrize("missing_key", list(MANIFEST_ROW_KEYS))
def test_validate_row_missing_required_key(missing_key):
    jobs = plan_captures([_finding()])
    row = _rows(jobs)[0]
    row.pop(missing_key)
    ok, reason = validate_manifest([row], jobs)
    assert ok is False and missing_key in reason


def test_validate_row_out_path_rewrite_rejected():
    jobs = plan_captures(_batch(2))
    rows = _rows(jobs)
    rows[1]["out_path"] = "evidence/screens/shot-0099.png"
    ok, reason = validate_manifest(rows, jobs)
    assert ok is False and "out_path" in reason


def test_validate_garbage_inputs_rejected():
    jobs = plan_captures([_finding()])
    rows = _rows(jobs)
    assert validate_manifest({}, jobs)[0] is False     # manifest not a list
    assert validate_manifest(rows, "nope")[0] is False  # jobs not a list
    assert validate_manifest([42], jobs)[0] is False    # row not a dict
    assert validate_manifest(None, [42])[0] is False    # job not a dict


def test_validate_empty_contracts_pass():
    for manifest, planned in ((None, None), ([], []), (None, [])):
        ok, reason = validate_manifest(manifest, planned)
        assert ok is True and reason


def test_validate_planned_escape_rejected():
    for bad_out in ("/etc/evil.png", "../evil.png",
                    "evidence/screens/../evil.png"):
        planned = [{"job_id": "shot-0001", "out_path": bad_out}]
        rows = [{"job_id": "shot-0001", "out_path": bad_out, "status": "ok"}]
        ok, reason = validate_manifest(rows, planned)
        assert ok is False and "escape" in reason, (bad_out, reason)


def test_validate_explicit_base_checks():
    planned = [{"job_id": "shot-0001", "out_path": "other/shot-0001.png"}]
    rows = [{"job_id": "shot-0001", "out_path": "other/shot-0001.png",
             "status": "ok"}]
    ok, reason = validate_manifest(rows, planned,
                                   base_out_dir="evidence/screens")
    assert ok is False and "escapes the base dir" in reason
    ok, reason = validate_manifest(rows, planned, base_out_dir="../evil")
    assert ok is False and "rejected" in reason


def test_validate_base_derivation():
    jobs = plan_captures(_batch(2))
    ok, reason = validate_manifest(_rows(jobs), jobs)
    assert ok is True and "evidence/screens" in reason
    single = plan_captures([_finding()])
    assert validate_manifest(_rows(single), single)[0] is True
    siblings = [{"job_id": "shot-0001",
                 "out_path": "screens-a/shot-0001.png"},
                {"job_id": "shot-0002",
                 "out_path": "screens-b/shot-0002.png"}]
    rows = [{"job_id": j["job_id"], "out_path": j["out_path"], "status": "ok"}
            for j in siblings]
    ok, reason = validate_manifest(rows, siblings)
    assert ok is False and "common" in reason


@pytest.mark.parametrize("bad", ["", 42])
def test_validate_sha256_malformed_rejected(bad):
    jobs = plan_captures([_finding()])
    row = dict(_rows(jobs)[0], sha256=bad)
    ok, reason = validate_manifest([row], jobs)
    assert ok is False and "sha256" in reason


def test_validate_sha256_digest_forms():
    png = b"\x89PNG\r\n\x1a\n"
    digest = hashlib.sha256(png).hexdigest()
    jobs = plan_captures([_finding()])
    ok, _ = validate_manifest([dict(_rows(jobs)[0], sha256=digest)], jobs)
    assert ok is True
    ok, _ = validate_manifest(
        [dict(_rows(jobs)[0], sha256=digest.upper())], jobs)
    assert ok is True
    assert is_sha256_hex(hashlib.sha256(b"x").hexdigest())
    assert is_sha256_hex("A" * 64)
    assert not is_sha256_hex("g" * 64)   # off-charset
    assert not is_sha256_hex("a" * 63)   # off-length


# --- mixin + house pins --------------------------------------------------------


def test_mixin_delegates_to_module_planner():
    mixin = ScreenshotCaptureMixin()
    findings = _batch(3)
    assert mixin.plan_captures(findings) == plan_captures(findings)
    assert mixin.plan_captures(findings, "alt/screens") == \
        plan_captures(findings, "alt/screens")
    jobs = plan_captures(findings)
    assert mixin.validate_manifest(_rows(jobs), jobs) == \
        validate_manifest(_rows(jobs), jobs)
    assert mixin._sc_scrub_text(" A ") == "A"
    assert mixin._sc_scrub_url("https://host/p") == \
        sc_scrub_url("https://host/p")
    assert mixin._sc_scrub_path("a/b") == "a/b"
    assert mixin._sc_is_sha256(hashlib.sha256(b"y").hexdigest())


def test_module_docs_pin_the_execution_boundary():
    module_doc = sc.__doc__ or ""
    class_doc = ScreenshotCaptureMixin.__doc__ or ""
    assert "owner-gated" in class_doc  # the runner boundary, in writing
    assert "playwright screenshot" in module_doc
    assert "viewport-size" in module_doc
    assert "1280" in module_doc
    assert "Mozilla/" in module_doc
    assert "requires_owner" in module_doc


def test_planner_purity_source_scan():
    code = _MODULE_SOURCE
    for banned in ("subprocess", "os.system", "eval(", "exec(", "popen",
                   "socket", "urllib", "import requests", "http.client",
                   "import playwright", "from playwright", "webbrowser",
                   "import os"):
        assert banned not in code, banned
    assert "hashlib" in code      # digest checks via hashlib, no process
    assert "posixpath" in code    # path joins/derivation, no os import