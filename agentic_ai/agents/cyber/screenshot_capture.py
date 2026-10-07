"""Screenshot-capture planning (KA-086) - headless-browser evidence for web
findings.

A pure planner module: it turns web findings into capture-job dicts and
validates the runner's return manifest. It NEVER launches a browser or
child process and imports NO playwright - the actual screen capture is
to be run later by an owner-gated runner that the
integration wires (see the class docstring for the boundary). No chassis
import, no network facilities, no wall-clock reads.

THE PLAYWRIGHT-ON-THING1 RECIPE (DOCUMENTATION ONLY - nothing in this
module executes it):

  thing1's kali_agent_v4/venv carries the playwright CLI; the runner
  lives on that host and is owner-gated. One capture is one call:

    playwright screenshot --browser=chromium \
      --viewport-size="1280,720" \
      --full-page \
      --wait-for-timeout=3 \
      --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
      https://<target-url>/path \
      evidence/screens/shot-0001.png

  Viewport sizes in fleet use (VIEWPORT_CHOICES): desktop 1280x720,
  laptop 1440x900, mobile 390x844. --full-page takes the whole page;
  leave it off (empty selector_hint does not imply -full-page is
  always wanted) and point a selector hint at the element whose
  rendering IS the evidence (login prompt, injected marker, error
  page). Manifest rows are written by the runner with a sha256 of the
  PNG bytes (hashlib on the runner side) so validate_manifest can pin
  evidence integrity with no process spawning.

JOB SHAPE (the planner's output contract, exact keys):
  job_id          "shot-0001"-style planning-local id,
  url             the scrubbed capture target (http/https only),
  viewport        "1280x720"-style size string,
  full_page       True -> whole-page shot, False -> viewport shot,
  selector_hint   CSS selector to focus (or None for a plain page shot),
  out_path        "<base>/<job_id>.png", always inside the base dir,
  reason_ref      the finding id this job evidences,
  requires_owner  always True - nothing is captured without the owner
                  gate approving the runner run.

MANIFEST SHAPE (the runner's return contract, exact required keys):
  row: job_id, out_path, status; optional sha256 hex digest.
  validate_manifest checks coverage (every job exactly once, no unknown
  or duplicate rows), row completeness, row out_path == the planned
  out_path, relative containment inside the base dir (or the explicit
  base_out_dir argument), and well-formed sha256 digests where given,
  returning the house (bool, reason) tuple.

Scrub discipline: every external string (finding ids, urls, selector
hints, base dirs) passes a module-level scrub helper before use;
findings that fail scrubbing are skipped - one hostile row must not
cost the rest of the evidence batch. Job count is capped at
MAX_CAPTURE_JOBS (25) with a warnings.warn on overflow.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple

# Default evidence base dir (posix-relative, runner resolved on thing1).
SCREENSHOT_BASE_DIR = "evidence/screens"

# House result cap: 25 jobs per planning pass, warnings on overflow.
MAX_CAPTURE_JOBS = 25

# Viewport sizes in fleet use: canonical size string per role key.
VIEWPORT_CHOICES = {"desktop": "1280x720", "laptop": "1440x900",
                    "mobile": "390x844"}
VIEWPORT_DEFAULT = VIEWPORT_CHOICES["desktop"]

# Job id prefix: planned jobs are "shot-0001".. style.
JOB_ID_PREFIX = "shot"

# Required manifest row keys; sha256 is optional per row.
MANIFEST_ROW_KEYS = ("job_id", "out_path", "status")

# External-string length caps (url may carry a deep path).
SCRUB_LIMIT = 128
URL_LIMIT = 2048

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
# House metachar set (mirror of wp_scrub_target): nothing that reads as
# shell punctuation may survive scrubbing into jobs or manifest rows.
_META_RE = re.compile(r"[;|&`\$()\n\r<>\"']")
_SHA256_RE = re.compile(r"^[0-9a-f]+$")


def _sha256_length() -> int:
    """The canonical sha256 hex digest length, via hashlib (no process)."""
    return len(hashlib.sha256(b"").hexdigest())


def is_sha256_hex(value: Any) -> bool:
    """Return True when value is a well-formed sha256 hex digest string
    (case-insensitive; runner rows carry hashlib-style lowercase)."""
    if not isinstance(value, str):
        return False
    return (len(value) == _sha256_length()
            and bool(_SHA256_RE.match(value.lower())))


def sc_scrub_text(value: Any, max_size: int = SCRUB_LIMIT) -> str:
    """Scrub a free-text finding field (id / selector): reject control
    characters, whitespace, house metacharacters, and ".."; cap length.
    Non-string input raises ValueError."""
    if not isinstance(value, str):
        raise ValueError("field must be a string: %r" % (value,))
    if _CTRL_RE.search(value) or _META_RE.search(value) or ".." in value:
        raise ValueError("rejected hostile characters in field: %r"
                         % (value[:64],))
    text = value.strip()
    if not text:
        raise ValueError("field must be a non-empty string")
    if len(text) > max_size:
        raise ValueError("field exceeds the %d-character limit" % max_size)
    return text


def sc_scrub_url(value: Any) -> str:
    """Scrub a capture URL: house rejection set, then a required
    http/https scheme with a non-empty host. Returns the stripped url
    with any fragment removed (fragments are client-side scrolls,
    never evidence-worthy)."""
    text = sc_scrub_text(value, max_size=URL_LIMIT)
    if re.search(r"\s", text):
        raise ValueError("capture url must not contain whitespace: %r "
                         % (value[:64],))
    if not _SCHEME_RE.match(text):
        raise ValueError("capture url must be http(s): %r "
                         % (value[:64],))
    scheme, _, rest = text.partition("://")
    rest, _, _fragment = rest.partition("#")
    if not rest.split(posixpath.sep, 1)[0]:
        raise ValueError("capture url must include a host: %r "
                         % (value[:64],))
    if ".." in rest.split(posixpath.sep):
        raise ValueError("capture url contains a path traversal segment")
    return scheme.lower() + "://" + rest


def sc_scrub_path(value: Any) -> str:
    """Scrub a filesystem path fragment (base dirs, job out_paths):
    must be a posix-RELATIVE, non-escaped path - no leading slash, no
    backslash, no whitespace, no ".." segments, house metachar set
    rejected. Returns the normalized path."""
    if not isinstance(value, str):
        raise ValueError("path must be a string: %r" % (value,))
    if _CTRL_RE.search(value) or _META_RE.search(value) or "\\" in value:
        raise ValueError("rejected hostile characters in path: %r"
                         % (value[:64],))
    text = value.strip()
    if not text:
        raise ValueError("path must be a non-empty string")
    if re.search(r"\s", text):
        raise ValueError("path must not contain whitespace: %r"
                         % (value[:64],))
    if ".." in text.split(posixpath.sep):
        raise ValueError("path may not traverse up: %r" % (value[:64],))
    if text.startswith("/"):
        raise ValueError("path must be relative, not absolute: %r"
                         % (value[:64],))
    if len(text) > 400:
        raise ValueError("path exceeds the 400-character limit")
    norm = posixpath.normpath(text)
    if norm == ".":
        raise ValueError("path must name a directory or file")
    if posixpath.isabs(norm):
        raise ValueError("path must be relative, not absolute: %r"
                         % (value[:64],))
    return norm


def sc_norm_viewport(value: Any) -> str:
    """Normalize a viewport to a fleet size string (accepts a role key
    like 'mobile' or a canonical size like '1280x720'); unknown values
    fall back to the default rather than crashing a batch."""
    if isinstance(value, str):
        text = value.strip().lower()
        if text in (VIEWPORT_CHOICES.keys() | VIEWPORT_CHOICES.values()):
            return VIEWPORT_CHOICES.get(text, text)
    return VIEWPORT_DEFAULT


def _inside_base(out_path: str, base: str) -> bool:
    """True when out_path is relative, carries no ".." segment (checked
    raw, before normalization), and sits strictly inside base."""
    if (posixpath.isabs(out_path)
            or ".." in out_path.split(posixpath.sep)):
        return False
    norm = posixpath.normpath(out_path)
    return norm.startswith(base.rstrip("/") + "/")


def _derive_base(jobs: List[Dict[str, Any]]) -> Optional[str]:
    """Derive the common evidence base dir from the planned jobs'
    out_paths (planners emit <base>/<job_id>.png); None when the paths
    carry a traversal segment or share no common relative base."""
    out_paths = []
    for job in jobs:
        out_path = job.get("out_path")
        if (not isinstance(out_path, str) or not out_path.strip()
                or posixpath.isabs(out_path)
                or ".." in out_path.split(posixpath.sep)):
            return None
        out_paths.append(posixpath.normpath(out_path))
    if not out_paths:
        return None
    if len(out_paths) == 1:
        return posixpath.dirname(out_paths[0])
    base = posixpath.commonpath(out_paths)
    if base in (".", ""):
        return None
    return base


def plan_captures(findings: Optional[List[Dict[str, Any]]],
                  base_out_dir: str = SCREENSHOT_BASE_DIR,
                  ) -> List[Dict[str, Any]]:
    """Plan capture jobs from web findings: one job per usable finding.

    findings: an optional list of dicts; a finding may carry:
      id / finding_id   id string (required; becomes reason_ref),
      url               http(s) capture target (required),
      viewport          role key ('desktop'...) or 'WxH' size,
      full_page         True (default) -> whole-page shot,
      selector          or selector_hint  -> CSS selector to focus.
    Findings that are not dicts, or that lack a usable id or url, or
    whose strings fail scrubbing, are SKIPPED - one hostile row must
    not cost the rest of the evidence batch. Jobs are numbered
    sequentially (shot-0001...) in input order and capped at
    MAX_CAPTURE_JOBS with a warnings.warn overflow notice.
    """
    base = sc_scrub_path(base_out_dir)
    prepared: List[Tuple[str, str, Optional[str], Any, Any]] = []
    for finding in (findings or []):
        if not isinstance(finding, dict):
            continue
        raw_id = finding.get("finding_id") or finding.get("id")
        raw_url = finding.get("url")
        if not raw_url:
            continue
        try:
            reason_ref = sc_scrub_text(raw_id) if raw_id else ""
            url = sc_scrub_url(raw_url)
            raw_selector = (finding.get("selector")
                            or finding.get("selector_hint"))
            selector = (sc_scrub_text(raw_selector)
                        if isinstance(raw_selector, str)
                        and raw_selector.strip() else None)
        except ValueError:
            continue
        if not reason_ref:
            continue
        prepared.append((reason_ref, url, selector, finding.get("full_page"),
                 finding.get("viewport")))

    overflow = len(prepared) - MAX_CAPTURE_JOBS
    if overflow > 0:
        warnings.warn(
            "screenshot plan capped at %d jobs: %d usable finding(s) in, "
            "%d cut from this pass - re-run planning for the overflow"
            % (MAX_CAPTURE_JOBS, len(prepared), overflow),
            stacklevel=2,
        )
        prepared = prepared[:MAX_CAPTURE_JOBS]

    jobs: List[Dict[str, Any]] = []
    for index, (reason_ref, url, selector, full_page, viewport) in enumerate(
            prepared, start=1):
        job_id = f"{JOB_ID_PREFIX}-{index:04d}"
        jobs.append({
            "job_id": job_id,
            "url": url,
            "viewport": sc_norm_viewport(viewport),
            "full_page": full_page if isinstance(full_page, bool) else True,
            "selector_hint": selector,
            "out_path": posixpath.join(base, job_id + ".png"),
            "reason_ref": reason_ref,
            "requires_owner": True,
        })
    return jobs


def validate_manifest(manifest: Any, jobs: Any,
                      base_out_dir: Optional[str] = None,
                      ) -> Tuple[bool, str]:
    """Validate a runner manifest against its planned capture jobs.

    Returns the house (ok, reason) tuple; reason names the first
    contract miss (coverage, row completeness, out_path match, base-dir
    containment, or sha256 well-formedness). sha256 is optional per
    row; when present it must be a well-formed hex digest (hashlib
    shape, checked here - no process spawning).
    """
    if manifest is None:
        manifest = []
    if jobs is None:
        jobs = []
    if not isinstance(jobs, list):
        return (False, "planned jobs must be a list of job dicts")
    if not isinstance(manifest, list):
        return (False, "manifest must be a list of row dicts")

    planned: Dict[str, Dict[str, Any]] = {}
    for job in jobs:
        if not isinstance(job, dict):
            return (False, "planned jobs must be a list of job dicts")
        job_id = job.get("job_id")
        if not isinstance(job_id, str) or not job_id.strip():
            return (False, "planned job lacks a usable job_id")
        if job_id in planned:
            return (False, "planned list repeats job_id %s" % job_id)
        job_out = job.get("out_path")
        if not isinstance(job_out, str) or not job_out.strip():
            return (False, "planned job %s lacks a usable out_path" % job_id)
        if posixpath.isabs(job_out) or ".." in job_out.split(posixpath.sep):
            return (False, "planned out_path for %s escapes the "
                           "evidence base dir: %r" % (job_id, job_out[:80]))
        planned[job_id] = job

    if not planned and not manifest:
        return (True, "nothing to validate: no planned jobs and no rows")

    covered: Dict[str, None] = {}
    for row in manifest:
        if not isinstance(row, dict):
            return (False, "manifest rows must be dicts")
        for key in MANIFEST_ROW_KEYS:
            value = row.get(key)
            if not isinstance(value, str) or not value.strip():
                return (False, "manifest row missing required key %r" % (key,))
        job_id = row["job_id"]
        if job_id not in planned:
            return (False, "manifest row references unknown job_id %s"
                           % job_id)
        if job_id in covered:
            return (False, "manifest repeats job_id %s" % job_id)
        job = planned[job_id]
        if row["out_path"] != job.get("out_path"):
            return (False, "manifest row for %s rewrites the planned "
                           "out_path: %r (planned %r)"
                           % (job_id, row["out_path"], job.get("out_path")))
        digest = row.get("sha256")
        if digest is not None and not is_sha256_hex(digest):
            return (False, "manifest row for %s carries a malformed "
                           "sha256 digest" % job_id)
        covered[job_id] = None

    missing = [job_id for job_id in planned if job_id not in covered]
    if missing:
        return (False, "%d planned job(s) lack manifest rows, first "
                       "missing: %s" % (len(missing), missing[0]))

    if base_out_dir is not None:
        try:
            base = sc_scrub_path(base_out_dir)
        except ValueError as exc:
            return (False, "base_out_dir rejected: %s" % exc)
    else:
        base = _derive_base(list(planned.values()))
        if base is None:
            return (False, "planned out_paths do not sit under a common "
                           "relative base dir")
    for job in planned.values():
        if not _inside_base(job["out_path"], base):
            return (False, "planned out_path for %s escapes the base dir "
                           "%r: %r" % (job["job_id"], base,
                                       job["out_path"][:80]))
    return (True, "ok: %d manifest row(s) cover %d planned job(s) under "
                  "base %r" % (len(manifest), len(planned), base))


class ScreenshotCaptureMixin:
    """Planning-only mixin: build screenshot capture jobs from web
    findings and validate the runner's return manifest.

    Execution boundary: planning ONLY. Nothing here launches a browser
    or spawns a process; the actual playwright run happens exclusively
    via an owner-gated capture runner that the integration wires later -
    the mixin's job dicts carry requires_owner=True so nothing can be
    captured without that gate approving the runner first.
    """

    @staticmethod
    def _sc_scrub_text(value: Any, max_size: int = SCRUB_LIMIT) -> str:
        """Thin wrapper over the module-level text scrub helper."""
        return sc_scrub_text(value, max_size)

    @staticmethod
    def _sc_scrub_url(value: Any) -> str:
        """Thin wrapper over the module-level url scrub helper."""
        return sc_scrub_url(value)

    @staticmethod
    def _sc_scrub_path(value: Any) -> str:
        """Thin wrapper over the module-level path scrub helper."""
        return sc_scrub_path(value)

    @staticmethod
    def _sc_is_sha256(value: Any) -> bool:
        """Thin wrapper over the module-level sha256 shape check."""
        return is_sha256_hex(value)

    def plan_captures(self, findings: Optional[List[Dict[str, Any]]] = None,
                      base_out_dir: str = SCREENSHOT_BASE_DIR,
                      ) -> List[Dict[str, Any]]:
        """Plan screenshot capture jobs; see the module-level
        plan_captures for the accepted finding keys and job contract."""
        return plan_captures(findings, base_out_dir)

    def validate_manifest(self, manifest: Any, jobs: Any,
                          base_out_dir: Optional[str] = None,
                          ) -> Tuple[bool, str]:
        """Validate a capture manifest; see the module-level
        validate_manifest for the house (bool, reason) tuple contract."""
        return validate_manifest(manifest, jobs, base_out_dir)