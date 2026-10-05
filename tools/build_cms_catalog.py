#!/usr/bin/env python3
"""Build data/cms_flows.json - KA-049 per-CMS methodology catalogs.

WordPress/Drupal/Joomla/typo3 assessment FLOWS for the kali agents,
beyond the chassis's existing wpscan/wpscan-audit entry points: stage arcs
(enumeration -> extension audit -> version trail -> hardening/assessment)
with in-house re-authored methodology rows pointing at each project's own
official documentation (preferred over third-party writeups). Rows carry
NAMES + OFFICIAL DOC LINKS + RE-AUTHORED PURPOSES only - no payloads, no
exploit code, no evasion snippets (policy is in the data's meta and is
enforced by tests/test_cms_flows.py).

Build-time URL discipline (mirrors tools/build_xss_catalog.py): every
committed row was verified live (HTTP 200) on 2026-10-05 with a bounded,
polite sequential check (the --live mode below; 429/Retry-After honored
once, then the candidate is dropped). Candidates that failed that check
were DROPPED and replaced, and are not in the catalog:
  - docs.joomla.org/            (HTTP 403 to non-browser clients)
  - docs.joomla.org/Security_Checklist (HTTP 403 to non-browser clients)
  - docs.typo3.org/.../ApiOverview/CliScenarios/Index.html (HTTP 404)
Replacements that passed the same check: manual.joomla.org/,
developer.joomla.org/security-centre.html, and the TYPO3
ExtensionArchitecture / ApiOverview Index pages. Dead-link notes live in
this docstring, never in the data - the data must carry no dead-link
markers.

Default run is OFFLINE and deterministic: it re-serializes the curated
rows below canonically (the data evolves by editing the CATALOG literal,
never by hand-editing the JSON). --live is opt-in verification only
(never in CI; unit tests stay offline).
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "cms_flows.json"

SOURCE = ("re-authored in-house from each project's official "
          "documentation (wordpress.org, drupal.org, joomla.org, "
          "typo3.org); stage-arc structure follows the kali web-pentest "
          "cms phase conventions; goes beyond the chassis's "
          "wpscan/wpscan-audit op pair")
POLICY = ("methodology stage arcs + names + official doc links + "
          "re-authored purposes only; no payloads, exploit code, or "
          "evasion snippets; every link verified live at build time")
URLS_VERIFIED = "2026-10-05"

ARCS = ["enumeration", "extension-audit", "version-trail",
        "hardening-assessment"]

# Curated flow rows per CMS. "stage" is always one of ARCS; rows within a
# stage stay in curated (consultation) order. Every URL below returned
# HTTP 200 to the bounded polite check on 2026-10-05 (see --live).
CATALOG = {
    "wordpress": {
        "flows": [
            {"stage": "enumeration",
             "name": "WP-CLI command reference",
             "url": "https://developer.wordpress.org/cli/commands/",
             "purpose": "shell command reference (core/user/plugin/theme "
                        "commands) drafted as the fastest read-only "
                        "state inventory when CLI access is in scope"},
            {"stage": "enumeration",
             "name": "WordPress REST API reference",
             "url": "https://developer.wordpress.org/rest-api/",
             "purpose": "public route/parameter surface notes for mapping "
                        "what an unauthenticated or low-privilege session "
                        "can read before touching the admin UI"},
            {"stage": "extension-audit",
             "name": "WordPress Plugin Developer Handbook",
             "url": "https://developer.wordpress.org/plugins/",
             "purpose": "authoritative plugin architecture and hook docs "
                        "for mapping what each installed plugin touches: "
                        "capabilities, storage, and update channels"},
            {"stage": "extension-audit",
             "name": "WordPress Theme Developer Handbook",
             "url": "https://developer.wordpress.org/themes/",
             "purpose": "theme structure and template-loading docs for "
                        "auditing child themes, orphaned templates, and "
                        "who can modify theme files"},
            {"stage": "version-trail",
             "name": "WordPress release archive",
             "url": "https://wordpress.org/download/releases/",
             "purpose": "release listing for placing the installed core "
                        "version inside its maintenance window before "
                        "pairing findings with advisories"},
            {"stage": "hardening-assessment",
             "name": "Hardening WordPress",
             "url": "https://wordpress.org/documentation/article/hardening-wordpress/",
             "purpose": "official hardening doc for the assessment pass: "
                        "file permissions, secret keys, write restrictions, "
                        "and TLS posture recommendations"},
            {"stage": "hardening-assessment",
             "name": "Roles and capabilities overview",
             "url": "https://wordpress.org/documentation/article/roles-and-capabilities/",
             "purpose": "role/capability matrix for privilege-model review "
                        "and for stating least-privilege findings against "
                        "the real user population"},
        ],
    },
    "drupal": {
        "flows": [
            {"stage": "enumeration",
             "name": "Drupal user guide",
             "url": "https://www.drupal.org/docs/user_guide/en",
             "purpose": "site-builder walkthrough used to plan enumeration "
                        "of accounts, content types, roles, and "
                        "administrative entry points on a found site"},
            {"stage": "enumeration",
             "name": "Administering a Drupal site",
             "url": "https://www.drupal.org/docs/administering-a-drupal-site",
             "purpose": "administrative surface map (modules, "
                        "configuration, reports, update status) for "
                        "sequencing a structured site review"},
            {"stage": "extension-audit",
             "name": "Extending Drupal (modules and themes)",
             "url": "https://www.drupal.org/docs/extending-drupal",
             "purpose": "module and theme integration docs for auditing "
                        "installed extensions, their update channels, and "
                        "their advisory exposure"},
            {"stage": "version-trail",
             "name": "Drupal core project and releases",
             "url": "https://www.drupal.org/project/drupal",
             "purpose": "core release listing for mapping the audited "
                        "version to its maintenance and advisory timeline"},
            {"stage": "version-trail",
             "name": "Drush commands",
             "url": "https://www.drush.org/latest/",
             "purpose": "Drush CLI reference for reading module lists, "
                        "update state, and configuration from the shell "
                        "when CLI access is in scope"},
            {"stage": "hardening-assessment",
             "name": "Drupal security advisories",
             "url": "https://www.drupal.org/security",
             "purpose": "official advisory hub used to pair version-trail "
                        "findings with current advisories and to source "
                        "hardening recommendations"},
        ],
    },
    "joomla": {
        "flows": [
            {"stage": "enumeration",
             "name": "Joomla user manual",
             "url": "https://manual.joomla.org/",
             "purpose": "current official manual (menus, users, "
                        "extensions, global configuration) for planning "
                        "interface-level enumeration"},
            {"stage": "extension-audit",
             "name": "Joomla Extensions Directory",
             "url": "https://extensions.joomla.org/",
             "purpose": "extension registry for matching installed "
                        "components and modules against active, archived, "
                        "and abandoned projects"},
            {"stage": "version-trail",
             "name": "Joomla downloads archive",
             "url": "https://downloads.joomla.org/",
             "purpose": "release archive for placing the audited version "
                        "inside its support and advisory window"},
            {"stage": "version-trail",
             "name": "Joomla release announcements",
             "url": "https://www.joomla.org/announcements.html",
             "purpose": "official release announcements corroborating the "
                        "version trail before pairing findings"},
            {"stage": "hardening-assessment",
             "name": "Joomla Security Centre",
             "url": "https://developer.joomla.org/security-centre.html",
             "purpose": "advisory centre mapping known component and core "
                        "version issues into the audit's hardening "
                        "recommendations"},
        ],
    },
    "typo3": {
        "flows": [
            {"stage": "enumeration",
             "name": "TYPO3 documentation hub",
             "url": "https://docs.typo3.org/",
             "purpose": "official documentation entry point for backend "
                        "users, installation state, and the system "
                        "extension map of an audited instance"},
            {"stage": "extension-audit",
             "name": "TYPO3 Extension Repository (TER)",
             "url": "https://extensions.typo3.org/",
             "purpose": "registry for auditing installed extension keys "
                        "against maintained, archived, and abandoned "
                        "status in the public TER"},
            {"stage": "extension-audit",
             "name": "TYPO3 Core API: Extension Architecture",
             "url": "https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ExtensionArchitecture/Index.html",
             "purpose": "extension lifecycle and composer-mode docs for "
                        "judging where third-party code hooks into the "
                        "audited installation"},
            {"stage": "version-trail",
             "name": "TYPO3 release roadmap",
             "url": "https://get.typo3.org/",
             "purpose": "support matrix for placing the audited core "
                        "version in its LTS/ELTS window"},
            {"stage": "version-trail",
             "name": "TYPO3 version 13 matrix",
             "url": "https://get.typo3.org/version/13",
             "purpose": "per-series release status and supported-version "
                        "detail for the current LTS line audit trail"},
            {"stage": "hardening-assessment",
             "name": "TYPO3 Core API: Security chapter",
             "url": "https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/Security/Index.html",
             "purpose": "official security guide: security policy, update "
                        "discipline, and hardening defaults for the "
                        "assessment pass"},
        ],
    },
}


def build_data() -> dict:
    """Canonical data structure from the curated rows: sorted cms keys,
    rows staged in curated order, meta totalled by count (drift alarm)."""
    cms = {}
    for name in sorted(CATALOG):
        rows = [dict(row) for row in CATALOG[name]["flows"]]
        cms[name] = {"arcs": list(ARCS), "flows": rows}
    totals = {"cms": len(cms), "flows": sum(len(e["flows"]) for e in cms.values())}
    return {
        "cms": cms,
        "meta": {
            "source": SOURCE,
            "policy": POLICY,
            "totals": totals,
            "urls_verified": URLS_VERIFIED,
        },
    }


def check_url_once(url: str, timeout: int = 20):
    """One polite bounded live check of a single row URL.

    Returns the final HTTP status code (after redirects), or an error
    string. Honors 429/Retry-After once (bounded wait), then gives up -
    candidates that fail here are dropped from the curated rows, never
    shipped dead."""
    import time
    import urllib.error
    import urllib.request

    ua = "Mozilla/5.0 (compatible; ka049-catalog-build/1.0)"
    request = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            retry = exc.headers.get("Retry-After", "").strip()
            wait = min(int(retry) if retry.isdigit() else 15, 30)
            time.sleep(wait)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as retry_response:
                    return retry_response.getcode()
            except Exception as exc2:
                return type(exc2).__name__ + ": " + str(exc2)[:120]
        return "HTTP %d" % exc.code
    except Exception as exc:
        return type(exc).__name__ + ": " + str(exc)[:120]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true",
                        help="opt-in: verify every row URL is live (HTTP "
                             "200); never in CI - drop/replace any row "
                             "that fails and rebuild offline")
    args = parser.parse_args()

    data = build_data()

    if args.live:
        dead = []
        checked = 0
        for name, entry in sorted(data["cms"].items()):
            for row in entry["flows"]:
                result = check_url_once(row["url"])
                checked += 1
                if result != 200:
                    dead.append((name, row["stage"], row["name"],
                                 row["url"], result))
        for row in dead:
            print("DEAD: %s/%s %s %s -> %s" % row)
        print("CMS-CATALOG-LIVE checked=%d dead=%d" % (checked, len(dead)))
        return 1 if dead else 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print("CMS-CATALOG-OK cms=%d flows=%d out=%s"
          % (data["meta"]["totals"]["cms"], data["meta"]["totals"]["flows"],
             OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())