#!/usr/bin/env python3
"""KA-080 - build data/appliance_cves.json: the KEV appliance CVE set
(vCenter/ESXi, Citrix, F5 BIG/IP, Ivanti incl. the legacy Pulse Secure
lineage) curated as PROPOSAL rows for the KA-029 CVE-DB review queue.

Every row is a pending-review proposal shaped exactly like
scripts/ka/cve_db_propose.py's rows (cve, dateAdded, vendor, product,
name, references, proposed_at, status, review_decision, source) plus
the per-row "family" bucket and the per-row "lab_only": true flag -
the OPT-80 lab-only flagging: the appliance set is lab-test material,
never an automatic CVE_EXPLOIT_DB change, and each row is still waiting
for a human approve/reject/park in KA-029's review queue
(docs/KA-CVE-DB-REVIEW-QUEUE.md). The DB itself stays untouched by this
corpus; this file is the proposal DATA only.

Filter semantics (the appliance matcher below): the VMware vendor leg
restricted to vCenter/ESX(i)/vSphere products as OPT-80 names them
(other VMware product lines stay out), the Citrix vendor leg in full
(NetScaler ADC/Gateway, SD-WAN, ShareFile, StoreFront..., per the
spec's Citrix leg), the F5 vendor leg or a BIG-IP/BIG-IQ product, and
the Ivanti vendor leg in full plus the legacy "Pulse Secure" vendor
label (Pulse Connect Secure, now Ivanti-branded).

Build-time URL discipline (mirrors tools/build_cms_catalog.py): every
committed reference was verified live (HTTP 200) on 2026-10-06 with a
bounded, polite sequential check (the --live mode below; UA
"Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)"; slow per-host
pacing, 429/Retry-After honored once, then the candidate is dropped).
Candidates that failed that check were DROPPED and replaced, and are
not in the data; dead-link notes live HERE, never in the data:

  - initial curation run: no committed reference failed. Candidate
    vendor links already excluded by the 2-reference curation rule
    (kept: the vendor advisory + the NVD anchor per row) included the
    aggregate CISA BOD-26-04 directive round-up pages and two extra
    Citrix/F5 blog+article links the KEV notes carried beside the kept
    bulletin links.

Default run is OFFLINE and deterministic: it re-serializes the curated
rows below canonically (the corpus evolves by editing the CANDIDATES
literal, never by hand-editing the JSON). --live is opt-in verification
only (never in CI; unit tests stay offline): one fresh read of the
CISA catalog feed plus one bounded check per committed reference -
every curated cve must still be an appliance-family row in the live
feed (KEV removals fail loudly) and every reference must return 200.

Source/inspiration licensing: rows derive from the U.S. CISA Catalog
of Known Exploited Vulnerabilities (public JSON API,
https://www.cisa.gov/sites/default/files/feeds/
known_exploited_vulnerabilities.json) - a U.S. Government work whose
catalog page invites reuse; CVE ids, vendor/product labels, dates, and
short titles are factual data re-listed with credit. The lab-only
proposal framing, the family taxonomy, the matcher, the 2-reference
curation rule (vendor advisory anchored by the NVD detail page), and
the filter logic are re-authored in-house. No payload or exploit
content of any kind (policy in the data's meta, enforced by
tests/test_appliance_corpus.py).
"""
import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "appliance_cves.json"

FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
UA = "Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)"

SOURCE = ("entries derive from the U.S. CISA Catalog of Known Exploited "
          "Vulnerabilities (public JSON API, cited in the meta's kev_feed); "
          "factual fields re-listed with credit; proposal framing, family "
          "taxonomy, and matcher re-authored in-house (KA-080)")
POLICY = ("pending-review proposal data for KA-029's CVE-DB review "
          "queue: a human approve/reject/park decision is required "
          "before any CVE_EXPLOIT_DB row may exist; rows are flagged "
          "lab-only (OPT-80): appliance CVEs are lab-test material, "
          "never live-match ammunition; names + vendor/product labels "
          "+ reference links only, no payloads or exploit content")
FAMILIES_DOC = ("vmware-vsphere (vCenter/ESX(i)/vSphere products only), "
                "citrix (vendor leg incl. NetScaler ADC/Gateway), f5 "
                "(vendor leg or BIG-IP/BIG-IQ products), ivanti (vendor "
                "leg + legacy Pulse Secure Connect Secure lineage)")

VERIFIED_ON = "2026-10-06"
PROPOSED_AT = VERIFIED_ON
SOURCE_LABEL = "cisa-kev-appliance"
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")

_VMWARE_PRODUCTS = ("vcenter", "esxi", "vsphere")
_IVANTI_VENDORS = ("ivanti", "pulse secure")

# Curated rows: chosen from the live KEV appliance-filtered set on the
# verification date, in curated (consultation) order within each
# family. Fields are verbatim feed values (names trimmed); references
# follow the 2-ref rule: the vendor advisory from the entry's notes,
# anchored by the NVD detail page; every URL verified live (see --live).
CANDIDATES = {
    "citrix": [
        {
         'cve': 'CVE-2019-19781',
         'dateAdded': '2021-11-03',
         'vendor': 'Citrix',
         'product': 'Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance',
         'name': 'Citrix ADC, Gateway, and SD-WAN WANOP Appliance Code Execution Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2019-19781',
         ],
        },
        {
         'cve': 'CVE-2020-8193',
         'dateAdded': '2021-11-03',
         'vendor': 'Citrix',
         'product': 'Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance',
         'name': 'Citrix ADC, Gateway, and SD-WAN WANOP Appliance Authorization Bypass Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2020-8193',
         ],
        },
        {
         'cve': 'CVE-2022-27518',
         'dateAdded': '2022-12-13',
         'vendor': 'Citrix',
         'product': 'Application Delivery Controller (ADC) and Gateway',
         'name': 'Citrix Application Delivery Controller (ADC) and Gateway Authentication Bypass Vulnerability',
         "references": [
             'https://www.citrix.com/blogs/2022/12/13/critical-security-update-now-available-for-citrix-adc-citrix-gateway/',
             'https://nvd.nist.gov/vuln/detail/CVE-2022-27518',
         ],
        },
        {
         'cve': 'CVE-2023-3519',
         'dateAdded': '2023-07-19',
         'vendor': 'Citrix',
         'product': 'NetScaler ADC and NetScaler Gateway',
         'name': 'Citrix NetScaler ADC and NetScaler Gateway Code Injection Vulnerability',
         "references": [
             'https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-3519',
         ],
        },
        {
         'cve': 'CVE-2023-4966',
         'dateAdded': '2023-10-18',
         'vendor': 'Citrix',
         'product': 'NetScaler ADC and NetScaler Gateway',
         'name': 'Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability',
         "references": [
             'https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
         ],
        },
        {
         'cve': 'CVE-2023-6548',
         'dateAdded': '2024-01-17',
         'vendor': 'Citrix',
         'product': 'NetScaler ADC and NetScaler Gateway',
         'name': 'Citrix NetScaler ADC and NetScaler Gateway Code Injection Vulnerability',
         "references": [
             'https://support.citrix.com/article/CTX584986/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20236548-and-cve20236549',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-6548',
         ],
        },
        {
         'cve': 'CVE-2025-5777',
         'dateAdded': '2025-07-10',
         'vendor': 'Citrix',
         'product': 'NetScaler ADC and Gateway',
         'name': 'Citrix NetScaler ADC and Gateway Out-of-Bounds Read Vulnerability',
         "references": [
             'https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-5777',
         ],
        },
        {
         'cve': 'CVE-2025-7775',
         'dateAdded': '2025-08-26',
         'vendor': 'Citrix',
         'product': 'NetScaler',
         'name': 'Citrix NetScaler Memory Overflow Vulnerability',
         "references": [
             'https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694938',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-7775',
         ],
        },
    ],
    "f5": [
        {
         'cve': 'CVE-2020-5902',
         'dateAdded': '2021-11-03',
         'vendor': 'F5',
         'product': 'BIG-IP',
         'name': 'F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2020-5902',
         ],
        },
        {
         'cve': 'CVE-2021-22986',
         'dateAdded': '2021-11-03',
         'vendor': 'F5',
         'product': 'BIG-IP and BIG-IQ Centralized Management',
         'name': 'F5 BIG-IP and BIG-IQ Centralized Management iControl REST Remote Code Execution Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-22986',
         ],
        },
        {
         'cve': 'CVE-2021-22991',
         'dateAdded': '2022-01-18',
         'vendor': 'F5',
         'product': 'BIG-IP Traffic Management Microkernel',
         'name': 'F5 BIG-IP Traffic Management Microkernel Buffer Overflow',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-22991',
         ],
        },
        {
         'cve': 'CVE-2022-1388',
         'dateAdded': '2022-05-10',
         'vendor': 'F5',
         'product': 'BIG-IP',
         'name': 'F5 BIG-IP Missing Authentication Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2022-1388',
         ],
        },
        {
         'cve': 'CVE-2023-46747',
         'dateAdded': '2023-10-31',
         'vendor': 'F5',
         'product': 'BIG-IP Configuration Utility',
         'name': 'F5 BIG-IP Configuration Utility Authentication Bypass Vulnerability',
         "references": [
             'https://my.f5.com/manage/s/article/K000137353',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-46747',
         ],
        },
        {
         'cve': 'CVE-2025-53521',
         'dateAdded': '2026-03-27',
         'vendor': 'F5',
         'product': 'BIG-IP',
         'name': 'F5 BIG-IP Stack-Based Buffer Overflow Vulnerability',
         "references": [
             'https://my.f5.com/manage/s/article/K000156741',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-53521',
         ],
        },
    ],
    "ivanti": [
        {
         'cve': 'CVE-2019-11510',
         'dateAdded': '2021-11-03',
         'vendor': 'Ivanti',
         'product': 'Pulse Connect Secure',
         'name': 'Ivanti Pulse Connect Secure Arbitrary File Read Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2019-11510',
         ],
        },
        {
         'cve': 'CVE-2020-8218',
         'dateAdded': '2022-03-07',
         'vendor': 'Pulse Secure',
         'product': 'Pulse Connect Secure',
         'name': 'Pulse Connect Secure Code Injection Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2020-8218',
         ],
        },
        {
         'cve': 'CVE-2021-22893',
         'dateAdded': '2021-11-03',
         'vendor': 'Ivanti',
         'product': 'Pulse Connect Secure',
         'name': 'Ivanti Pulse Connect Secure Use-After-Free Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-22893',
         ],
        },
        {
         'cve': 'CVE-2023-35078',
         'dateAdded': '2023-07-25',
         'vendor': 'Ivanti',
         'product': 'Endpoint Manager Mobile (EPMM)',
         'name': 'Ivanti Endpoint Manager Mobile Authentication Bypass Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-35078',
         ],
        },
        {
         'cve': 'CVE-2023-38035',
         'dateAdded': '2023-08-22',
         'vendor': 'Ivanti',
         'product': 'Sentry',
         'name': 'Ivanti Sentry Authentication Bypass Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/CVE-2023-38035-API-Authentication-Bypass-on-Sentry-Administrator-Interface?language=en_US',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-38035',
         ],
        },
        {
         'cve': 'CVE-2023-46805',
         'dateAdded': '2024-01-10',
         'vendor': 'Ivanti',
         'product': 'Connect Secure and Policy Secure',
         'name': 'Ivanti Connect Secure and Policy Secure Authentication Bypass Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-46805',
         ],
        },
        {
         'cve': 'CVE-2024-21887',
         'dateAdded': '2024-01-10',
         'vendor': 'Ivanti',
         'product': 'Connect Secure and Policy Secure',
         'name': 'Ivanti Connect Secure and Policy Secure Command Injection Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US',
             'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
         ],
        },
        {
         'cve': 'CVE-2024-8963',
         'dateAdded': '2024-09-19',
         'vendor': 'Ivanti',
         'product': 'Cloud Services Appliance (CSA)',
         'name': 'Ivanti Cloud Services Appliance (CSA) Path Traversal Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-4-6-Cloud-Services-Appliance-CVE-2024-8963',
             'https://nvd.nist.gov/vuln/detail/CVE-2024-8963',
         ],
        },
        {
         'cve': 'CVE-2025-0282',
         'dateAdded': '2025-01-08',
         'vendor': 'Ivanti',
         'product': 'Connect Secure, Policy Secure, and ZTA Gateways',
         'name': 'Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
         ],
        },
        {
         'cve': 'CVE-2025-22457',
         'dateAdded': '2025-04-04',
         'vendor': 'Ivanti',
         'product': 'Connect Secure, Policy Secure, and ZTA Gateways',
         'name': 'Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability',
         "references": [
             'https://forums.ivanti.com/s/article/April-Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-22457',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-22457',
         ],
        },
    ],
    "vmware-vsphere": [
        {
         'cve': 'CVE-2019-5544',
         'dateAdded': '2021-11-03',
         'vendor': 'VMware',
         'product': 'VMware ESXi and Horizon DaaS',
         'name': 'VMware ESXi and Horizon DaaS OpenSLP Heap-Based Buffer Overflow Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2019-5544',
         ],
        },
        {
         'cve': 'CVE-2020-3992',
         'dateAdded': '2021-11-03',
         'vendor': 'VMware',
         'product': 'ESXi',
         'name': 'VMware ESXi OpenSLP Use-After-Free Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2020-3992',
         ],
        },
        {
         'cve': 'CVE-2021-21972',
         'dateAdded': '2021-11-03',
         'vendor': 'VMware',
         'product': 'vCenter Server',
         'name': 'VMware vCenter Server Remote Code Execution Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-21972',
         ],
        },
        {
         'cve': 'CVE-2021-21985',
         'dateAdded': '2021-11-03',
         'vendor': 'VMware',
         'product': 'vCenter Server',
         'name': 'VMware vCenter Server Improper Input Validation Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-21985',
         ],
        },
        {
         'cve': 'CVE-2021-22005',
         'dateAdded': '2021-11-03',
         'vendor': 'VMware',
         'product': 'vCenter Server',
         'name': 'VMware vCenter Server File Upload Vulnerability',
         "references": [
             'https://nvd.nist.gov/vuln/detail/CVE-2021-22005',
         ],
        },
        {
         'cve': 'CVE-2023-34048',
         'dateAdded': '2024-01-22',
         'vendor': 'VMware',
         'product': 'vCenter Server',
         'name': 'VMware vCenter Server Out-of-Bounds Write Vulnerability',
         "references": [
             'https://www.vmware.com/security/advisories/VMSA-2023-0023.html',
             'https://nvd.nist.gov/vuln/detail/CVE-2023-34048',
         ],
        },
        {
         'cve': 'CVE-2024-38812',
         'dateAdded': '2024-11-20',
         'vendor': 'VMware',
         'product': 'vCenter Server',
         'name': 'VMware vCenter Server Heap-Based Buffer Overflow Vulnerability',
         "references": [
             'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968',
             'https://nvd.nist.gov/vuln/detail/CVE-2024-38812',
         ],
        },
        {
         'cve': 'CVE-2025-22225',
         'dateAdded': '2025-03-04',
         'vendor': 'VMware',
         'product': 'ESXi',
         'name': 'VMware ESXi Arbitrary Write Vulnerability',
         "references": [
             'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390',
             'https://nvd.nist.gov/vuln/detail/CVE-2025-22225',
         ],
        },
    ],
}


def appliance_family(vendor, product):
    """The OPT-80 appliance matcher: the family name for a vendor/
    product pair inside the KEV appliance set, else None when the pair
    is outside it. String inputs produce clean results (None or a
    family name); any other input type raises ValueError."""
    for label, value in (("vendor", vendor), ("product", product)):
        if not isinstance(value, str):
            raise ValueError("%s must be a string" % label)
    vendor = vendor.strip().lower()
    product = product.strip().lower()
    if vendor == "vmware":
        if any(word in product for word in _VMWARE_PRODUCTS):
            return "vmware-vsphere"
        return None
    if vendor == "citrix" or "citrix" in product:
        return "citrix"
    if vendor == "f5" or "big-ip" in product or "bigip" in product:
        return "f5"
    if vendor in _IVANTI_VENDORS:
        return "ivanti"
    return None


def _scrub_text(label, value):
    """Clean one proposal string or raise ValueError: strings only, no
    control/bidi/zero-width injection characters, nothing left blank by
    trimming. No length bound by design (the guard-corpus finding)."""
    if not isinstance(value, str):
        raise ValueError("%s must be a string" % label)
    value = value.strip()
    if not value:
        raise ValueError("%s must not be empty" % label)
    for ch in value:
        if ch < " " or ch == "\x7f":
            raise ValueError("%s carries a control character" % label)
        code = ord(ch)
        if 0x200B <= code <= 0x200F or 0x202A <= code <= 0x202E:
            raise ValueError("%s carries an invisible-override character" % label)
    return value


def _valid_reference(url):
    """Shape-check one reference URL (offline, string-level)."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("reference must be a non-empty string")
    url = url.strip()
    if not url.startswith("https://"):
        raise ValueError("reference must start with https:// : %r" % url)
    if any(ch < " " for ch in url) or " " in url or "\x7f" in url:
        raise ValueError("reference carries whitespace/control characters")
    if url.count("/") < 3:
        raise ValueError("reference is not a well-formed URL")
    return url


def _valid_date(text):
    """dateAdded parses as a real calendar date (a stdlib-free check -
    the date machinery lives with the consuming modules)."""
    year, month, day = (int(part) for part in text.split("-"))
    if year < 1999 or not 1 <= month <= 12 or not 1 <= day <= 31:
        return False
    month_lengths = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return day <= month_lengths[month - 1]


def build_proposal(family, row):
    """One curated row -> the canonical pending-review proposal dict
    (the KA-029 proposal shape + family + lab_only)."""
    for label in ("cve", "dateAdded", "vendor", "product", "name"):
        if label not in row:
            raise ValueError("row misses %s" % label)
    cve = _scrub_text("cve", row["cve"])
    if not CVE_RE.fullmatch(cve):
        raise ValueError("cve malformed: %r" % cve)
    date_added = _scrub_text("dateAdded", row["dateAdded"])
    if not DATE_RE.fullmatch(date_added) or not _valid_date(date_added):
        raise ValueError("dateAdded malformed: %r" % date_added)
    vendor = _scrub_text("vendor", row["vendor"])
    product = _scrub_text("product", row["product"])
    name = _scrub_text("name", row["name"])
    matched = appliance_family(vendor, product)
    if matched != family:
        raise ValueError("row does not match family %r: %r/%r"
                         % (family, vendor, product))
    refs = row["references"]
    if not isinstance(refs, list) or not refs:
        raise ValueError("references must be a non-empty list")
    cleaned = []
    for url in refs:
        url = _valid_reference(url)
        if url in cleaned:
            raise ValueError("duplicate reference in row: %r" % url)
        cleaned.append(url)
    return {
        "cve": cve,
        "dateAdded": date_added,
        "vendor": vendor,
        "product": product,
        "name": name,
        "references": cleaned,
        "proposed_at": PROPOSED_AT,
        "status": "pending-review",
        "review_decision": None,
        "source": SOURCE_LABEL,
        "lab_only": True,
        "family": family,
    }


def build_data():
    """Canonical data structure: sorted family keys, rows in curated
    order, unique CVE ids corpus-wide, meta totalled by count."""
    families = {}
    seen = {}
    for family in sorted(CANDIDATES):
        proposals = []
        for row in CANDIDATES[family]:
            proposal = build_proposal(family, row)
            if proposal["cve"] in seen:
                raise ValueError("duplicate cve across corpus: %s"
                                 % proposal["cve"])
            seen[proposal["cve"]] = family
            proposals.append(proposal)
        families[family] = {"proposals": proposals}
    totals = {
        "families": len(families),
        "proposals": sum(len(entry["proposals"])
                         for entry in families.values()),
    }
    return {
        "families": families,
        "meta": {
            "source": SOURCE,
            "policy": POLICY,
            "totals": totals,
            "urls_verified": VERIFIED_ON,
            "kev_feed": FEED_URL,
            "families_doc": FAMILIES_DOC,
            "lab_only": True,
        },
    }


def _feed_rows(feed):
    """Normalize one parsed feed document (raw CISA KEV shape or the
    kevstig entry shape) to plain rows keyed cve/vendor/product/name/
    dateAdded."""
    rows = feed.get("vulnerabilities") or feed.get("entries") or []
    normalized = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        def grab(*keys, _entry=entry):
            for key in keys:
                if _entry.get(key):
                    return _entry[key]
            return ""
        normalized.append({
            "cve": grab("cveID", "cve"),
            "vendor": grab("vendorProject", "vendor"),
            "product": grab("product"),
            "name": grab("vulnerabilityName", "name"),
            "dateAdded": grab("dateAdded"),
        })
    return normalized


def _polite_get(url, timeout):
    """--live support: one bounded polite GET with the build UA; a 429
    honors Retry-After once, then gives up. Returns (status, body);
    body is None following an error, whose text is the status return.
    The only network import in this builder is lazy, right here."""
    import time
    import urllib.error
    import urllib.request

    time.sleep(7 if "nvd.nist.gov" in url else 3)
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode(), response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            retry = exc.headers.get("Retry-After", "").strip()
            wait = min(int(retry) if retry.isdigit() else 15, 30)
            time.sleep(wait)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as again:
                    return again.getcode(), again.read()
            except Exception as exc2:
                return type(exc2).__name__ + ": " + str(exc2)[:120], None
        return "HTTP %d" % exc.code, None
    except Exception as exc:
        return type(exc).__name__ + ": " + str(exc)[:120], None


def _polite_feed_round():
    """One bounded feed round (429 handled once inside _polite_get),
    returning the parsed doc or an error string."""
    status, body = _polite_get(FEED_URL, 120)
    if body is None:
        return status
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        return "feed unparsable"


def check_url_once(url, timeout=30):
    """One polite bounded live check of a single reference URL (the
    tools/build_cms_catalog.py discipline). Returns the final HTTP
    status code, or an error string - candidates that fail here were
    dropped from the curated rows, never shipped dead."""
    status, _ = _polite_get(url, timeout)
    return status


def live_verify(data):
    """--live: (1) one bounded feed read - every curated cve must still
    be an appliance-family row in it (KEV removals and re-labeled rows
    fail loudly; growth of the live set is expected and only reported);
    (2) every committed reference must answer HTTP 200."""
    feed = _polite_feed_round()
    if not isinstance(feed, dict):
        print("APPLIANCE-CORPUS-LIVE feed-read failed: %s" % feed)
        return 1
    live_index = {}
    for row in _feed_rows(feed):
        family = appliance_family(row["vendor"], row["product"])
        if family:
            live_index[row["cve"]] = family
    counts = {}
    for family in live_index.values():
        counts[family] = counts.get(family, 0) + 1
    missing = 0
    for family in sorted(data["families"]):
        for proposal in data["families"][family]["proposals"]:
            still = live_index.get(proposal["cve"])
            if still != family:
                print("MISSING: %s %s (live feed: %s)"
                      % (family, proposal["cve"], still))
                missing += 1
    dead = []
    checked = 0
    for family in sorted(data["families"]):
        for proposal in data["families"][family]["proposals"]:
            for url in proposal["references"]:
                checked += 1
                status = check_url_once(url)
                if status != 200:
                    dead.append((family, proposal["cve"], url, status))
    for family, cve, url, status in dead:
        print("DEAD: %s %s %s -> %s" % (family, cve, url, status))
    print("APPLIANCE-CORPUS-LIVE entries=%d urls=%d dead=%d missing=%d"
          % (len(live_index), checked, len(dead), missing))
    return 1 if (dead or missing) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true",
                        help="opt-in: re-read the CISA feed and verify "
                             "every curated cve still matches + every "
                             "reference answers 200; never in CI - "
                             "drop/replace failing rows and rebuild")
    args = parser.parse_args()
    data = build_data()
    if args.live:
        return live_verify(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print("APPLIANCE-CORPUS-OK families=%d proposals=%d out=%s"
          % (data["meta"]["totals"]["families"],
             data["meta"]["totals"]["proposals"], OUT))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
