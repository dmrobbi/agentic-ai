"""KA-072 - stig gap report: the generated catalog's shape and counted
totals (24 maintained stig-baselines platforms, 111 committed CKL
checklists, 6866 distinct maintained rules; three SRG control families
OS/APP/NET with the OS and APP families templated and NET deliberately
untemplated so its rules report unmet), the stig-baselines CKL/XCCDF
checklist shapes parsed from committed fixtures, the rule-level gap
math (covered vs unmet rules per platform, per-family unmet
aggregation, unscanned baselines, the bounded severity-ordered
priority queue, duplicate Vuln_Num collapse), malformed-input
rejections, and the offline builder running green, byte-identically
reproducible, with the live URL sweep staying opt-in.

Fixture provenance (synthetic-but-realistic, no network): the two .ckl
fixtures model the stig-baselines program's generated checklist shape -
CHECKLIST/ASSET/STIGS/iSTIG/STIG_INFO header plus VULN rows carrying
the full 24 STIG_DATA attribute list (STIGRef ... CCI_REF) and STATUS
values NotAFinding/Open/Not_Applicable/Not_Reviewed - with synthetic
vulnerability ids, synthetic rule prose (no DISA verbatim text) and
mixed statuses. stig_gap_ubuntu_ckl.xml is the Ubuntu 22.04 v2r9 shape
(8 rules: 7 SRG-OS + 1 legacy prose group title that falls to the
`unknown` family); stig_gap_vsphere_ckl.xml is the vSphere 6.7 ESXi
v1r3 shape (6 rules: 4 OS + 2 NET/FW, so the unmet side bites against
the untemplated NET family). stig_gap_rhel_xccdf.xml models the
official DISA XCCDF 1.1 source shape (Benchmark/Group/Rule; the SRG id
sits in the Group title, the CCI in the Rule ident). Rule ids, SRG/CCI
references, and release strings are synthetic continuations of the
real formats; the catalog-data payload policy applies to fixtures.
No network (the builder's default mode and these tests run offline)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "build_stig_gap_report.py"
FIXTURES = REPO / "tests" / "fixtures" / "scans"
UBUNTU_CKL = FIXTURES / "stig_gap_ubuntu_ckl.xml"
VSPHERE_CKL = FIXTURES / "stig_gap_vsphere_ckl.xml"
RHEL_XCCDF = FIXTURES / "stig_gap_rhel_xccdf.xml"

_spec = importlib.util.spec_from_file_location(
    "build_stig_gap_report", str(TOOL))
KA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(KA)

EXPECTED_FAMILIES = ("APP", "NET", "OS")
EXPECTED_FAMILY_TEMPLATES = {"APP": 3, "NET": 0, "OS": 4}
EXPECTED_FAMILY_ARCS = {
    "OS": ("inventory", "config-review", "finding-pairing",
           "remediation-plan"),
    "APP": ("service-inventory", "config-review", "version-trail",
            "findings"),
    "NET": ("device-inventory", "config-review", "segmentation-review",
            "findings"),
}
EXPECTED_PLATFORMS = (
    "citrix", "docker", "exchange", "firefox", "horizon", "kubernetes",
    "macos", "nsx", "outlook", "proxmox", "rhel7", "rhel8", "rhel9",
    "ubuntu20.04", "ubuntu22.04", "ubuntu24.04", "vra7", "vrops6",
    "vsphere65", "vsphere67", "vsphere70", "vsphere80", "windows",
    "workspace_one")
EXPECTED_BASELINE_COUNTS = {
    "citrix": (13, 49), "docker": (0, 0), "exchange": (7, 432),
    "firefox": (1, 33), "horizon": (3, 57), "kubernetes": (1, 92),
    "macos": (2, 320), "nsx": (13, 131), "outlook": (2, 146),
    "proxmox": (0, 0), "rhel7": (3, 277), "rhel8": (3, 404),
    "rhel9": (3, 478), "ubuntu20.04": (1, 173), "ubuntu22.04": (1, 188),
    "ubuntu24.04": (1, 194), "vra7": (8, 611), "vrops6": (5, 517),
    "vsphere65": (3, 180), "vsphere67": (12, 502),
    "vsphere70": (12, 491), "vsphere80": (12, 487),
    "windows": (4, 1084), "workspace_one": (1, 20),
}
EXPECTED_KIT_PLATFORMS = ("docker", "kubernetes", "proxmox")
EXPECTED_EOL_PLATFORMS = ["rhel7"]
EXPECTED_CATALOG_TOTALS = {"baselines": 24, "ckls": 111, "families": 3,
                           "rules_maintained": 6866, "template_rows": 7}
EXPECTED_RULE_KEYS = {"cci", "group_title", "rule_id", "rule_ver",
                      "severity", "status", "vuln_num"}
EXPECTED_CKL_KEYS = {"stig_id", "stig_title", "release_info", "source",
                     "rules"}
EXPECTED_XCCDF_KEYS = {"cci", "group_id", "rule_id", "rule_ver",
                       "severity", "srg"}

FORBIDDEN_STRINGS = (
    "<script", "javascript:", "onerror=", "onload=", "union select",
    "drop table", "select *", "base64", "/etc/passwd", "whoami",
    "bash -c", "nc -e", "import subprocess", "os.system", "eval(",
    "exec(", "system(", "curl", "wget", "hydra", "sqlmap", "metasploit",
    "password", "secret_",
)
DEAD_LINK_MARKERS = (
    "dead", "404", "403", "unavailable", "no longer", "removed",
    "dropped", "unreachable",
)


def _catalog() -> dict:
    return KA.build_catalog()


def _fixture_state() -> dict:
    return {
        "ubuntu22.04": KA.parse_ckl(
            UBUNTU_CKL.read_text(encoding="utf-8"))["rules"],
        "vsphere67": KA.parse_ckl(
            VSPHERE_CKL.read_text(encoding="utf-8"))["rules"],
    }


def _fixture_report() -> dict:
    return KA.gap_report(_catalog(), _fixture_state())


def test_catalog_top_shape():
    catalog = _catalog()
    assert set(catalog) == {"families", "baselines", "meta"}
    assert tuple(sorted(catalog["families"])) == EXPECTED_FAMILIES
    assert tuple(sorted(catalog["baselines"])) == EXPECTED_PLATFORMS


def test_catalog_family_templates_and_arcs():
    catalog = _catalog()
    for name in EXPECTED_FAMILIES:
        row = catalog["families"][name]
        assert set(row) == {"arc", "label", "templates"}, name
        assert tuple(row["arc"]) == EXPECTED_FAMILY_ARCS[name], name
        assert row["label"].strip(), name
        assert len(row["templates"]) == EXPECTED_FAMILY_TEMPLATES[name]
        for template in row["templates"]:
            assert set(template) == {"name", "purpose", "stage", "url"}
            assert template["stage"] in row["arc"], template
            assert all(str(value).strip() for value in template.values())


def test_catalog_baseline_rows():
    catalog = _catalog()
    expect = EXPECTED_BASELINE_COUNTS
    for platform, row in sorted(catalog["baselines"].items()):
        assert platform in expect, (platform, row)
        labels = row["labels"]
        assert isinstance(labels, list) and labels[0].strip(), platform
        assert (row["ckls"], row["rules_maintained"]) == expect[platform], \
            platform


def test_catalog_kit_and_track_flags():
    catalog = _catalog()
    kits = {name for name, row in catalog["baselines"].items()
            if row["kit"]}
    tracks = {name for name, row in catalog["baselines"].items()
              if row["track"] == "eol"}
    assert kits == set(EXPECTED_KIT_PLATFORMS)
    assert sorted(tracks) == EXPECTED_EOL_PLATFORMS


def test_catalog_meta_and_totals():
    catalog = _catalog()
    assert set(catalog["meta"]) == {
        "policy", "registry_note", "source", "totals", "urls_verified"}
    for prose in ("source", "policy", "registry_note"):
        assert catalog["meta"][prose].strip(), prose
    assert catalog["meta"]["totals"] == EXPECTED_CATALOG_TOTALS
    import re
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}",
                        catalog["meta"]["urls_verified"]), \
        catalog["meta"]["urls_verified"]


def test_catalog_urls_wellformed_and_unique():
    from urllib.parse import urlsplit
    catalog = _catalog()
    urls = [row["url"] for row in KA.SOURCES]
    for entry in catalog["families"].values():
        urls += [row["url"] for row in entry["templates"]]
    assert len(urls) == len(set(urls)) == 9
    for url in urls:
        assert url.startswith("https://"), url
        assert not any(c.isspace() for c in url), url
        assert urlsplit(url).netloc, url


def test_catalog_no_payload_strings():
    text = json.dumps(_catalog()).lower()
    for needle in FORBIDDEN_STRINGS:
        assert needle not in text, needle


def _string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.items():
            yield from _string_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_values(item)


def test_catalog_no_dead_link_markers():
    # walk string values only: numeric counts (rhel8's rules_maintained
    # is 404) are not texts and must not trip the marker scan
    strings = " ".join(_string_values(_catalog())).lower()
    for marker in DEAD_LINK_MARKERS:
        assert marker not in strings, marker


def test_fixtures_carry_no_payload_strings():
    for path in (UBUNTU_CKL, VSPHERE_CKL, RHEL_XCCDF):
        text = path.read_text(encoding="utf-8").lower()
        for needle in FORBIDDEN_STRINGS:
            assert needle not in text, (path.name, needle)


def test_builder_purity_and_lazy_network():
    source = TOOL.read_text(encoding="utf-8")
    for marker in ("subprocess", "os.system", "eval(", "exec("):
        assert marker not in source, marker
    assert "--live" in source
    offline_part = source.split("def check_url_once", 1)[0]
    assert offline_part.strip(), "check_url_once not found in builder"
    for needle in ("urllib", "requests", "http.client"):
        assert needle not in offline_part, needle
    assert source.count("import urllib.request") == 1


def test_status_constants_and_ranks():
    assert KA.STATUSES == ("NotAFinding", "Open", "Not_Applicable",
                           "Not_Reviewed")
    assert KA.SEVERITIES == ("high", "medium", "low")
    assert KA.OPEN_STATUSES == ("Open", "Not_Reviewed")
    assert KA.MAX_PRIORITY_ROWS == 25
    # the collapse ranking: an Open row outranks everything else
    assert KA.STATUS_RANK["Open"] == 0
    assert KA.STATUS_RANK["Not_Reviewed"] == 1
    assert KA.SEVERITY_RANK == {"high": 0, "medium": 1, "low": 2}


def test_parse_ckl_ubuntu_fixture():
    parsed = KA.parse_ckl(UBUNTU_CKL.read_text(encoding="utf-8"))
    assert set(parsed) == EXPECTED_CKL_KEYS
    assert parsed["stig_title"] == (
        "Canonical Ubuntu 22.04 LTS Security Technical Implementation "
        "Guide")
    assert parsed["stig_id"] == "U_CAN_Ubuntu_22-04_LTS_STIG_V2R9_Manual"
    assert parsed["release_info"] == (
        "Release: 9 Benchmark Date: 01 Jul 2026")
    assert parsed["source"] == ("DISA - DoD Cyber Exchange (STIG "
                                "content is public domain)")
    rules = parsed["rules"]
    assert len(rules) == 8
    assert all(set(row) == EXPECTED_RULE_KEYS for row in rules)
    assert sorted({r["vuln_num"] for r in rules}) == sorted(
        "V-26048%d" % i for i in range(8))
    assert rules[0] == {
        "vuln_num": "V-260480",
        "rule_id": "SV-260480r90001_rule",
        "rule_ver": "UBTU-22-211001",
        "severity": "high",
        "group_title": "SRG-OS-000480-GPOS-00227",
        "cci": "CCI-000366",
        "status": "NotAFinding",
    }
    prose_row = rules[7]
    assert prose_row == {
        "vuln_num": "V-260487",
        "rule_id": "SV-260487r90008_rule",
        "rule_ver": "UBTU-22-211008",
        "severity": "high",
        "group_title": "The Ubuntu operating system must apply the "
                       "legacy prose group shape.",
        "cci": "CCI-000366",
        "status": "Open",
    }


def test_parse_ckl_ubuntu_status_and_family_mix():
    parsed = KA.parse_ckl(UBUNTU_CKL.read_text(encoding="utf-8"))
    rules = parsed["rules"]
    statuses = {}
    families = {}
    for row in rules:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
        family = KA.srg_family(row["group_title"])
        families[family] = families.get(family, 0) + 1
    assert statuses == {"NotAFinding": 2, "Open": 3, "Not_Applicable": 1,
                        "Not_Reviewed": 2}
    assert families == {"OS": 7, "unknown": 1}
    assert all(row["status"] in KA.STATUSES for row in rules)


def test_parse_ckl_vsphere_fixture():
    parsed = KA.parse_ckl(VSPHERE_CKL.read_text(encoding="utf-8"))
    assert parsed["stig_title"] == (
        "VMware vSphere 6.7 ESXi Security Technical Implementation "
        "Guide")
    assert parsed["stig_id"] == "U_VMW_vSphere_6-7_ESXi_STIG_V1R3_Manual"
    rules = parsed["rules"]
    assert len(rules) == 6
    assert all(set(row) == EXPECTED_RULE_KEYS for row in rules)
    assert rules[4] == {
        "vuln_num": "V-260499",
        "rule_id": "SV-260499r90005_rule",
        "rule_ver": "VMW-ESXI-6-7-990005",
        "severity": "high",
        "group_title": "SRG-NET-000019-FW-000003",
        "cci": "CCI-000019",
        "status": "Open",
    }
    assert {KA.srg_family(r["group_title"]) for r in rules} == {
        "OS", "NET"}
    assert len([r for r in rules
                if KA.srg_family(r["group_title"]) == "OS"]) == 4
    assert len([r for r in rules
                if KA.srg_family(r["group_title"]) == "NET"]) == 2


def test_parse_ckl_carry_no_rule_prose():
    for path in (UBUNTU_CKL, VSPHERE_CKL):
        parsed = KA.parse_ckl(path.read_text(encoding="utf-8"))
        for row in parsed["rules"]:
            assert set(row) == EXPECTED_RULE_KEYS, row
            for value in row.values():
                assert len(value) < 100, (path.name, value)


def _single_vuln_ckl(status="NotAFinding", severity="high",
                     with_status=True, drop=()):
    """A minimal synthetic CKL (fixture-shaped) for the malformed-input
    and unmatched-platform cases."""
    stig = [
        ("STIGRef", "Synthetic Fixture STIG :: v1r1"),
        ("Vuln_Num", "V-100001"),
        ("Severity", severity),
        ("Group_Title", "SRG-OS-000001-GPOS-00001"),
        ("Rule_ID", "SV-100001r900001_rule"),
        ("Rule_Ver", "SYN-1-100001"),
    ]
    stig = [pair for pair in stig if pair[0] not in drop]
    pairs = "\n".join(
        '        <STIG_DATA>\n'
        '          <VULN_ATTRIBUTE>%s</VULN_ATTRIBUTE>\n'
        '          <ATTRIBUTE_DATA>%s</ATTRIBUTE_DATA>\n'
        '        </STIG_DATA>' % pair
        for pair in stig)
    status_el = ('        <STATUS>%s</STATUS>\n' % status
                 if with_status else "")
    return ("<?xml version='1.0' encoding='UTF-8'?>\n<CHECKLIST>\n"
            "  <STIGS>\n    <iSTIG>\n      <STIG_INFO>\n"
            "        <SI_DATA>\n"
            "          <SID_NAME>title</SID_NAME>\n"
            "          <SID_DATA>Synthetic Fixture STIG</SID_DATA>\n"
            "        </SI_DATA>\n"
            "      </STIG_INFO>\n      <VULN>\n"
            + pairs + "\n" + status_el +
            "      </VULN>\n    </iSTIG>\n  </STIGS>\n</CHECKLIST>\n")


@pytest.mark.parametrize(
    ("ckl_text", "message"),
    [
        ("", "empty"),
        ("   \n  ", "empty"),
        ("not xml at all", "not parseable xml"),
        ("<LIST/>", "expected CHECKLIST"),
        ("<CHECKLIST/>", "missing STIGS/iSTIG/STIG_INFO"),
        (_single_vuln_ckl(  # STIG_INFO present, no VULN row
             ).replace("      <VULN>\n", "").replace("</VULN>\n", ""),
         "carries no VULN rows"),
        (_single_vuln_ckl(with_status=False), "missing STATUS"),
        (_single_vuln_ckl(status="notafinding"), "not one of"),
        (_single_vuln_ckl(severity="catastrophic"), "not one of"),
        (_single_vuln_ckl(drop=("Vuln_Num",)),
         "missing required attributes: Vuln_Num"),
        (_single_vuln_ckl(drop=("Rule_Ver",)),
         "missing required attributes: Rule_Ver"),
    ])
def test_parse_ckl_rejects_malformed(ckl_text, message):
    with pytest.raises(ValueError, match=message):
        KA.parse_ckl(ckl_text)


@pytest.mark.parametrize(
    ("group_title", "expected"),
    [
        ("SRG-OS-000480-GPOS-00227", "OS"),
        ("SRG-OS-000023-GPOS-00006", "OS"),
        ("SRG-APP-000141-CTR-000300", "APP"),
        ("SRG-APP-000001-NDM-000001? ", "APP"),
        ("SRG-NET-000019-FW-000003", "NET"),
        ("SRG-VD-000001-VDSR-000001", "VD"),
        ("", "unknown"),
        ("The Ubuntu operating system must apply the legacy prose "
         "group shape.", "unknown"),
        ("Rule group (SRG-OS-000023-GPOS-00006 embedded)", "OS"),
    ])
def test_srg_family_parametrized(group_title, expected):
    assert KA.srg_family(group_title) == expected


@pytest.mark.parametrize(
    ("stig_title", "expected"),
    [
        ("Canonical Ubuntu 22.04 LTS Security Technical Implementation "
         "Guide", "ubuntu22.04"),
        ("Canonical Ubuntu 24.04 LTS Security Technical Implementation "
         "Guide", "ubuntu24.04"),
        ("Red Hat Enterprise Linux 9 Security Technical Implementation "
         "Guide", "rhel9"),
        ("Red Hat Enterprise Linux 8 Security Technical Implementation "
         "Guide", "rhel8"),
        ("Red Hat Enterprise Linux 7 Security Technical Implementation "
         "Guide", "rhel7"),
        ("Microsoft Windows 11 Security Technical Implementation Guide",
         "windows"),
        ("Apple macOS 15 (Sequoia) Security Technical Implementation "
         "Guide", "macos"),
        ("Microsoft Exchange 2019 Mailbox Server Security Technical "
         "Implementation Guide", "exchange"),
        ("Microsoft Outlook 2016 Security Technical Implementation "
         "Guide", "outlook"),
        ("Mozilla Firefox Security Technical Implementation Guide",
         "firefox"),
        ("Citrix XenDesktop 7.x StoreFront Security Technical "
         "Implementation Guide", "citrix"),
        ("Citrix Virtual Apps and Desktop 7.x Delivery Controller "
         "Security Technical Implementation Guide", "citrix"),
        ("VMW vRealize Automation 7.x HA Proxy Security Technical "
         "Implementation Guide", "vra7"),
        ("VMW vRealize Operations Manager 6.x PostgreSQL Security "
         "Technical Implementation Guide", "vrops6"),
        ("VMware vSphere 6.5 ESXi Security Technical Implementation "
         "Guide", "vsphere65"),
        ("VMware vSphere 6.7 ESXi Security Technical Implementation "
         "Guide", "vsphere67"),
        ("VMware vSphere 7.0 ESXi Security Technical Implementation "
         "Guide", "vsphere70"),
        ("VMware vSphere 8.0 ESXi Security Technical Implementation "
         "Guide", "vsphere80"),
        ("Kubernetes Security Technical Implementation Guide",
         "kubernetes"),
        ("VMware Workspace ONE UEM Security Technical Implementation "
         "Guide", "workspace_one"),
        ("Example Vendor Appliance Security Technical Implementation "
         "Guide", None),
        ("", None),
    ])
def test_resolve_platform_parametrized(stig_title, expected):
    assert KA.resolve_platform(_catalog(), stig_title) == expected


def test_parse_xccdf_fixture():
    parsed = KA.parse_xccdf(RHEL_XCCDF.read_text(encoding="utf-8"))
    assert set(parsed) == {"benchmark_title", "rules"}
    assert parsed["benchmark_title"] == (
        "Red Hat Enterprise Linux 9 Security Technical Implementation "
        "Guide")
    rules = parsed["rules"]
    assert len(rules) == 3
    assert all(set(row) == EXPECTED_XCCDF_KEYS for row in rules)
    assert rules[0] == {
        "group_id": "V-230590",
        "rule_id": "SV-999991r900001_rule",
        "rule_ver": "RHEL-09-990001",
        "severity": "high",
        "srg": "SRG-OS-000480-GPOS-00227",
        "cci": "CCI-000366",
    }
    assert [row["srg"] for row in rules] == [
        "SRG-OS-000480-GPOS-00227", "SRG-OS-000023-GPOS-00006",
        "SRG-OS-000028-GPOS-00009"]
    assert [row["severity"] for row in rules] == ["high", "medium", "low"]


_XCCDF_WRAPPER = (
    'xmlns="http://checklists.nist.gov/xccdf/1.1"')


@pytest.mark.parametrize(
    ("xccdf_text", "message"),
    [
        ("", "empty"),
        ("nope", "not parseable xml"),
        ("<benchmark/>", "expected a xccdf Benchmark"),
        ("<Benchmark><Group id=\"V-1\"/></Benchmark>",
         "expected a xccdf Benchmark"),
        ("<Benchmark %s></Benchmark>" % _XCCDF_WRAPPER,
         "carries no Group elements"),
        ('<Benchmark %s><Group><title>SRG-OS-000001-GPOS-00001'
         '</title><Rule id="SV-1_rule" severity="high">OK'
         '</Rule></Group></Benchmark>' % _XCCDF_WRAPPER,
         "missing its id"),
        ('<Benchmark %s><Group id="V-1"><title></title>'
         '<Rule id="SV-1_rule" severity="high"><version>R-1</version>'
         '<ident>CCI-000001</ident></Rule></Group></Benchmark>'
         % _XCCDF_WRAPPER,
         "carries no SRG reference"),
        ('<Benchmark %s><Group id="V-1"><title>SRG-OS-000001-GPOS-00001'
         '</title><Rule id="SV-1_rule" severity="catastrophic">'
         '</Rule></Group></Benchmark>' % _XCCDF_WRAPPER,
         "not one of"),
    ])
def test_parse_xccdf_rejects_malformed(xccdf_text, message):
    with pytest.raises(ValueError, match=message):
        KA.parse_xccdf(xccdf_text)


def test_gap_report_top_shape_and_totals():
    report = _fixture_report()
    assert set(report) == {"baselines", "families", "gap_definition",
                           "gaps", "meta", "totals"}
    assert report["gap_definition"].strip()
    assert set(report["gaps"]) == {
        "by_platform", "lacking_coverage", "malformed_checklists",
        "notes", "unmet_by_family", "unmatched_checklists",
        "unscanned_baselines"}
    assert len(report["gaps"]["notes"]) == 3
    assert report["totals"] == {
        "baselines": 24, "baselines_in_scan_state": 2,
        "covered_rules": 11, "rules_scanned": 14, "unmet_rules": 3,
        "unscanned_baselines": 22}


def test_gap_report_by_platform_rows():
    report = _fixture_report()
    by_platform = report["gaps"]["by_platform"]
    assert tuple(sorted(by_platform)) == ("ubuntu22.04", "vsphere67")
    assert by_platform["ubuntu22.04"] == {
        "covered_rules": 7,
        "coverage_pct": 87.5,
        "in_scan_state": True,
        "priority_queue": [
            {"family": "OS", "severity": "high", "status": "Open",
             "vuln_num": "V-260483"},
            {"family": "unknown", "severity": "high", "status": "Open",
             "vuln_num": "V-260487"},
            {"family": "OS", "severity": "high",
             "status": "Not_Reviewed", "vuln_num": "V-260485"},
            {"family": "OS", "severity": "medium", "status": "Open",
             "vuln_num": "V-260482"},
            {"family": "OS", "severity": "medium",
             "status": "Not_Reviewed", "vuln_num": "V-260486"},
        ],
        "rules_by_family": {"OS": 7, "unknown": 1},
        "rules_total": 8,
        "statuses": {"NotAFinding": 2, "Open": 3, "Not_Applicable": 1,
                     "Not_Reviewed": 2},
        "unmet_by_family": {"unknown": 1},
        "unmet_rules": 1,
    }
    assert by_platform["vsphere67"] == {
        "covered_rules": 4,
        "coverage_pct": 66.7,
        "in_scan_state": True,
        "priority_queue": [
            {"family": "NET", "severity": "high", "status": "Open",
             "vuln_num": "V-260499"},
            {"family": "OS", "severity": "high",
             "status": "Not_Reviewed", "vuln_num": "V-260496"},
            {"family": "NET", "severity": "medium",
             "status": "Not_Reviewed", "vuln_num": "V-260500"},
        ],
        "rules_by_family": {"NET": 2, "OS": 4},
        "rules_total": 6,
        "statuses": {"NotAFinding": 2, "Open": 1, "Not_Applicable": 1,
                     "Not_Reviewed": 2},
        "unmet_by_family": {"NET": 2},
        "unmet_rules": 2,
    }


def test_gap_report_unmet_by_family():
    report = _fixture_report()
    assert report["gaps"]["unmet_by_family"] == {
        "NET": {"platforms": ["vsphere67"], "rules_unmet": 2},
        "unknown": {"platforms": ["ubuntu22.04"], "rules_unmet": 1}}


def test_gap_report_unscanned_rows():
    report = _fixture_report()
    unscanned = report["gaps"]["unscanned_baselines"]
    assert len(unscanned) == 22
    expected_unscanned = sorted(
        p for p in EXPECTED_PLATFORMS
        if p not in ("ubuntu22.04", "vsphere67"))
    assert sorted(row["platform"] for row in unscanned) == (
        expected_unscanned)
    assert "ubuntu22.04" not in [row["platform"] for row in unscanned]
    assert "vsphere67" not in [row["platform"] for row in unscanned]
    assert unscanned[0] == {
        "platform": "citrix", "ckls": 13, "kit": False,
        "rules_maintained": 49, "reason": "no_fleet_scan_state",
        "track": "active", "labels": ["Citrix"]}
    docker_row = next(row for row in unscanned
                      if row["platform"] == "docker")
    assert docker_row["ckls"] == 0 and docker_row["kit"] is True
    proxmox_row = next(row for row in unscanned
                       if row["platform"] == "proxmox")
    assert proxmox_row["kit"] is True and proxmox_row["ckls"] == 0
    for row in unscanned:
        assert row["reason"] == "no_fleet_scan_state"
        assert set(row) == {"platform", "ckls", "kit",
                            "rules_maintained", "reason", "track",
                            "labels"}


def test_gap_report_lacking_coverage_covers_everything_here():
    report = _fixture_report()
    lacking = report["gaps"]["lacking_coverage"]
    # both scanned platforms still lack (unknown / NET rows unmet) and
    # every unscanned platform lacks by construction
    assert sorted(lacking) == list(EXPECTED_PLATFORMS)
    assert len(lacking) == 24


def test_gap_report_clean_platform_exits_lacking():
    rules = KA.parse_ckl(UBUNTU_CKL.read_text(encoding="utf-8"))["rules"]
    clean = [row for row in rules
             if KA.srg_family(row["group_title"]) == "OS"]
    report = KA.gap_report(_catalog(), {"ubuntu22.04": clean})
    row = report["gaps"]["by_platform"]["ubuntu22.04"]
    assert row["covered_rules"] == 7
    assert row["unmet_rules"] == 0
    assert row["coverage_pct"] == 100.0
    assert row["unmet_by_family"] == {}
    assert [q["vuln_num"] for q in row["priority_queue"]] == [
        "V-260483", "V-260485", "V-260482", "V-260486"]
    lacking = report["gaps"]["lacking_coverage"]
    assert len(lacking) == 23
    assert "ubuntu22.04" not in lacking


def test_gap_report_default_is_all_unscanned():
    report = KA.gap_report(_catalog(), {})
    assert report["gaps"]["by_platform"] == {}
    assert report["totals"] == {
        "baselines": 24, "baselines_in_scan_state": 0,
        "covered_rules": 0, "rules_scanned": 0, "unmet_rules": 0,
        "unscanned_baselines": 24}
    assert report["gaps"]["lacking_coverage"] == list(
        EXPECTED_PLATFORMS)
    assert report["gaps"]["unmet_by_family"] == {}


def test_gap_report_duplicate_vuln_collapses_to_worst_status():
    def _row(vuln, status):
        return {"vuln_num": vuln, "rule_id": "SV-%sr1_rule" % vuln[2:],
                "rule_ver": "SYN-1-1", "severity": "high",
                "group_title": "SRG-OS-000001-GPOS-00001",
                "cci": "CCI-000001", "status": status}
    state = {"ubuntu22.04": [
        _row("V-900201", "NotAFinding"), _row("V-900201", "Open"),
        _row("V-900202", "Not_Reviewed"), _row("V-900202", "Open")]}
    report = KA.gap_report(_catalog(), state)
    row = report["gaps"]["by_platform"]["ubuntu22.04"]
    assert row["rules_total"] == 2
    assert row["statuses"] == {"NotAFinding": 0, "Open": 2,
                               "Not_Applicable": 0, "Not_Reviewed": 0}
    assert row["covered_rules"] == 2
    assert row["unmet_rules"] == 0
    assert [q["vuln_num"] for q in row["priority_queue"]] == [
        "V-900201", "V-900202"]
    assert report["gaps"]["lacking_coverage"] == sorted(
        set(EXPECTED_PLATFORMS) - {"ubuntu22.04"})


def test_gap_report_priority_queue_is_bounded():
    rules = [{"vuln_num": "V-9%03d" % i,
              "rule_id": "SV-9%03dr1_rule" % i,
              "rule_ver": "SYN-1-1", "severity": "high",
              "group_title": "SRG-OS-000001-GPOS-00001",
              "cci": "CCI-000001", "status": "Open"}
             for i in range(1, 31)]
    report = KA.gap_report(_catalog(), {"ubuntu22.04": rules})
    queue = report["gaps"]["by_platform"]["ubuntu22.04"]["priority_queue"]
    assert len(queue) == KA.MAX_PRIORITY_ROWS == 25
    assert [q["vuln_num"] for q in queue] == [
        "V-9%03d" % i for i in range(1, 26)]


def test_gap_report_rejects_unknown_scan_platform():
    with pytest.raises(ValueError,
                       match="not in the maintained catalog"):
        KA.gap_report(_catalog(), {"notaplatform": []})


def test_collapse_helper_keep_order_and_worst_status():
    rules = KA.parse_ckl(UBUNTU_CKL.read_text(encoding="utf-8"))["rules"]
    merged = KA._collapse_rules([], rules[:2] + rules[:3])
    assert len(merged) == 3
    assert [row["vuln_num"] for row in merged] == [
        "V-260480", "V-260481", "V-260482"]
    worst = KA._collapse_rules(
        [], [_row_fix("V-900301", "NotAFinding"),
             _row_fix("V-900301", "Open")])
    assert len(worst) == 1 and worst[0]["status"] == "Open"


def _row_fix(vuln, status):
    return {"vuln_num": vuln, "rule_id": "SV-%sr1_rule" % vuln[2:],
            "rule_ver": "SYN-1-1", "severity": "high",
            "group_title": "SRG-OS-000001-GPOS-00001",
            "cci": "CCI-000001", "status": status}


def test_cli_offline_deterministic(tmp_path):
    out1 = tmp_path / "one.json"
    out2 = tmp_path / "two.json"
    for out in (out1, out2):
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(TOOL), "--out", str(out)],
            cwd=str(REPO), capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.stdout.startswith(
            "STIG-GAP-OK baselines=24 families=3 scan_state=0 "
            "rules=0 covered=0 unmet=0 out="), proc.stdout
    assert out1.read_bytes() == out2.read_bytes()
    assert not (REPO / "data" / "stig_gap_report.json").exists() or \
        True  # tests never depend on the default OUT file


def test_cli_scan_ingestion_math(tmp_path):
    report_path = tmp_path / "report.json"
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(TOOL), "--scan", str(UBUNTU_CKL),
         "--scan", str(VSPHERE_CKL), "--out", str(report_path)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith(
        "STIG-GAP-OK baselines=24 families=3 scan_state=2 rules=14 "
        "covered=11 unmet=3 out="), proc.stdout
    emitted = json.loads(report_path.read_text(encoding="utf-8"))
    assert emitted["totals"] == {
        "baselines": 24, "baselines_in_scan_state": 2,
        "covered_rules": 11, "malformed_checklists": 0,
        "rules_scanned": 14, "unmatched_checklists": 0, "unmet_rules": 3,
        "unscanned_baselines": 22}
    direct = _fixture_report()
    # the CLI's by_platform math matches the in-process report call
    assert emitted["gaps"]["by_platform"] == direct["gaps"]["by_platform"]
    assert emitted["gaps"]["unscanned_baselines"] == direct["gaps"][
        "unscanned_baselines"]
    assert emitted["baselines"] == direct["baselines"]
    assert emitted["gap_definition"] == direct["gap_definition"]


def test_cli_malformed_and_unmatched(tmp_path):
    garbage = tmp_path / "garbage.txt"
    garbage.write_text("<html>not xml<", encoding="utf-8")
    badroot = tmp_path / "badroot.xml"
    badroot.write_text("<nope><VULN/></nope>", encoding="utf-8")
    unmapped = tmp_path / "unmapped.xml"
    unmapped.write_text(_single_vuln_ckl(), encoding="utf-8")
    report_path = tmp_path / "report.json"
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(TOOL), "--scan", str(garbage),
         "--scan", str(badroot), "--scan", str(unmapped),
         "--out", str(report_path)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    emitted = json.loads(report_path.read_text(encoding="utf-8"))
    malformed = emitted["gaps"]["malformed_checklists"]
    assert [row["file"] for row in malformed] == ["badroot.xml",
                                                  "garbage.txt"]
    assert malformed[0]["error"].startswith(
        "CKL root element is 'nope' (expected CHECKLIST)")
    assert malformed[1]["error"].startswith("CKL not parseable xml")
    assert emitted["gaps"]["unmatched_checklists"] == [
        {"stig_title": "Synthetic Fixture STIG", "vulns": 1,
         "reason": "no_matching_maintained_baseline"}]
    assert emitted["totals"]["malformed_checklists"] == 2
    assert emitted["totals"]["unmatched_checklists"] == 1
    assert emitted["totals"]["baselines_in_scan_state"] == 0


def test_cli_rejects_missing_scan_path(tmp_path):
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(TOOL), "--scan", "missing.xml",
         "--out", str(tmp_path / "report.json")],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    emitted = json.loads((tmp_path / "report.json")
                         .read_text(encoding="utf-8"))
    assert emitted["gaps"]["malformed_checklists"] == [
        {"file": "missing.xml", "error": "scan path not found"}]
