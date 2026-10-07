"""KA-080 - the appliance corpus: the data/appliance_cves.json
sha snapshot (the drift alarm on hand-edits), the four-family shape and
counted totals matching the corpus meta, the per-row pending-review
proposal contract aligned with KA-029's rows (scripts/ka/
cve_db_propose.py) plus exactly the family + lab_only keys, the
per-row lab-only flagging (OPT-80: appliances are lab-test material),
reference hygiene (https, >=1, <=2, unique-in-row, the NVD anchor last,
known hosts only), the payload/dead-link scans, the offline builder
re-running green and byte-identical with the live mode staying opt-in,
and the appliance matcher exercised with live-derived examples plus
the guard-corpus hostile values (ValueError-or-clean; no network
anywhere - the live check belongs to the builder only)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data" / "appliance_cves.json"
SCRIPT = REPO / "tools" / "build_appliance_corpus.py"
KA029_SCRIPT = REPO / "scripts" / "ka" / "cve_db_propose.py"
GUARD = (REPO / "tests" / "fixtures" / "guard_corpus"
         / "hostile_inputs.json")

DATA_SHA = "1dac5209bae4ed74fe44e086127400ba7c3213daf32da5e3130224082c7121e3"

EXPECTED_FAMILIES = ("citrix", "f5", "ivanti", "vmware-vsphere")
EXPECTED_COUNTS = {"citrix": 8, "f5": 6, "ivanti": 10,
                   "vmware-vsphere": 8}
EXPECTED_TOTALS = {"families": 4, "proposals": 32}
EXPECTED_META_KEYS = ["families_doc", "kev_feed", "lab_only", "policy",
                      "source", "totals", "urls_verified"]

# the KA-029 row contract plus exactly these two appliance keys
EXTRA_ROW_KEYS = {"family", "lab_only"}

SOURCE_LABEL = "cisa-kev-appliance"
BUILD_DATE = "2026-10-06"
KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")

NVD_ANCHOR = "https://nvd.nist.gov/vuln/detail/%s"
EXPECTED_REFERENCE_HOSTS = {"nvd.nist.gov", "www.vmware.com",
                            "support.broadcom.com", "www.citrix.com",
                            "support.citrix.com", "my.f5.com",
                            "forums.ivanti.com"}

# payload/hostile/exploit strings that must never leak into the corpus
# (proposal data: names + labels + reference links only)
FORBIDDEN_STRINGS = (
    "<script", "javascript:", "onerror=", "onload=", "union select",
    "drop table", "select *", "base64", "/etc/passwd", "whoami",
    "bash -c", "nc -e", "import subprocess", "os.system", "eval(",
    "exec(", "system(", "curl", "wget", "hydra", "sqlmap", "metasploit",
    "password", "secret_", "| ", "&& ", "%27", "%3c",
)

# dead-link markers: dropped candidates are documented in the builder's
# docstring only - the committed data carries none of these
DEAD_LINK_MARKERS = (
    "dead", "404", "403", "unavailable", "no longer", "removed",
    "dropped", "unreachable",
)


def _load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def _rows() -> list:
    data = _load()
    return [row for entry in data["families"].values()
            for row in entry["proposals"]]


def _load_tool_module():
    spec = importlib.util.spec_from_file_location("ka080_tool", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("ka080_tool", module)
    spec.loader.exec_module(module)
    return module


def _load_ka029_module():
    spec = importlib.util.spec_from_file_location("ka029_cve_db_propose",
                                                  str(KA029_SCRIPT))
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("ka029_cve_db_propose", module)
    spec.loader.exec_module(module)
    return module


def test_corpus_sha_unchanged():
    assert hashlib.sha256(DATA.read_bytes()).hexdigest() == DATA_SHA


def test_data_shape_top_keys_and_family_set():
    data = _load()
    assert sorted(data) == ["families", "meta"]
    assert tuple(sorted(data["families"])) == EXPECTED_FAMILIES
    assert sorted(data["meta"]) == EXPECTED_META_KEYS
    assert data["meta"]["kev_feed"] == KEV_FEED_URL


def test_proposal_row_schema_is_ka029_plus_appliance_keys():
    contract = sorted(_load_ka029_module().build_proposals(
        [{"cve": "CVE-2026-0001", "dateAdded": "2026-10-01",
          "vendor": "V", "product": "P", "name": "N",
          "note": "https://example.com/a"}],
        __import__("datetime").date(2026, 10, 1))[0][0])
    for row in _rows():
        assert sorted(row) == sorted(contract + sorted(EXTRA_ROW_KEYS)), \
            (sorted(row), contract)
        for key in contract:
            assert key in row, (key, row["cve"])


def test_rows_carry_queue_contract_values_and_lab_only():
    data = _load()
    assert data["meta"]["lab_only"] is True
    for row in _rows():
        assert row["status"] == "pending-review", row["cve"]
        assert row["review_decision"] is None, row["cve"]
        assert row["source"] == SOURCE_LABEL, row["cve"]
        assert row["proposed_at"] == BUILD_DATE, row["cve"]
        assert row["lab_only"] is True, row["cve"]


def test_counts_match_meta_totals():
    data = _load()
    for family, entry in data["families"].items():
        assert len(entry["proposals"]) == EXPECTED_COUNTS[family], family
    assert data["meta"]["totals"] == EXPECTED_TOTALS
    assert sum(sorted(EXPECTED_COUNTS.values())) == \
        EXPECTED_TOTALS["proposals"]
    assert len(_rows()) == EXPECTED_TOTALS["proposals"]


def test_cves_unique_wellformed_dates_valid():
    cves = [row["cve"] for row in _rows()]
    assert len(cves) == len(set(cves)) == EXPECTED_TOTALS["proposals"]
    for row in _rows():
        assert re.fullmatch(r"CVE-\d{4}-\d+", row["cve"]), row["cve"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["dateAdded"])
        year, month, day = (int(part)
                            for part in row["dateAdded"].split("-"))
        assert 2000 <= year <= 2026 and 1 <= month <= 12 and 1 <= day <= 31
        for field in ("vendor", "product", "name"):
            value = row[field]
            assert isinstance(value, str) and value == value.strip(), row
            assert all(ord(ch) >= 32 and ord(ch) < 0x2000 for ch in value)


def test_member_rows_match_their_family_bucket():
    data = _load()
    for family, entry in data["families"].items():
        for row in entry["proposals"]:
            assert row["family"] == family, row["cve"]


def test_references_shape_hosts_and_nvd_anchor():
    data = _load()
    for entry in data["families"].values():
        for row in entry["proposals"]:
            refs = row["references"]
            assert 1 <= len(refs) <= 2, (row["cve"], refs)
            assert len(set(refs)) == len(refs), (row["cve"], refs)
            for url in refs:
                assert url.startswith("https://"), (row["cve"], url)
                assert not any(c.isspace() for c in url), url
                assert urlsplit(url).netloc in EXPECTED_REFERENCE_HOSTS, \
                    (row["cve"], url)
            assert refs[-1] == NVD_ANCHOR % row["cve"], (row["cve"], refs)


def _scannable_text() -> str:
    """The data text for the leak scans, with CVE-id digits masked -
    '404'/'403' legitimately occur inside ids (e.g. CVE-2023-34048);
    as prose markers they still apply everywhere else."""
    text = DATA.read_text(encoding="utf-8").lower()
    return re.sub(r"cve-\d{4}-\d+", "cve-xxxx-xxxxx", text)


def test_no_payload_strings():
    text = DATA.read_text(encoding="utf-8").lower()
    for needle in FORBIDDEN_STRINGS:
        assert needle not in text, needle


def test_no_dead_link_markers():
    text = _scannable_text()
    for marker in DEAD_LINK_MARKERS:
        assert marker not in text, marker


def test_meta_claims_present():
    data = _load()
    meta = data["meta"]
    for prose in (meta["source"], meta["policy"], meta["families_doc"]):
        assert isinstance(prose, str) and prose.strip(), prose
    assert "review" in meta["policy"].lower()
    assert "lab" in meta["policy"].lower()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["urls_verified"]), \
        meta["urls_verified"]
    assert meta["urls_verified"] == BUILD_DATE


def test_builder_offline_deterministic():
    before = DATA.read_bytes()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(SCRIPT)], cwd=str(REPO),
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "APPLIANCE-CORPUS-OK families=4 proposals=32" in proc.stdout, \
        proc.stdout
    assert DATA.read_bytes() == before, "builder rewrite is not byte-stable"


def test_live_mode_is_optin_only():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--live" in source
    # planner/catalog purity: no execution markers anywhere in the builder
    for marker in ("subprocess", "os.system", "eval("):
        assert marker not in source, marker
    # the offline module part (before the lazy network import) never
    # mentions a network client; urllib imports stay lazy inside the
    # live-check helpers, exactly once
    offline_part = source.split("def _polite_get", 1)[0]
    assert offline_part.strip(), "network helpers moved?"
    for needle in ("urllib", "requests", "http.client"):
        assert needle not in offline_part, needle
    assert source.count("import urllib.request") == 1


@pytest.mark.parametrize(
    "vendor,product,expected",
    [
        ("VMware", "vCenter Server", "vmware-vsphere"),
        ("VMware", "ESXi", "vmware-vsphere"),
        ("VMware", "ESXi, Workstation, and Fusion", "vmware-vsphere"),
        # OPT-80 names vCenter/ESXi only: other VMware lines stay out
        ("VMware", "Workspace ONE Access", None),
        ("VMware", "VMware Tools", None),
        ("Citrix", "NetScaler ADC and NetScaler Gateway", "citrix"),
        ("Citrix", "Application Delivery Controller (ADC), Gateway, "
         "and SD-WAN WANOP Appliance", "citrix"),
        ("Citrix", "ShareFile", "citrix"),
        ("F5", "BIG-IP", "f5"),
        ("F5", "BIG-IP and BIG-IQ Centralized Management", "f5"),
        ("Ivanti", "Connect Secure, Policy Secure", "ivanti"),
        ("Ivanti", "Endpoint Manager Mobile (EPMM)", "ivanti"),
        ("Ivanti", "Cloud Services Appliance (CSA)", "ivanti"),
        ("Pulse Secure", "Pulse Connect Secure", "ivanti"),
        ("Apache", "HTTP Server", None),
        # the ivanti/pulse legs are vendor-based: any product string
        # counts (KEV rows always carry product labels)
        ("Ivanti", "", "ivanti"),
    ],
)
def test_appliance_matcher_live_examples(vendor, product, expected):
    tool = _load_tool_module()
    assert tool.appliance_family(vendor, product) == expected


def test_matcher_hostile_inputs_valueerror_or_clean():
    """Guard-corpus sweeps through the matcher: string inputs land
    clean (None or a family); only type errors may raise, and only as
    ValueError - never any other exception."""
    tool = _load_tool_module()
    corpus = json.loads(GUARD.read_text(encoding="utf-8"))
    for case in corpus["inputs"]:
        value = case["value"]
        assert isinstance(value, str)
        try:
            result = tool.appliance_family(value, "vCenter Server")
        except ValueError as exc:
            assert str(exc) == "vendor must be a string", (case["id"], exc)
            continue
        assert result in (None,) + EXPECTED_FAMILIES, (case["id"], result)
        try:
            result = tool.appliance_family("f5", value)
        except ValueError:
            continue
        assert result in (None, "f5"), (case["id"], result)
    for non_string in (None, 7, {"k": 1}, ["v"]):
        with pytest.raises(ValueError):
            tool.appliance_family(non_string, "x")
    with pytest.raises(ValueError):
        tool.appliance_family("f5", 1)


def _proposal_of(tool, row):
    return tool.build_proposal("ivanti", row)


def test_build_proposal_hostile_or_malformed_rows_rejected():
    tool = _load_tool_module()
    base = {"cve": "CVE-2024-21887", "dateAdded": "2024-01-10",
            "vendor": "Ivanti", "product": "Connect Secure, Policy Secure",
            "name": "Command Injection Vulnerability",
            "references": ["https://example.com/advisory",
                           "https://nvd.nist.gov/vuln/detail/CVE-2024-21887"]}
    good = _proposal_of(tool, base)
    assert sorted(good) == sorted(_rows()[0])
    assert good["references"][0] == "https://example.com/advisory"

    corpus = json.loads(GUARD.read_text(encoding="utf-8"))
    for case in corpus["inputs"]:
        poisoned = dict(base, name=case["value"])
        try:
            _proposal_of(tool, poisoned)
        except ValueError:
            pass  # clean rejection is a fine answer
        # the raw string survives a clean sweep: no other exception class
    for mutated in (
        dict(base, cve="NOT-A-CVE"),
        dict(base, cve="cve-2024-21887"),
        dict(base, dateAdded="2024-13-10"),
        dict(base, dateAdded="not-a-date"),
        dict(base, references=[]),
        dict(base, references=["http://example.com/a"]),
        dict(base, references=["https://example.com/advisory",
                               "https://example.com/advisory"]),
        dict(base, vendor="Apache"),
        dict(base, name=None),
        {k: v for k, v in base.items() if k != "name"},
    ):
        with pytest.raises(ValueError):
            _proposal_of(tool, mutated)
    with pytest.raises(ValueError):
        tool.build_proposal("f5", base)  # family/bucket mismatch


def test_build_proposal_oversize_accepts_clean():
    tool = _load_tool_module()
    row = {"cve": "CVE-2021-21972", "dateAdded": "2021-11-03",
           "vendor": "VMware", "product": "vCenter Server",
           "name": "V" * 60000,
           "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"]}
    proposal = tool.build_proposal("vmware-vsphere", row)
    assert len(proposal["name"]) == 60000  # no length bound (guard finding)
    assert proposal["lab_only"] is True and proposal["status"] == \
        "pending-review"
