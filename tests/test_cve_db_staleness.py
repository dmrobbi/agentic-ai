"""KA-012 - the staleness gate's offline mode runs green (the script
itself, subprocess, no network), the EDB-id partition is pinned as
observed (4 with ids / 2 deliberately None), the derived URLs are
well-formed, and the live mode stays opt-in (the lazy requests import + the --live flag)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agentic_ai.agents.cyber.kali_v2 import CVE_EXPLOIT_DB

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ka" / "cve_db_check.py"

EXPECTED_EDB_IDS = {"CVE-2017-0144": "42315", "CVE-2019-0708": "47266",
                    "CVE-2021-44228": "50666", "CVE-2021-34473": "50287"}
EXPECTED_NONE = {"CVE-2023-44487", "CVE-2024-1709"}


def test_offline_script_runs_green():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CVE-DB-CHECK-OK rows=6" in proc.stdout


def test_edb_id_partition_as_observed():
    with_ids = {c: r.exploit_db_id for c, r in CVE_EXPLOIT_DB.items()
                if r.exploit_db_id}
    assert with_ids == EXPECTED_EDB_IDS
    assert {c for c, r in CVE_EXPLOIT_DB.items()
            if not r.exploit_db_id} == EXPECTED_NONE


def test_derived_urls_wellformed():
    for cve_id, row in CVE_EXPLOIT_DB.items():
        if not row.exploit_db_id:
            continue
        url = "https://www.exploit-db.com/exploits/" + str(row.exploit_db_id)
        assert url.startswith("https://www.exploit-db.com/exploits/")
        assert url.rsplit("/", 1)[1].isdigit()


def test_module_paths_plausible():
    for cve_id, row in CVE_EXPLOIT_DB.items():
        module = row.metasploit_module or ""
        if not module:
            continue
        parts = module.split("/")
        # observed norm: 4 segments (exploit/os/vector/name)
        assert len(parts) == 4 and parts[0] == "exploit", (cve_id, module)


def test_reliability_ranks_dates():
    bands = {"excellent", "great", "good", "normal", "low", "manual"}
    for cve_id, row in CVE_EXPLOIT_DB.items():
        assert row.reliability in bands, (cve_id, row.reliability)
        assert 1 <= row.rank <= 5, cve_id
        try:
            from datetime import date
            date.fromisoformat(row.disclosure_date)
        except ValueError:
            raise AssertionError((cve_id, row.disclosure_date))


def test_live_mode_is_optin_only():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--live" in source
    assert source.count("import requests") == 1  # the lazy live-branch only
    # the offline path is imported-free: requests sits in the live branch
    live_branch = source.split("if args.live", 1)[1]
    offline_part = source.split("import requests", 1)[0]
    assert "import requests" not in offline_part
    assert "requests.get" in live_branch
