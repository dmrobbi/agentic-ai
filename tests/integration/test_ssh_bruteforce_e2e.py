"""End-to-end integration test for the Wazuh → SOC pipeline.

Fires real bad-password SSH attempts at a Wazuh-monitored host, waits for the
resulting brute-force correlation alert (rule 5551 or 5763, level >= 10) to
land in the OpenSearch indexer, then feeds it through the
SecurityOperationsAgent and asserts:

  1. The Wazuh alert is reachable via the indexer
  2. The SOC ingests it as a SecurityAlert
  3. A level>=10 alert auto-creates an IncidentReport (the auto-escalate path)

This is an OPT-IN integration test (skipped by default). It requires:
  - Wazuh manager + indexer reachable (manager-host:55000 / 9200)
  - A target host monitored by Wazuh that accepts password auth
  - sshpass installed on this host
  - The Wazuh agent on the target must be able to read journald/auth.log

Run with (opt-in):
  BRUTEFORCE_E2E=1 pytest tests/integration/test_ssh_bruteforce_e2e.py -v
  BRUTEFORCE_E2E=1 pytest tests/integration/test_ssh_bruteforce_e2e.py -v -k bruteforce

Or drive the underlying script directly for more control over timeouts:
  python3 scripts/soc/benign_ssh_bruteforce_test.py --attempts 12 --timeout 120

Skip reasons (printed as the pytest skip message):
  - BRUTEFORCE_E2E not set to 1  -> not opted in (default)
  - sshpass not installed
  - Wazuh indexer unreachable
  - ssh cannot reach target
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so we can import agentic_ai modules
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "scripts" / "soc" / "benign_ssh_bruteforce_test.py"


def _opted_out() -> bool:
    # Opt-in only: run when BRUTEFORCE_E2E is exactly "1"; skip otherwise
    # (unset, 0, or any other value). The default is skip, matching the
    # docstring: this fires real SSH attempts at a LAN host.
    return os.environ.get("BRUTEFORCE_E2E") != "1"


def _sshpass_available() -> bool:
    return shutil.which("sshpass") is not None


def _indexer_reachable(host: str = "127.0.0.1", port: int = 9200, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ssh_target_reachable(target: str, timeout: float = 3.0) -> bool:
    """Can we even TCP-connect to sshd on `target`? (without auth)"""
    try:
        with socket.create_connection((target, 22), timeout=timeout):
            return True
    except OSError:
        return False


# Pytest skip conditions (eval'd at collection time)
pytestmark = pytest.mark.skipif(
    _opted_out(),
    reason="BRUTEFORCE_E2E!=1 (opt-in: set BRUTEFORCE_E2E=1 to run)",
)


@pytest.fixture(scope="module")
def _preflight():
    """Verify all prerequisites before letting the test fire."""
    if not _sshpass_available():
        pytest.skip("sshpass not installed (apt-get install -y sshpass)")
    if not _indexer_reachable():
        pytest.skip("Wazuh indexer not reachable at 127.0.0.1:9200")
    target = os.environ.get("BRUTEFORCE_TARGET", "192.0.2.151")
    if not _ssh_target_reachable(target):
        pytest.skip(f"ssh target {target} unreachable")
    return target


def test_bruteforce_end_to_end(_preflight):
    """Drive benign_ssh_bruteforce_test.py end-to-end and assert success.

    We invoke the script as a subprocess rather than reimplementing it
    inline because (a) it already has all the timing/diagnostic logic
    from the manual verification, and (b) future changes to the script
    (e.g. different rule IDs) are exercised here automatically.
    """
    target = _preflight
    timeout = int(os.environ.get("BRUTEFORCE_TIMEOUT", "120"))
    attempts = int(os.environ.get("BRUTEFORCE_ATTEMPTS", "12"))

    proc = subprocess.run(
        [
            sys.executable, str(SCRIPT),
            "--target", target,
            "--attempts", str(attempts),
            "--timeout", str(timeout),
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 60,  # script timeout + buffer for ssh pass attempts
    )
    # Print stdout/stderr regardless so a failure shows context.
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    assert proc.returncode == 0, (
        f"benign_ssh_bruteforce_test.py exited {proc.returncode}.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "[ALL GOOD]" in proc.stdout, (
        f"script ran but did not produce the success marker. "
        f"stdout:\n{proc.stdout}"
    )
    assert "[OK]   ingested: +1 alert(s), +1 incident(s)" in proc.stdout, (
        f"script ran but did not auto-create an incident for the level>=10 "
        f"alert. stdout:\n{proc.stdout}"
    )


def test_bruteforce_script_exists():
    """Sanity: the script we're wrapping actually exists."""
    assert SCRIPT.is_file(), f"missing script: {SCRIPT}"


def test_bruteforce_script_is_executable_help():
    """Sanity: the script's --help works (catches import errors)."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0, f"--help failed: {r.stderr}"
    assert "benign_ssh_bruteforce_test.py" in r.stdout
