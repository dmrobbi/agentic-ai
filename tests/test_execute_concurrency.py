"""KA-016 - concurrency soak: 8 parallel threads against a real
KaliAgent. The dry-run batch proves job_lock exactness (the counter
returns to zero under contention, no exceptions, all runs complete); the
slow real-path batch proves max_concurrent_jobs is a real ceiling (8
threads > 5 cap: capped failures are expected and correct, the recorded
counter never exceeds the cap, nothing deadlocks). pytest-timeout is not
installed here - the bounds are the test's own explicit join deadlines,
documented. No network; the real path stubs the subprocess layer."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent

BENIGN_TARGET = "192.0.2.1"
THREADS = 8
JOIN_SECONDS = 90
CAP = 5


@pytest.fixture()
def dry_agent(tmp_path):
    agent = KaliAgent(agent_id="ka016-soak", workspace=str(tmp_path / "ws"),
                      log_dir=str(tmp_path / "logs"))
    agent.set_authorization(AuthorizationLevel.BASIC)
    agent.enable_dry_run()
    return agent


def _run_batch(agent, runs, out_executions, errors):
    for _ in range(runs):
        try:
            out_executions.append(agent.execute_tool(
                "nmap", {"target": BENIGN_TARGET}))
        except Exception as exc:
            errors.append(exc)


def test_dry_run_batch_concurrency(dry_agent):
    """8 threads x 5 dry runs: zero errors, all completed, the counter
    exact (0 at the end). The threads start through a barrier so the lock
    contention is real."""
    results, errors = [], []
    barrier = threading.Barrier(THREADS)

    def worker():
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:  # pragma: no cover
            errors.append("barrier broken")
            return
        _run_batch(dry_agent, 5, results, errors)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + JOIN_SECONDS
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    assert all(not t.is_alive() for t in threads), "soak deadlocked"
    assert errors == [], errors[:3]
    assert len(results) == THREADS * 5
    assert all(ex.status == "completed" for ex in results)
    assert dry_agent.current_jobs == 0
    assert len(dry_agent.executions) == THREADS * 5  # ids stayed unique


def test_slow_execution_respects_cap(tmp_path, monkeypatch):
    """The real path with a slowed process layer: cap failures EXPECTED
    for late threads (8 > 5); the counter never exceeds CAP anywhere; the
    final counter = 0; no deadlock."""
    import agentic_ai.agents.cyber.kali as kali_mod

    class _FakeTimeoutExpired(Exception):
        pass

    def stub_subprocess(monkeypatch, rc=0):
        calls = []

        class _Proc:
            def __init__(self, cmd_args):
                self.killed = False
                self.returncode = rc

            def communicate(self, timeout=None):
                time.sleep(0.06)  # widen the contention window
                return b"ok", b""

            def kill(self):
                self.killed = True

        def ctor(cmd_args, **kwargs):
            _Proc_instance = _Proc(cmd_args)
            calls.append(list(cmd_args))
            return _Proc_instance

        stub = SimpleNamespace(Popen=ctor, TimeoutExpired=_FakeTimeoutExpired,
                               PIPE=None, STDOUT=None, DEVNULL=None)
        monkeypatch.setattr("agentic_ai.agents.cyber.kali.subprocess", stub)
        return calls

    stub_subprocess(monkeypatch)

    agent = KaliAgent(agent_id="ka016-cap", workspace=str(tmp_path / "ws2"),
                      log_dir=str(tmp_path / "logs2"))
    agent.set_authorization(AuthorizationLevel.BASIC)
    agent.disable_dry_run()

    recorded_jobs = []
    method_lock = threading.Lock()
    orig = KaliAgent._execute_command

    def recording_execute(self, execution, timeout):
        with self.job_lock:
            recorded_jobs.append(self.current_jobs)
        return orig(self, execution, timeout)

    monkeypatch.setattr(KaliAgent, "_execute_command", recording_execute)

    results, errors = [], []
    barrier = threading.Barrier(THREADS)

    def worker():
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:  # pragma: no cover
            errors.append("barrier broken")
            return
        _run_batch(agent, 3, results, errors)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + JOIN_SECONDS
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    assert all(not t.is_alive() for t in threads), "cap soak deadlocked"
    assert errors == [], errors[:3]
    assert len(results) == THREADS * 3

    cap_failed = [ex for ex in results
                  if ex.status == "failed"
                  and "Maximum concurrent jobs reached" in ex.stderr]
    completed = [ex for ex in results if ex.status == "completed"]
    assert len(cap_failed) >= 1, "8 threads > cap 5: some must cap"
    assert len(completed) + len(cap_failed) == len(results)
    assert max(recorded_jobs) <= CAP, max(recorded_jobs)
    assert agent.current_jobs == 0, agent.current_jobs
    # every capped execution carries the exact stderr message, once
    assert all(ex.stderr == "Maximum concurrent jobs reached"
               for ex in cap_failed)
