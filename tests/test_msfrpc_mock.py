"""KA-004 - MetasploitRPC mocked battery: every RPC call shape pinned
against the committed canned-response fixture via a method-name
requests.post dispatcher; token gates pinned WITHOUT any request (a
strict dispatcher raises if the wire is touched); failure branches
(timeout mode, malformed-JSON mode, opt-in failure bodies) all return
the documented fallbacks. import_nmap reads a REAL local file first
(pinned with a tmp file). No network anywhere."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from agentic_ai.agents.cyber.kali import MetasploitRPC

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "parsers" / "msfrpc_responses.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
RESPONSES = FIXTURE["responses"]
FAILURES = FIXTURE["failure_responses"]


@pytest.fixture()
def dispatcher(monkeypatch):
    """Route requests.post by the payload's method name to the canned
    body. state['mode']: ok | timeout | malformed | strict; methods listed
    in state['use_failure_for'] are served the failure bodies instead."""
    state = {"mode": "ok", "use_failure_for": set(), "calls": []}

    class _Response:
        def __init__(self, body):
            self._body = body

        def json(self):
            if state["mode"] == "malformed":
                raise json.JSONDecodeError("bad", "{}", 0)
            return self._body

    def fake_post(url, json=None, headers=None, timeout=None, **kw):
        call = {"url": url, "method": (json or {}).get("method"),
                "params": (json or {}).get("params"), "timeout": timeout}
        state["calls"].append(call)
        if state["mode"] == "strict":
            raise AssertionError("a request was attempted (mode=strict)")
        if state["mode"] == "timeout":
            raise requests.exceptions.ConnectionError("timed out")
        method = call["method"]
        body_map = FAILURES if method in state["use_failure_for"] else RESPONSES
        if method not in body_map:
            raise AssertionError("no canned response for method: " + str(method))
        return _Response(body_map[method])

    monkeypatch.setattr("requests.post", fake_post)
    return state


def _rpc(token="fake-token-ka004"):
    return MetasploitRPC(host="127.0.0.1", port=55553, token=token)


def test_login_success_stores_token_and_shape(dispatcher):
    rpc = _rpc(token=None)
    assert rpc.login("msf-password") is True
    assert rpc.token == "fake-token-ka004"
    call = dispatcher["calls"][0]
    assert call["url"].endswith("/api/auth/login")
    assert call["method"] == "auth.login"
    assert call["params"] == ["", "msf-password"]


def test_login_failure_keeps_token_none(dispatcher):
    dispatcher["use_failure_for"] = {"auth.login"}
    rpc = _rpc(token=None)
    assert rpc.login("wrong") is False
    assert rpc.token is None


def test_login_timeout_returns_false(dispatcher):
    dispatcher["mode"] = "timeout"
    rpc = _rpc(token=None)
    assert rpc.login("msf-password") is False
    assert rpc.token is None


def test_get_modules_shape_and_filter(dispatcher):
    rpc = _rpc()
    modules = rpc.get_modules()
    assert modules == [
        {"path": "exploit/windows/smb/ms17_010_eternalblue",
         "rank": "excellent"},
        {"path": "exploit/multi/http/log4shell_header_injection",
         "rank": "great"},
        {"path": "exploit/unix/webapp/php_cgi_arg_injection", "rank": "normal"}]
    windows = rpc.get_modules(module_type="windows")
    assert [m["path"] for m in windows] == [
        "exploit/windows/smb/ms17_010_eternalblue"]
    assert rpc.get_modules(module_type="postgresql") == []
    assert dispatcher["calls"][0]["url"].endswith("/api/module/exploits")


def test_execute_exploit_builds_job(dispatcher):
    rpc = _rpc()
    job = rpc.execute_exploit(
        "exploit/windows/smb/ms17_010_eternalblue",
        "windows/x64/meterpreter/reverse_tcp", "192.0.2.10",
        options={"DisableFirewall": True})
    assert job.job_id == "KA004-JOB-1"
    assert job.name == job.module == "exploit/windows/smb/ms17_010_eternalblue"
    assert job.target == "192.0.2.10"
    assert job.payload == "windows/x64/meterpreter/reverse_tcp"
    assert job.status == "running" and job.completed_at is None
    call = dispatcher["calls"][0]
    assert call["url"].endswith("/api/job.create")
    assert call["method"] == "job.create"
    assert call["params"][1]["MODULE"] == "exploit/windows/smb/ms17_010_eternalblue"
    assert call["params"][1]["DisableFirewall"] is True  # the options merged


def test_execute_exploit_failure_body_returns_none(dispatcher):
    dispatcher["use_failure_for"] = {"job.create"}
    rpc = _rpc()
    assert rpc.execute_exploit("e", "p", "192.0.2.1") is None


def test_get_sessions_converts_rows(dispatcher):
    sessions = _rpc().get_sessions()
    assert [s.session_id for s in sessions] == ["1", "2"]
    s1 = sessions[0]
    assert (s1.type, s1.target_host, s1.target_port) == (
        "meterpreter", "192.0.2.10", 445)
    assert s1.exploit_used == "exploit/windows/smb/ms17_010_eternalblue"
    assert s1.payload == "windows/x64/meterpreter/reverse_tcp"
    assert s1.user_context == "NT AUTHORITY\\SYSTEM"
    s2 = sessions[1]
    assert (s2.type, s2.target_host, s2.target_port, s2.user_context) == (
        "shell", "198.51.100.20", 22, None)


def test_session_write_and_filter_params(dispatcher):
    rpc = _rpc()
    out = rpc.session_write("1", "whoami")
    assert out == "whoami: NT AUTHORITY\\SYSTEM"
    host_row = _rpc().get_services(host="192.0.2.10")
    assert host_row == [{"host": "192.0.2.10", "port": 445, "name": "smb",
                         "proto": "tcp"}]
    call = dispatcher["calls"][1]
    assert call["params"] == ["fake-token-ka004", {"address": "192.0.2.10"}]


def test_db_rows_return_canned_shapes(dispatcher, tmp_path):
    rpc = _rpc()
    assert rpc.get_hosts() == [{"host": "192.0.2.10", "os_name": "Windows",
                                "os_lang": "en-US"}]
    assert rpc.get_vulns() == [{"host": "192.0.2.10", "name": "CVE-2017-0144",
                                "refs": ["CVE-2017-0144"]}]
    assert rpc.get_creds() == [{"user": "jroberts", "pass": "Winter2026!",
                                "host": "192.0.2.10"}]
    assert rpc.get_loots() == [{"host": "192.0.2.10", "type": "file",
                                "data": "C:\\users\\flag.txt"}]
    # import_nmap reads a REAL local file before the POST (pinned):
    nmap_file = tmp_path / "scan.xml"
    nmap_file.write_text("<nmaprun/>")  # the content is opaque to the RPC
    assert rpc.import_nmap(str(nmap_file)) is True


def test_malformed_and_timeout_fallbacks(dispatcher):
    dispatcher["mode"] = "malformed"
    rpc = _rpc()
    assert rpc.get_modules() == []
    assert rpc.get_sessions() == []
    assert rpc.session_write("1", "c") == ""
    assert rpc.get_hosts() == []
    assert rpc.execute_exploit("e", "p", "t") is None
    dispatcher["mode"] = "timeout"
    assert rpc.get_hosts() == []
    assert rpc.session_write("1", "c") == ""
    assert rpc.logout() is False  # narrow catches cover requests errors


def test_no_token_never_touches_the_wire(dispatcher):
    dispatcher["mode"] = "strict"  # any post call = AssertionError
    rpc = _rpc(token=None)
    assert rpc.logout() is False
    assert rpc.get_modules() == []
    assert rpc.execute_exploit("e", "p", "t") is None
    assert rpc.get_sessions() == []
    assert rpc.session_write("1", "c") == ""
    assert rpc.get_hosts() == []
    assert rpc.get_services() == []
    assert rpc.get_vulns() == []
    assert rpc.get_creds() == []
    assert rpc.get_loots() == []
    assert dispatcher["calls"] == []  # the wire was NEVER touched
