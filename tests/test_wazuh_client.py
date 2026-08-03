"""Tests for the WazuhClient + WazuhPoller bridge.

Run with: PYTHONPATH=. pytest tests/test_wazuh_client.py -v
or:       python -m pytest tests/test_wazuh_client.py -v
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from agentic_ai.infrastructure import wazuh_client as wc
from agentic_ai.infrastructure.utils import utcnow


# --------------------------------------------------------------------------- #
# Pure-helper tests (no network, no DB)
# --------------------------------------------------------------------------- #

class MapLevelTests(unittest.TestCase):
    def test_critical_at_13_and_above(self):
        for lvl in (13, 14, 15, 20):
            self.assertEqual(wc.map_level_to_severity(lvl), "critical")

    def test_high_at_10_through_12(self):
        for lvl in (10, 11, 12):
            self.assertEqual(wc.map_level_to_severity(lvl), "high")

    def test_medium_at_7_through_9(self):
        for lvl in (7, 8, 9):
            self.assertEqual(wc.map_level_to_severity(lvl), "medium")

    def test_low_at_4_through_6(self):
        for lvl in (4, 5, 6):
            self.assertEqual(wc.map_level_to_severity(lvl), "low")

    def test_info_below_4(self):
        for lvl in (0, 1, 2, 3):
            self.assertEqual(wc.map_level_to_severity(lvl), "informational")


class AlertIdTests(unittest.TestCase):
    def test_composite_id_uses_timestamp_agent_rule(self):
        a = {"timestamp": "2026-08-03T10:00:00+00:00",
             "agent": {"id": "003"}, "rule": {"id": "5715"}}
        self.assertEqual(wc._alert_id(a), "2026-08-03T10:00:00+00:00|003|5715")

    def test_composite_id_handles_missing_pieces(self):
        a = {"agent": {}, "rule": {}}
        # both ids fall back to empty string, but the function shouldn't crash
        self.assertTrue(wc._alert_id(a))


class AlertToSOCTests(unittest.TestCase):
    def test_full_alert_mapping(self):
        a = {
            "timestamp": "2026-08-03T10:00:00+00:00",
            "agent": {"id": "003", "name": "darth", "ip": "10.0.0.114"},
            "rule": {"id": "5715", "level": 10, "description": "SSHD brute force"},
        }
        kw = wc.alert_to_soc_kwargs(a)
        self.assertEqual(kw["title"], "SSHD brute force")
        self.assertEqual(kw["severity"], "high")
        self.assertEqual(kw["source"], "wazuh")
        self.assertEqual(kw["rule_name"], "5715")
        self.assertEqual(kw["affected_asset"], "darth")
        self.assertEqual(kw["source_ip"], "10.0.0.114")

    def test_loopback_ip_filtered(self):
        a = {"agent": {"id": "000", "name": "wazuh.manager", "ip": "127.0.0.1"},
             "rule": {"id": "1", "level": 3}}
        kw = wc.alert_to_soc_kwargs(a)
        self.assertIsNone(kw["source_ip"])

    def test_minimal_alert(self):
        kw = wc.alert_to_soc_kwargs({"rule": {}, "agent": {}})
        self.assertEqual(kw["severity"], "informational")
        self.assertEqual(kw["source"], "wazuh")


# --------------------------------------------------------------------------- #
# Client tests with mocked HTTP (no real network)
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, body: bytes = b"{}"):
        self._body = body
    def read(self):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class WazuhClientTests(unittest.TestCase):
    def setUp(self):
        self.client = wc.WazuhClient(
            base_url="https://example.test:55000",
            username="alice",
            password="s3cret",
        )

    def _mock_token(self):
        return {"data": {"token": "abc.def.ghi"}}

    def test_authenticate_caches_token(self):
        with patch.object(self.client, "_request", return_value=self._mock_token()) as mreq:
            t1 = self.client.authenticate()
            t2 = self.client.authenticate()
            self.assertEqual(t1.value, "abc.def.ghi")
            self.assertEqual(t2.value, "abc.def.ghi")
            self.assertEqual(mreq.call_count, 1, "second call must hit cache")

    def test_authenticate_refresh_on_expiry(self):
        self.client._token = wc.Token(value="old", expires_at=utcnow() - timedelta(seconds=5))
        with patch.object(self.client, "_request",
                          return_value=self._mock_token()) as mreq:
            t = self.client.authenticate()
            self.assertEqual(t.value, "abc.def.ghi")
            self.assertEqual(mreq.call_count, 1)

    def test_authenticate_force(self):
        self.client._token = wc.Token(value="good", expires_at=utcnow() + timedelta(hours=1))
        with patch.object(self.client, "_request",
                          return_value=self._mock_token()) as mreq:
            t = self.client.authenticate(force=True)
            self.assertEqual(t.value, "abc.def.ghi")
            self.assertEqual(mreq.call_count, 1)

    def test_authenticate_sends_basic_auth_header(self):
        with patch.object(self.client, "_request",
                          return_value=self._mock_token()) as mreq:
            self.client.authenticate()
        # second positional arg or kwargs has 'extra_headers' with Authorization: Basic ...
        args, kwargs = mreq.call_args
        headers = kwargs.get("extra_headers") or {}
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_password_required(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("WAZUH_API_PASSWORD", None)
            with self.assertRaises(wc.WazuhHTTPError):
                wc.WazuhClient(base_url="https://x", username="u", password=None)

    def test_list_alerts_returns_items(self):
        self.client._token = wc.Token(value="tok", expires_at=utcnow() + timedelta(hours=1))
        fake = {"data": {"affected_items": [{"id": 1}, {"id": 2}]}}
        with patch.object(self.client, "_request", return_value=fake) as mreq:
            items = self.client.list_alerts(limit=50)
        self.assertEqual(len(items), 2)
        args, kwargs = mreq.call_args
        self.assertEqual(kwargs.get("params", {}).get("limit"), 50)
        self.assertEqual(kwargs.get("params", {}).get("sort"), "-timestamp")

    def test_manager_info_returns_first_item(self):
        self.client._token = wc.Token(value="tok", expires_at=utcnow() + timedelta(hours=1))
        with patch.object(self.client, "_request",
                          return_value={"data": {"affected_items": [{"version": "v4.14.1"}]}}):
            info = self.client.manager_info()
        self.assertEqual(info.get("version"), "v4.14.1")

    def test_ping_does_not_require_auth(self):
        with patch.object(self.client, "_request") as mreq:
            self.client.ping()
            self.assertFalse(mreq.call_args.kwargs.get("auth", True))

    def test_ping_treats_401_as_healthy(self):
        from agentic_ai.infrastructure.wazuh_client import WazuhHTTPError
        with patch.object(self.client, "_request",
                          side_effect=WazuhHTTPError("HTTP 401 on GET /: ...")):
            self.assertTrue(self.client.ping())


# --------------------------------------------------------------------------- #
# Poller tests with stub client
# --------------------------------------------------------------------------- #

class PollerDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.seen = wc.SeenStore(db_path=self.tmp.name)
        self.cfg = wc.WazuhPollerConfig(
            base_url="https://example.test", username="u", password="p",
            poll_interval_sec=999, page_limit=50,
        )
        # replace client with stub
        self.poller = wc.WazuhPoller(self.cfg, seen_store=self.seen)
        self.poller.client = MagicMock()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _alert(self, ts, agent_id, rule_id):
        return {
            "timestamp": ts,
            "agent": {"id": agent_id, "name": f"agent{agent_id}", "ip": "10.0.0.1"},
            "rule": {"id": rule_id, "level": 10, "description": "test"},
        }

    def test_first_poll_returns_all_alerts(self):
        self.poller.client.list_alerts.return_value = [
            self._alert("2026-08-03T10:00:00Z", "001", "5715"),
            self._alert("2026-08-03T10:00:01Z", "002", "5715"),
        ]
        new = self.poller.fetch_new_alerts()
        self.assertEqual(len(new), 2)

    def test_second_poll_dedupes(self):
        self.poller.client.list_alerts.return_value = [
            self._alert("2026-08-03T10:00:00Z", "001", "5715"),
        ]
        first = self.poller.fetch_new_alerts()
        second = self.poller.fetch_new_alerts()
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0, "same alert should not reappear")

    def test_mixed_old_and_new(self):
        self.poller.client.list_alerts.return_value = [
            self._alert("2026-08-03T10:00:00Z", "001", "5715"),  # seen
            self._alert("2026-08-03T10:01:00Z", "002", "5716"),  # new
        ]
        # seed seen-set
        self.seen.add("2026-08-03T10:00:00Z|001|5715")
        new = self.poller.fetch_new_alerts()
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["agent"]["id"], "002")

    def test_failed_fetch_returns_empty_no_crash(self):
        self.poller.client.list_alerts.side_effect = wc.WazuhHTTPError("boom")
        new = self.poller.fetch_new_alerts()
        self.assertEqual(new, [])

    def test_status_reports_state(self):
        s = self.poller.status()
        self.assertFalse(s["running"])
        self.assertEqual(s["interval_sec"], 999)
        self.assertEqual(s["base_url"], "https://example.test")


# --------------------------------------------------------------------------- #
# Sanity: end-to-end with the live manager (only run if env is set)
# --------------------------------------------------------------------------- #

class LiveIntegrationTests(unittest.TestCase):
    """Skipped unless WAZUH_API_PASSWORD is set in env."""

    @classmethod
    def setUpClass(cls):
        if not os.environ.get("WAZUH_API_PASSWORD"):
            raise unittest.SkipTest("WAZUH_API_PASSWORD not set; skipping live test")

    def test_live_ping(self):
        c = wc.WazuhClient()
        self.assertTrue(c.ping(), "live Wazuh manager should respond")

    def test_live_list_agents(self):
        c = wc.WazuhClient()
        agents = c.list_agents(limit=50)
        self.assertIsInstance(agents, list)
        self.assertGreater(len(agents), 0, "manager should know at least itself (000)")


class WazuhIndexerClientTests(unittest.TestCase):
    def setUp(self):
        self.client = wc.WazuhIndexerClient(
            base_url="https://example.test:9200",
            username="admin",
            password="s3cret",
        )

    def test_search_alerts_returns_sources(self):
        fake = {
            "hits": {
                "hits": [
                    {"_index": "wazuh-alerts-2026.08", "_source": {"rule": {"level": 10}, "agent": {"id": "001"}}},
                    {"_index": "wazuh-alerts-2026.08", "_source": {"rule": {"level": 13}, "agent": {"id": "002"}}},
                ]
            }
        }
        with patch.object(self.client, "_request", return_value=fake) as mreq:
            hits = self.client.search_alerts(size=10)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["rule"]["level"], 10)

    def test_count_alerts(self):
        fake = {"count": 42}
        with patch.object(self.client, "_request", return_value=fake):
            self.assertEqual(self.client.count_alerts(), 42)

    def test_404_returns_empty_no_crash(self):
        from agentic_ai.infrastructure.wazuh_client import WazuhHTTPError
        with patch.object(self.client, "_request",
                          side_effect=WazuhHTTPError("HTTP 404 on POST /wazuh-alerts*/_search")):
            self.assertEqual(self.client.search_alerts(), [])
            self.assertEqual(self.client.count_alerts(), 0)


if __name__ == "__main__":
    unittest.main()