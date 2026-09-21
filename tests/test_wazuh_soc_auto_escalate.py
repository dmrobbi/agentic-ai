"""Test that SecurityOperationsAgent auto-escalates Wazuh alerts >= level 10
to incidents (existing behavior; locks it in).

This is the Step 2 of the 2026-08-03 follow-up: verify that a level-12 SSH
brute-force alert from Wazuh automatically produces a SecurityAlert AND a
linked IncidentReport. A level-5 systemd failure should NOT escalate.

Run with: PYTHONPATH=. pytest tests/test_wazuh_soc_auto_escalate.py -v
"""
from __future__ import annotations

import unittest

from agentic_ai.agents.cyber.soc import (
    AlertSeverity,
    IncidentSeverity,
    SecurityOperationsAgent,
)


def _wazuh_alert(level: int, rule_id: str, desc: str, agent: str = "test-host") -> dict:
    """Build a Wazuh 4.x alert document as it would land in wazuh-alerts-*."""
    return {
        "@timestamp": "2026-08-03T19:30:00.000+00:00",
        "timestamp": "2026-08-03T19:30:00.000+00:00",
        "rule": {
            "level": level,
            "id": rule_id,
            "description": desc,
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "099", "name": agent, "ip": "198.51.100.99"},
        "manager": {"name": "wazuh.manager"},
        "id": f"abc123-{rule_id}",
    }


class WazuhAutoEscalateTests(unittest.TestCase):
    def setUp(self):
        self.soc = SecurityOperationsAgent()

    def test_level_12_auto_escalates_to_incident(self):
        """A Wazuh level-12 alert (multiple failed logins) creates an incident."""
        before_incidents = len(self.soc.incidents)
        a = self.soc.ingest_wazuh_alert(
            _wazuh_alert(12, "5720", "sshd: Multiple failed logins from same source IP.")
        )
        # Should be HIGH severity (10..12 -> high)
        self.assertEqual(a.severity, AlertSeverity.HIGH)
        # Should have created an incident
        self.assertEqual(len(self.soc.incidents), before_incidents + 1)
        latest = list(self.soc.incidents.values())[-1]
        self.assertEqual(latest.severity, IncidentSeverity.HIGH)
        self.assertIn("Multiple failed logins", latest.description)
        self.assertIn("test-host", latest.title)

    def test_level_13_auto_escalates_critical(self):
        """A Wazuh level-13 alert (active attack) creates a CRITICAL incident."""
        before_incidents = len(self.soc.incidents)
        a = self.soc.ingest_wazuh_alert(
            _wazuh_alert(13, "1002", "Host-based anomaly detection (rootcheck).")
        )
        self.assertEqual(a.severity, AlertSeverity.CRITICAL)
        self.assertEqual(len(self.soc.incidents), before_incidents + 1)
        latest = list(self.soc.incidents.values())[-1]
        self.assertEqual(latest.severity, IncidentSeverity.CRITICAL)

    def test_level_5_does_not_escalate(self):
        """A Wazuh level-5 alert (systemd failure) should NOT create an incident."""
        before_incidents = len(self.soc.incidents)
        a = self.soc.ingest_wazuh_alert(
            _wazuh_alert(5, "40704", "Systemd: Service exited due to a failure.")
        )
        # Should be LOW severity
        self.assertEqual(a.severity, AlertSeverity.LOW)
        # No incident created
        self.assertEqual(len(self.soc.incidents), before_incidents)
        # No escalation note stamped on the alert
        self.assertEqual(len(a.investigation_notes), 0)

    def test_linkage_note_present_when_escalated(self):
        """When escalated, the alert should have a note linking to the incident id."""
        a = self.soc.ingest_wazuh_alert(
            _wazuh_alert(11, "5503", "Login session opened with superuser.")
        )
        self.assertEqual(a.severity, AlertSeverity.HIGH)
        self.assertTrue(
            any("auto-escalated to incident" in n for n in a.investigation_notes),
            f"expected escalation note in {a.investigation_notes!r}",
        )


if __name__ == "__main__":
    unittest.main()
