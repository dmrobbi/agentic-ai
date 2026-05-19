"""
SOCLeadAgent
============

SOC Lead Agent — orchestrates alert triage and investigation.
Extends SecurityOperationsAgent (from agentic_ai.agents.cyber.soc)
with SOC-specific tools, Kafka integration, and PostgreSQL persistence.

This is the PRIMARY AGENT for SOCConversation Milestone 1.
It connects to Kafka `soc.alerts.raw`, triages each alert,
dispatches to specialist agents, and presents HITL recommendations.
"""

import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Optional

from agentic_ai.agents.cyber.soc import (
    SecurityOperationsAgent,
    AlertSeverity,
    AlertStatus,
)

from soc.kafka_client import (
    SOCKafkaClient,
    SOCAlert,
    generate_alert_id,
)
from soc.db_client import SOCDBClient, DBConfig
from soc.tools.soc_tools import (
    soc_triage,
    soc_dispatch,
    soc_rsem_score,
    soc_hitl_present,
    threat_enrich,
    mitre_lookup,
)

logger = logging.getLogger(__name__)


class SOCLeadAgent:
    """
    SOC Lead Agent — the central orchestrator for the SOCConversation pipeline.

    In Milestone 1, this agent:
    1. Consumes raw alerts from Kafka `soc.alerts.raw`
    2. Runs triage (classification, deduplication, MITRE mapping)
    3. Writes triaged alerts to PostgreSQL
    4. Dispatches investigation tasks via Kafka
    5. Waits for HITL analyst decision
    6. Produces response commands to Kafka `soc.response.commands`

    In later milestones, this also runs NCE → RSEM → HITL presentation.
    """

    def __init__(
        self,
        kafka_bootstrap: str = "207.244.226.151:9092",
        db_host: str = "localhost",
        db_port: int = 5433,
        db_user: str = "postgres",
        db_password: str = "",
        db_database: str = "postgres",
        kafka_topic: str = "soc.alerts.raw",
        consumer_group: str = "soc-lead-agent",
        analyst_name: str = "SOCAnalyst",
        enable_postgres: bool = False,
        enable_kafka_consumer: bool = False,
    ):
        self.kafka_bootstrap = kafka_bootstrap
        self.analyst_name = analyst_name

        # ── Kafka ──
        self.kafka_topic = kafka_topic
        self.consumer_group = consumer_group
        self.kafka = SOCKafkaClient(bootstrap_server=kafka_bootstrap)

        # ── Database ──
        self.db = None
        if enable_postgres:
            db_config = DBConfig(
                host=db_host,
                writer_port=db_port,
                reader_port=db_port + 1,  # usually writer+1
                database=db_database,
                user=db_user,
                password=db_password,
            )
            self.db = SOCDBClient(config=db_config)
            self.db.init_schema()
            logger.info("SOCDBClient schema initialized")

        # ── Underlying SOC agent ──
        self.soc_agent = SecurityOperationsAgent(agent_id="soc-lead-agent")

        # ── Metrics ──
        self._metrics = {
            "alerts_processed": 0,
            "alerts_triaged": 0,
            "alerts_dispatched": 0,
            "alerts_failed": 0,
            "avg_triage_ms": 0,
            "start_time": datetime.utcnow().isoformat(),
        }
        self._triage_times = []

        logger.info(
            f"SOCLeadAgent initialized — kafka={kafka_bootstrap} "
            f"db={db_host}:{db_port} consumer_group={consumer_group}"
        )

    # ─────────────────────────────────────────────
    # Core pipeline
    # ─────────────────────────────────────────────

    def process_alert(self, alert: SOCAlert) -> dict:
        """
        Process a single alert through the full SOC pipeline.
        Returns a result dict with triage, dispatch, and HITL state.
        """
        start = time.monotonic()
        alert_id = alert.alert_id

        logger.info(f"[process_alert] Starting: {alert_id}")
        result = {
            "alert_id": alert_id,
            "investigation_id": None,
            "status": "pending",
            "triage": None,
            "dispatch": None,
            "scored_options": [],
            "hitl_panel": None,
            "error": None,
        }

        try:
            # ── Step 1: Triage ──
            triage = soc_triage(alert.to_kafka_message()["value"])
            result["triage"] = triage
            result["investigation_id"] = triage["investigation_id"]
            self._metrics["alerts_triaged"] += 1

            # ── Step 2: PostgreSQL write ──
            if self.db:
                self.db.upsert_alert({
                    "alert_id": alert.alert_id,
                    "source": alert.source,
                    "source_ref": alert.source_ref,
                    "rule_name": alert.rule_name,
                    "description": alert.description,
                    "severity": triage["severity"],
                    "category": triage["category"],
                    "status": "triaged",
                    "affected_asset": alert.affected_asset,
                    "source_ip": str(alert.source_ip) if alert.source_ip else None,
                    "dest_ip": str(alert.dest_ip) if alert.dest_ip else None,
                    "source_port": alert.source_port,
                    "dest_port": alert.dest_port,
                    "protocol": alert.protocol,
                    "user_name": alert.user,
                    "filename": alert.filename,
                    "file_hash": alert.hash,
                    "domain": alert.domain,
                    "raw_log": json.dumps(alert.raw_log) if alert.raw_log else None,
                    "mitre_tactics": [t["id"] for t in triage.get("mitre_tactics", [])],
                    "mitre_techniques": [],
                    "confidence_score": triage.get("confidence_score", 0),
                    "investigation_id": triage["investigation_id"],
                    "status": "triaged",
                })
                self.db.set_investigation_id(alert.alert_id, triage["investigation_id"])

            # ── Step 3: Check for FP ──
            if triage["is_false_positive"]:
                logger.info(f"[process_alert] {alert_id} → marked as FP, no dispatch")
                result["status"] = "false_positive"
                if self.db:
                    self.db.update_alert_status(alert.alert_id, "fp")
                self._record_triage_time(start)
                return result

            # ── Step 4: Dispatch to specialist agents ──
            dispatch = soc_dispatch(triage, kafka_client=self.kafka)
            result["dispatch"] = dispatch
            self._metrics["alerts_dispatched"] += 1

            # ── Step 5: Quick enrichment (IP check) ──
            enrichment_result = {"hypotheses": [], "ip_reputation": None}
            if alert.source_ip:
                ip_reputation = threat_enrich(str(alert.source_ip), "ip")
                enrichment_result["ip_reputation"] = ip_reputation

                # Generate hypotheses based on IP reputation
                rep_score = ip_reputation.get("reputation_score", 50)
                if rep_score >= 70:
                    enrichment_result["hypotheses"] = [
                        {"text": f"Attacker from known suspicious IP ({rep_score}% reputation)", "confidence": rep_score},
                        {"text": "False positive — VPN exit node, not targeted", "confidence": 100 - rep_score},
                    ]
                else:
                    enrichment_result["hypotheses"] = [
                        {"text": "Suspicious activity pattern", "confidence": 60},
                        {"text": "Legitimate user misconfiguration", "confidence": 40},
                    ]

            # ── Step 6: RSEM scoring ──
            options = [
                {"action": "block_ip", "target": str(alert.source_ip), "description": f"Block {alert.source_ip} at perimeter"},
                {"action": "isolate_endpoint", "target": alert.affected_asset, "description": f"Isolate {alert.affected_asset} via EDR"},
                {"action": "reset_password", "target": str(alert.user), "description": f"Force password reset for {alert.user}"},
                {"action": "create_case", "target": alert.alert_id, "description": "Create TheHive case for investigation"},
            ]
            scored_options = soc_rsem_score(options, severity=triage["severity"], category=triage["category"])
            result["scored_options"] = scored_options

            # ── Step 7: HITL presentation ──
            hitl_panel = soc_hitl_present(
                triage_result=triage,
                enrichment_result=enrichment_result,
                scored_options=scored_options,
                analyst_name=self.analyst_name,
            )
            result["hitl_panel"] = hitl_panel
            result["status"] = "awaiting_human_decision"

            self._metrics["alerts_processed"] += 1
            self._record_triage_time(start)

            logger.info(
                f"[process_alert] {alert_id} → {result['status']} "
                f"(severity={triage['severity']}, dispatch={len(dispatch['dispatched_tasks'])} tasks)"
            )

        except Exception as e:
            logger.error(f"[process_alert] {alert_id} failed: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            self._metrics["alerts_failed"] += 1

        return result

    def handle_analyst_decision(
        self,
        alert_id: str,
        decision: str,
        custom_action: Optional[str] = None,
    ) -> dict:
        """
        Handle analyst's HITL decision.
        decision: "A", "B", "C", "D" (mapped to scored options)
        custom_action: raw action description if analyst typed their own

        Produces a ResponseCommand to Kafka soc.response.commands.
        """
        from soc.kafka_client import ResponseCommand

        # Look up the investigation
        investigation_id = None
        if self.db:
            alert = self.db.get_alert(alert_id)
            if alert:
                investigation_id = alert.get("investigation_id")

        # Parse analyst decision
        decision = decision.strip().upper()
        action_map = {"A": 0, "B": 1, "C": 2, "D": 3}

        if custom_action:
            action = "custom"
            target = alert_id
            description = custom_action
        elif decision in action_map:
            # Get the scored option (we'd need to store it; for now reconstruct)
            # In production this would be stored in Redis/PostgreSQL
            action = "block_ip"  # fallback
            target = "unknown"
            description = f"Analyst chose option {decision}"
        else:
            return {"error": f"Unknown decision: {decision}. Use A, B, C, D, or describe your own action."}

        cmd = ResponseCommand(
            command_id=f"CMD-{uuid.uuid4().hex[:8].upper()}",
            alert_id=alert_id,
            investigation_id=investigation_id or "UNKNOWN",
            action=action,
            target=target,
            reason=description,
            approver=self.analyst_name,
            status="pending",
        )

        self.kafka.produce_response_command(cmd)

        logger.info(f"[handle_decision] {alert_id} → analyst {self.analyst_name} chose [{decision}]: {action} {target}")

        return {
            "command_id": cmd.command_id,
            "alert_id": alert_id,
            "decision": decision,
            "action": action,
            "target": target,
            "status": "command_submitted",
        }

    # ─────────────────────────────────────────────
    # Start consuming from Kafka
    # ─────────────────────────────────────────────

    def run(self, max_alerts: Optional[int] = None):
        """
        Start the Lead Agent — continuously consume from Kafka.
        For each alert, run process_alert() and print HITL panel.

        Use max_alerts to limit for testing.
        """
        logger.info(f"🚀 SOCLeadAgent starting — consuming from {self.kafka_topic}")

        count = 0
        for alert in self.kafka.consume_alerts(group=self.consumer_group):
            result = self.process_alert(alert)
            print("\n" + "=" * 70)
            print(f"🍀 SOCConversation — Processed: {result['alert_id']}")
            print("=" * 70)

            if result["hitl_panel"]:
                print(result["hitl_panel"])
            else:
                print(f"⚠️  {result['status'].upper()}: {result.get('error') or 'no HITL panel generated'}")

            count += 1
            if max_alerts and count >= max_alerts:
                logger.info(f"Max alerts reached ({max_alerts}). Shutting down.")
                break

        self.kafka.close()
        if self.db:
            self.db.close()

    # ─────────────────────────────────────────────
    # Demo / test mode
    # ─────────────────────────────────────────────

    def demo(self):
        """
        Run a demo: produce a sample alert → process it → show HITL panel.
        No Kafka connection required — uses mock producer.
        """
        logger.info("🎭 SOCLeadAgent running DEMO mode")

        # Produce a realistic sample alert
        sample_alert = SOCAlert(
            alert_id=generate_alert_id(),
            source="wazuh",
            source_ref="WAZUH-20260519-0001",
            rule_name="Suspicious RDP Lateral Movement to Finance DC",
            description="5 failed RDP logins followed by successful connection from foreign TOR exit node",
            severity="P2",
            category="lateral_movement",
            affected_asset="FIN-DC01",
            source_ip="185.220.101.42",
            dest_ip="10.0.1.10",
            dest_port=3389,
            protocol="TCP",
            user="jsmith",
            raw_log=json.dumps({
                "timestamp": "2026-05-19T23:47:00Z",
                "event_type": "rdp_login",
                "src_ip": "185.220.101.42",
                "src_country": "Poland",
                "dst_ip": "10.0.1.10",
                "dst_host": "FIN-DC01",
                "user": "jsmith",
                "failed_attempts": 5,
                "mfa_used": True,
            }),
        )

        # Ensure topics exist (won't fail if Kafka is unreachable)
        try:
            self.kafka.ensure_topics()
        except Exception as e:
            logger.debug(f"Topic creation skipped: {e}")

        # Process the alert
        result = self.process_alert(sample_alert)

        print("\n" + "=" * 70)
        print("🍀 SOCConversation — Lead Agent Demo")
        print("=" * 70)
        print(f"\n📥 Alert: {sample_alert.alert_id}")
        print(f"   Source: {sample_alert.source} / {sample_alert.rule_name}")
        print(f"   Severity: {result['triage']['severity']} | Category: {result['triage']['category']}")
        print(f"   MITRE: {[t['id'] for t in result['triage'].get('mitre_tactics', [])]}")
        print(f"   Dedup hash: {result['triage']['dedup_hash']}")
        print(f"   Is FP: {result['triage']['is_false_positive']}")
        print(f"   Dispatched to: {[t['assigned_agent'] for t in result['dispatch']['dispatched_tasks']]}")
        print(f"   RSEM top score: {result['scored_options'][0]['score']:.0f}/100 ({result['scored_options'][0]['action']})")

        print("\n" + "-" * 70)
        print("📊 METRICS")
        print("-" * 70)
        metrics = self.get_metrics()
        for k, v in metrics.items():
            print(f"  {k}: {v}")

        print("\n" + "-" * 70)
        print("📋 HITL RECOMMENDATION PANEL")
        print("-" * 70)
        if result["hitl_panel"]:
            print(result["hitl_panel"])

        print("\n" + "-" * 70)
        print("🔢 ANALYST DECISION")
        print("-" * 70)
        decision_result = self.handle_analyst_decision(sample_alert.alert_id, "A")
        print(f"  {decision_result}")

        self.kafka.close()

    def get_metrics(self) -> dict:
        """Return current metrics."""
        m = dict(self._metrics)
        if self._triage_times:
            m["avg_triage_ms"] = round(sum(self._triage_times) / len(self._triage_times), 1)
        m["uptime_seconds"] = (datetime.utcnow() - datetime.fromisoformat(m["start_time"])).total_seconds()
        return m

    def _record_triage_time(self, start: float):
        elapsed_ms = (time.monotonic() - start) * 1000
        self._triage_times.append(elapsed_ms)
        # Keep last 1000 timings
        if len(self._triage_times) > 1000:
            self._triage_times = self._triage_times[-1000:]


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    agent = SOCLeadAgent(
        enable_postgres=False,  # Set True if PostgreSQL is reachable
        enable_kafka_consumer=False,
        analyst_name="Wes",
    )
    agent.demo()