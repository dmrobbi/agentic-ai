"""
SOC Kafka Client
================

Kafka consumer + producer for SOCConversation pipeline.
Connects to the Kafka KRaft cluster on miner (207.244.226.151:9092).
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """SOC alert severity tiers."""
    P1 = "P1"  # Critical — active breach suspected
    P2 = "P2"  # High — confirmed compromise or clear attack pattern
    P3 = "P3"  # Medium — suspicious activity, needs investigation
    P4 = "P4"  # Low — policy violation or informational


class AlertCategory(str, Enum):
    """SOC alert categories."""
    MALWARE = "malware"
    PHISHING = "phishing"
    NETWORK = "network"
    INSIDER = "insider"
    COMPLIANCE = "compliance"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    LATERAL_MOVEMENT = "lateral_movement"
    BRUTE_FORCE = "brute_force"
    UNKNOWN = "unknown"


@dataclass
class SOCAlert:
    """
    Standardized SOC alert as it flows through the Kafka pipeline.
    Produced by Wazuh/source connectors, consumed by Lead Agent.
    """
    alert_id: str              # e.g. "ALR-2026-0519-0142"
    source: str               # "wazuh", "cortex", "splunk", "manual"
    source_ref: str            # Original alert ID from source SIEM
    rule_name: str             # Detection rule that fired
    description: str           # Human-readable description
    severity: AlertSeverity
    category: AlertCategory
    affected_asset: str        # Hostname or IP of affected system
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    filename: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    raw_log: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    investigation_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str | dict) -> "SOCAlert":
        if isinstance(data, str):
            data = json.loads(data)
        # Convert severity/category strings to enums
        if isinstance(data.get("severity"), str):
            data["severity"] = AlertSeverity(data["severity"])
        if isinstance(data.get("category"), str):
            data["category"] = AlertCategory(data["category"])
        return cls(**data)

    def to_kafka_message(self) -> dict:
        """Return Kafka message dict."""
        return {
            "key": self.alert_id,
            "value": asdict(self),
            "timestamp": self.timestamp,
        }


@dataclass
class InvestigationTask:
    """
    Investigation task published to soc.investigation.tasks.
    Produced by Lead Agent, consumed by specialist agents.
    """
    task_id: str
    alert_id: str
    investigation_id: str
    task_type: str             # "enrichment", "log_analysis", "threat_hunt", "fp_check"
    assigned_agent: str        # "soc.developer", "soc.sysadmin", "soc.qa"
    priority: AlertSeverity
    context: dict = field(default_factory=dict)
    status: str = "pending"    # pending, in_progress, completed, failed
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    completed_at: Optional[str] = None
    findings: dict = field(default_factory=dict)


@dataclass
class ResponseCommand:
    """
    Response action command published to soc.response.commands.
    Produced by Lead Agent after HITL approval, consumed by n8n or agent.
    """
    command_id: str
    alert_id: str
    investigation_id: str
    action: str               # "block_ip", "isolate_endpoint", "reset_password", "create_case"
    target: str               # IP, hostname, user, etc.
    reason: str
    approver: str              # Analyst who approved
    parameters: dict = field(default_factory=dict)
    status: str = "pending"    # pending, executed, failed, cancelled
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    executed_at: Optional[str] = None


class SOCKafkaClient:
    """
    Kafka client for SOCConversation pipeline.
    Produces to and consumes from SOC Kafka topics.
    """

    # Kafka bootstrap server
    BOOTSTRAP_SERVER = "207.244.226.151:9092"

    # Topics
    TOPIC_ALERTS_RAW = "soc.alerts.raw"
    TOPIC_ALERTS_ENRICHED = "soc.alerts.enriched"
    TOPIC_INVESTIGATION_TASKS = "soc.investigation.tasks"
    TOPIC_RESPONSE_COMMANDS = "soc.response.commands"
    TOPIC_INTEL_IOCS = "soc.intel.iocs"
    TOPIC_CASES_EVENTS = "soc.cases.events"
    TOPIC_METRICS = "soc.metrics.agent"

    # Consumer groups
    GROUP_LEAD_AGENT = "soc-lead-agent"

    def __init__(self, bootstrap_server: Optional[str] = None):
        self.bootstrap_server = bootstrap_server or self.BOOTSTRAP_SERVER
        self._producer = None
        self._consumer = None
        self._admin = None
        logger.info(f"SOCKafkaClient initialized for {self.bootstrap_server}")

    # ─────────────────────────────────────────────
    # Producer helpers (lazy initialization)
    # ─────────────────────────────────────────────

    def _get_producer(self):
        """Lazily create Kafka producer."""
        if self._producer is None:
            try:
                from confluent_kafka import Producer
                self._producer = Producer({
                    "bootstrap.servers": self.bootstrap_server,
                    "acks": "all",
                    "retries": 3,
                    "client.id": "soc-conversation-producer",
                })
                logger.info("Kafka producer connected")
            except ImportError:
                logger.warning("confluent-kafka not installed — using mock producer")
                self._producer = MockProducer()
        return self._producer

    def _get_admin(self):
        """Lazily create Kafka admin client."""
        if self._admin is None:
            try:
                from confluent_kafka import AdminClient
                self._admin = AdminClient({
                    "bootstrap.servers": self.bootstrap_server,
                    "client.id": "soc-conversation-admin",
                })
                logger.info("Kafka admin client connected")
            except ImportError:
                logger.warning("confluent-kafka not installed — using mock admin")
                self._admin = MockAdminClient()
        return self._admin

    # ─────────────────────────────────────────────
    # Topic management
    # ─────────────────────────────────────────────

    def ensure_topics(self):
        """
        Ensure all SOC pipeline topics exist with correct config.
        Idempotent — safe to call on every startup.
        """
        from confluent_kafka.admin import AdminClient, NewTopic

        admin = self._get_admin()

        topic_configs = [
            # topic, partitions, replication_factor, retention_hours
            (self.TOPIC_ALERTS_RAW,           12, 3, 24 * 7),
            (self.TOPIC_ALERTS_ENRICHED,      12, 3, 24 * 7),
            (self.TOPIC_INVESTIGATION_TASKS,  12, 3, 24 * 14),
            (self.TOPIC_RESPONSE_COMMANDS,     6, 3, 24 * 3),
            (self.TOPIC_INTEL_IOCS,            6, 3, 24 * 30),
            (self.TOPIC_CASES_EVENTS,          6, 3, 24 * 14),
            (self.TOPIC_METRICS,                3, 3, 24 * 3),
        ]

        existing = set(admin.list_topics().topics.keys())
        topics_to_create = [
            NewTopic(
                name,
                num_partitions=num_p,
                replication_factor=rf,
                config={"retention.ms": str(retention_hours * 3600 * 1000)}
            )
            for name, num_p, rf, retention_hours in topic_configs
            if name not in existing
        ]

        if topics_to_create:
            futures = admin.create_topics(topics_to_create)
            for name, future in futures.items():
                try:
                    future.result()
                    logger.info(f"  ✅ Created topic: {name}")
                except Exception as e:
                    if "already exists" in str(e).lower():
                        logger.debug(f"  ⏭  Topic already exists: {name}")
                    else:
                        logger.error(f"  ❌ Failed to create topic {name}: {e}")

    # ─────────────────────────────────────────────
    # Produce messages
    # ─────────────────────────────────────────────

    def produce_alert(self, alert: SOCAlert) -> bool:
        """Produce a raw alert to soc.alerts.raw."""
        try:
            p = self._get_producer()
            msg = alert.to_kafka_message()
            p.produce(
                topic=self.TOPIC_ALERTS_RAW,
                key=msg["key"],
                value=json.dumps(msg["value"]),
                callback=_delivery_callback,
            )
            p.poll(0)
            logger.info(f"📤 Produced alert {alert.alert_id} → {self.TOPIC_ALERTS_RAW}")
            return True
        except Exception as e:
            logger.error(f"Failed to produce alert: {e}")
            return False

    def produce_investigation_task(self, task: InvestigationTask) -> bool:
        """Produce an investigation task to soc.investigation.tasks."""
        try:
            p = self._get_producer()
            p.produce(
                topic=self.TOPIC_INVESTIGATION_TASKS,
                key=task.task_id,
                value=json.dumps(asdict(task)),
                callback=_delivery_callback,
            )
            p.poll(0)
            logger.info(f"📤 Produced task {task.task_id} → {self.TOPIC_INVESTIGATION_TASKS}")
            return True
        except Exception as e:
            logger.error(f"Failed to produce investigation task: {e}")
            return False

    def produce_response_command(self, cmd: ResponseCommand) -> bool:
        """Produce a response command to soc.response.commands."""
        try:
            p = self._get_producer()
            p.produce(
                topic=self.TOPIC_RESPONSE_COMMANDS,
                key=cmd.command_id,
                value=json.dumps(asdict(cmd)),
                callback=_delivery_callback,
            )
            p.poll(0)
            logger.info(f"📤 Produced command {cmd.command_id} → {self.TOPIC_RESPONSE_COMMANDS}")
            return True
        except Exception as e:
            logger.error(f"Failed to produce response command: {e}")
            return False

    def flush(self, timeout: float = 5.0):
        """Flush pending producer messages."""
        try:
            p = self._get_producer()
            p.flush(timeout)
        except Exception as e:
            logger.warning(f"Flush error: {e}")

    # ─────────────────────────────────────────────
    # Consume alerts (Lead Agent entry point)
    # ─────────────────────────────────────────────

    def consume_alerts(self, group_id: str = GROUP_LEAD_AGENT, timeout: float = 1.0):
        """
        Yield SOCAlert objects from soc.alerts.raw.
        Use this as the main entry point for the Lead Agent.
        """
        try:
            from confluent_kafka import Consumer, ConsumerConfig

            consumer = Consumer({
                "bootstrap.servers": self.bootstrap_server,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": True,
                "client.id": f"soc-conversation-consumer-{group_id}",
            })
            consumer.subscribe([self.TOPIC_ALERTS_RAW])

            logger.info(f"Kafka consumer started, group={group_id}")

            try:
                while True:
                    msg = consumer.poll(timeout)
                    if msg is None:
                        continue
                    if msg.error():
                        logger.warning(f"Kafka error: {msg.error()}")
                        continue

                    try:
                        alert = SOCAlert.from_json(json.loads(msg.value()))
                        yield alert
                    except Exception as e:
                        logger.error(f"Failed to parse alert: {e}")

            finally:
                consumer.close()

        except ImportError:
            logger.error("confluent-kafka not installed — cannot consume. Install with: pip install confluent-kafka")
            return
        except Exception as e:
            logger.error(f"Consumer error: {e}")
            return

    def consume_investigation_tasks(self, group_id: str = "soc-specialist-consumer", timeout: float = 1.0):
        """
        Yield InvestigationTask objects from soc.investigation.tasks.
        Used by specialist agents to consume their assigned tasks.
        """
        try:
            from confluent_kafka import Consumer

            consumer = Consumer({
                "bootstrap.servers": self.bootstrap_server,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": True,
                "client.id": f"soc-specialist-consumer-{group_id}",
            })
            consumer.subscribe([self.TOPIC_INVESTIGATION_TASKS])

            logger.info(f"Kafka specialist consumer started, group={group_id}")

            try:
                while True:
                    msg = consumer.poll(timeout)
                    if msg is None:
                        continue
                    if msg.error():
                        logger.warning(f"Kafka error: {msg.error()}")
                        continue

                    try:
                        data = json.loads(msg.value())
                        task = InvestigationTask(**data)
                        yield task
                    except Exception as e:
                        logger.error(f"Failed to parse investigation task: {e}")

            finally:
                consumer.close()

        except ImportError:
            logger.error("confluent-kafka not installed — cannot consume tasks")
            return
        except Exception as e:
            logger.error(f"Consumer error: {e}")
            return

    # ─────────────────────────────────────────────
    # Flush on exit
    # ─────────────────────────────────────────────

    def close(self):
        """Close all Kafka clients."""
        self.flush()
        if self._producer:
            self._producer = None
        if self._admin:
            self._admin = None
        logger.info("SOCKafkaClient closed")


def _delivery_callback(err, msg):
    """Kafka producer delivery callback."""
    if err:
        logger.error(f"Kafka delivery failed: {err}")
    else:
        logger.debug(f"Kafka delivered to {msg.topic()} [{msg.partition()}]")


# ─────────────────────────────────────────────
# Mock implementations (no confluent-kafka)
# ─────────────────────────────────────────────

class MockProducer:
    """Mock producer when confluent-kafka is not installed."""

    def __init__(self):
        self.messages = []

    def produce(self, topic, key, value, callback=None):
        msg = {"topic": topic, "key": key, "value": value}
        self.messages.append(msg)
        logger.debug(f"[MOCK] produce → {topic}: {key}")
        if callback:
            callback(None, None)

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=5.0):
        logger.info(f"[MOCK] flush — {len(self.messages)} messages in buffer")
        self.messages.clear()


class MockAdminClient:
    """Mock admin client when confluent-kafka is not installed."""

    def list_topics(self):
        return MockTopicMetadata()


class MockTopicMetadata:
    """Mock topic metadata."""

    def __init__(self):
        self.topics = {"soc.alerts.raw": MockTopic("soc.alerts.raw")}


class MockTopic:
    """Mock individual topic."""

    def __init__(self, name):
        self.name = name
        self.is_internal = False


# ─────────────────────────────────────────────
# Convenience: generate a standardized alert ID
# ─────────────────────────────────────────────

def generate_alert_id(prefix: str = "ALR") -> str:
    """Generate a standardized SOCConversation alert ID."""
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"{prefix}-{ts}-{short_uuid}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    client = SOCKafkaClient()

    # Ensure topics exist
    print("\n🔧 Ensuring SOC topics exist...")
    client.ensure_topics()

    # Produce a sample alert
    print("\n📤 Producing sample alert...")
    sample_alert = SOCAlert(
        alert_id=generate_alert_id(),
        source="wazuh",
        source_ref="WAZUH-12345",
        rule_name="sigma_brute_force_rdp",
        description="Multiple failed RDP logins from suspicious IP",
        severity=AlertSeverity.P2,
        category=AlertCategory.BRUTE_FORCE,
        affected_asset="FIN-DC01",
        source_ip="185.220.101.42",
        dest_ip="10.0.1.10",
        dest_port=3389,
        protocol="TCP",
        user="jsmith",
        raw_log='{"timestamp":"2026-05-19T23:47:00Z","src_ip":"185.220.101.42","dst_ip":"10.0.1.10","event":"failed_rdp_login"}',
    )
    client.produce_alert(sample_alert)
    client.flush()

    print("\n✅ Kafka client test complete")
    print(f"   Broker: {client.bootstrap_server}")
    print(f"   Topics: {client.TOPIC_ALERTS_RAW}, {client.TOPIC_INVESTIGATION_TASKS}, {client.TOPIC_RESPONSE_COMMANDS}")