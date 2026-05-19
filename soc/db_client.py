"""
SOC PostgreSQL Database Client
==============================

Client for SOCConversation PostgreSQL schema.
Writes to Patroni HA PostgreSQL via HAProxy (:5433 writer, :5434 reader).
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extras import Json
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    psycopg2 = None
    Json = lambda x: x  # noop fallback

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# SQL Schema — create all 6 tables
# ─────────────────────────────────────────────

SOC_SCHEMA_SQL = """
-- ============================================================
-- SOCConversation Database Schema
-- PostgreSQL via Patroni HA / HAProxy
-- ============================================================

-- Alerts table: raw and enriched alerts from SIEM pipeline
CREATE TABLE IF NOT EXISTS alerts (
    alert_id          VARCHAR(64)  PRIMARY KEY,
    source            VARCHAR(32)  NOT NULL,          -- wazuh, cortex, splunk, manual
    source_ref        VARCHAR(128),                   -- Original ID in source SIEM
    rule_name         VARCHAR(256),
    description       TEXT,
    severity          VARCHAR(8)  CHECK (severity IN ('P1','P2','P3','P4')),
    category          VARCHAR(32),
    status            VARCHAR(24) DEFAULT 'new',       -- new, triaged, investigating, resolved, fp
    affected_asset    VARCHAR(256),
    source_ip         INET,
    dest_ip           INET,
    source_port       INTEGER,
    dest_port         INTEGER,
    protocol          VARCHAR(16),
    user_name         VARCHAR(256),
    filename          VARCHAR(512),
    file_hash         VARCHAR(128),
    domain            VARCHAR(256),
    raw_log           JSONB,
    mitre_tactics     TEXT[],
    mitre_techniques  TEXT[],
    confidence_score  DECIMAL(5,2) DEFAULT 0,
    investigation_id  VARCHAR(64),
    assigned_to       VARCHAR(256),
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status       ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at   ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip    ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_investigation ON alerts(investigation_id);


-- Cases table: incidents escalated from alerts
CREATE TABLE IF NOT EXISTS cases (
    case_id           VARCHAR(64)  PRIMARY KEY,
    alert_id          VARCHAR(64)  REFERENCES alerts(alert_id),
    title             VARCHAR(512) NOT NULL,
    severity          VARCHAR(8)  CHECK (severity IN ('P1','P2','P3','P4')),
    status            VARCHAR(24)  DEFAULT 'open',  -- open, investigating, contained, closed
    category          VARCHAR(32),
    threat_actor      VARCHAR(64),
    affected_assets   TEXT[],
    affected_users   TEXT[],
    root_cause        TEXT,
    remediation       TEXT[],
    lessons_learned  TEXT[],
    assigned_to       VARCHAR(256),
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    closed_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cases_status        ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_severity       ON cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_created_at    ON cases(created_at DESC);


-- IOC Registry: indicators of compromise
CREATE TABLE IF NOT EXISTS ioc_registry (
    ioc_id            VARCHAR(64)  PRIMARY KEY,
    ioc_type          VARCHAR(16)  NOT NULL,          -- ip, domain, hash, url, email
    ioc_value         VARCHAR(1024) NOT NULL,
    threat_type       VARCHAR(64),
    confidence        VARCHAR(16)  CHECK (confidence IN ('low','medium','high')),
    source            VARCHAR(64),
    first_seen        TIMESTAMPTZ,
    last_seen         TIMESTAMPTZ DEFAULT NOW(),
    tags              TEXT[],
    related_campaigns TEXT[],
    raw_intel         JSONB,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_value          ON ioc_registry(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_type           ON ioc_registry(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_confidence     ON ioc_registry(confidence);
CREATE INDEX IF NOT EXISTS idx_ioc_last_seen      ON ioc_registry(last_seen DESC);


-- MITRE ATT&CK Mappings
CREATE TABLE IF NOT EXISTS mitre_mappings (
    mapping_id        VARCHAR(64)  PRIMARY KEY,
    technique_id      VARCHAR(16)  NOT NULL,         -- e.g. "T1059.003"
    technique_name    VARCHAR(256),
    tactic_id         VARCHAR(16),                  -- e.g. "TA0008"
    tactic_name       VARCHAR(128),
    description       TEXT,
    applicable_alerts TEXT[],                       -- rule names this applies to
    coverage_note     TEXT,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mitre_technique    ON mitre_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic       ON mitre_mappings(tactic_id);


-- Agent Audit Log: immutable record of all agent decisions
CREATE TABLE IF NOT EXISTS agent_audit_log (
    log_id            VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::VARCHAR(64),
    session_id        VARCHAR(64),
    analyst_id        VARCHAR(256),
    agent_id          VARCHAR(64)  NOT NULL,
    action            VARCHAR(64)  NOT NULL,          -- triage, dispatch, enrich, approve, reject
    alert_id          VARCHAR(64),
    investigation_id  VARCHAR(64),
    query_text        TEXT,
    intent_classified VARCHAR(32),
    entities_extracted JSONB,
    response_summary  TEXT,
    actions_recommended JSONB,
    human_decision    VARCHAR(8),                    -- approved, rejected, redirected
    reasoning         TEXT,
    latency_ms        DECIMAL(12,2),
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_agent_id      ON agent_audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_alert_id      ON agent_audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at   ON agent_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session_id   ON agent_audit_log(session_id);


-- Response Actions: log of all response commands executed
CREATE TABLE IF NOT EXISTS response_actions (
    action_id         VARCHAR(64)  PRIMARY KEY,
    command_id        VARCHAR(64) REFERENCES response_commands(command_id),
    alert_id          VARCHAR(64),
    case_id           VARCHAR(64) REFERENCES cases(case_id),
    action_type       VARCHAR(32) NOT NULL,           -- block_ip, isolate, reset_password, create_case
    target            VARCHAR(512) NOT NULL,
    approver          VARCHAR(256),
    executor          VARCHAR(64),                     -- n8n, agent_id, manual
    status            VARCHAR(16) DEFAULT 'pending',  -- pending, executed, failed, cancelled
    parameters        JSONB,
    result            JSONB,
    error             TEXT,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    executed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_response_alert_id   ON response_actions(alert_id);
CREATE INDEX IF NOT EXISTS idx_response_status     ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_created_at ON response_actions(created_at DESC);
"""


SOC_SCHEMA_SQL += """

-- Response Commands: pending and executed commands
CREATE TABLE IF NOT EXISTS response_commands (
    command_id        VARCHAR(64)  PRIMARY KEY,
    alert_id          VARCHAR(64),
    investigation_id  VARCHAR(64),
    action            VARCHAR(32) NOT NULL,
    target           VARCHAR(512) NOT NULL,
    reason            TEXT,
    approver          VARCHAR(256),
    parameters        JSONB,
    status            VARCHAR(16)  DEFAULT 'pending',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    executed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_commands_alert_id   ON response_commands(alert_id);
CREATE INDEX IF NOT EXISTS idx_commands_status    ON response_commands(status);
"""


# ─────────────────────────────────────────────
# DB Client
# ─────────────────────────────────────────────

@dataclass
class DBConfig:
    """PostgreSQL connection config via HAProxy."""
    host: str = "localhost"
    port: int = 5433
    database: str = "postgres"
    user: str = "postgres"
    password: str = ""
    # For writes use port 5433, for reads use 5434 (replicas)
    writer_port: int = 5433
    reader_port: int = 5434

    @property
    def writer_uri(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.writer_port}/{self.database}"

    @property
    def reader_uri(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.reader_port}/{self.database}"


class SOCDBClient:
    """
    PostgreSQL client for SOCConversation schema.
    Writes always go to primary (:5433). Reads can go to replicas (:5434).
    """

    def __init__(self, config: Optional[DBConfig] = None):
        self.config = config or DBConfig()
        self._writer_conn = None
        self._reader_conn = None

    def _get_writer(self):
        """Get writer connection (primary via HAProxy :5433)."""
        if self._writer_conn is None or self._writer_conn.closed:
            self._writer_conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.writer_port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
            )
            self._writer_conn.autocommit = True
            logger.info(f"DB writer connected via :{self.config.writer_port}")
        return self._writer_conn

    def _get_reader(self):
        """Get reader connection (replica via HAProxy :5434)."""
        if self._reader_conn is None or self._reader_conn.closed:
            self._reader_conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.reader_port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
            )
            self._reader_conn.autocommit = True
            logger.info(f"DB reader connected via :{self.config.reader_port}")
        return self._reader_conn

    # ─────────────────────────────────────────────
    # Schema management
    # ─────────────────────────────────────────────

    def init_schema(self):
        """Create all SOC tables. Idempotent — safe to call on every startup."""
        if not HAS_PSYCOPG2:
            logger.warning("psycopg2 not installed — schema init skipped")
            return
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute(SOC_SCHEMA_SQL)
        logger.info("SOC schema initialized")

    # ─────────────────────────────────────────────
    # Alerts
    # ─────────────────────────────────────────────

    def upsert_alert(self, alert_data: dict) -> bool:
        """
        Insert or update an alert.
        alert_data must contain: alert_id, source, rule_name, description,
        severity, category, affected_asset.
        """
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (
                    alert_id, source, source_ref, rule_name, description,
                    severity, category, status, affected_asset,
                    source_ip, dest_ip, source_port, dest_port, protocol,
                    user_name, filename, file_hash, domain, raw_log,
                    mitre_tactics, mitre_techniques, confidence_score,
                    investigation_id, assigned_to, updated_at
                ) VALUES (
                    %(alert_id)s, %(source)s, %(source_ref)s, %(rule_name)s, %(description)s,
                    %(severity)s, %(category)s, %(status)s, %(affected_asset)s,
                    %(source_ip)s, %(dest_ip)s, %(source_port)s, %(dest_port)s, %(protocol)s,
                    %(user_name)s, %(filename)s, %(file_hash)s, %(domain)s, %(raw_log)s,
                    %(mitre_tactics)s, %(mitre_techniques)s, %(confidence_score)s,
                    %(investigation_id)s, %(assigned_to)s, NOW()
                )
                ON CONFLICT (alert_id) DO UPDATE SET
                    severity          = EXCLUDED.severity,
                    category          = EXCLUDED.category,
                    status            = EXCLUDED.status,
                    confidence_score  = EXCLUDED.confidence_score,
                    investigation_id   = EXCLUDED.investigation_id,
                    updated_at        = NOW()
                WHERE EXCLUDED.severity IS NOT NULL
            """, alert_data)
        return True

    def get_alert(self, alert_id: str) -> Optional[dict]:
        """Fetch a single alert by ID."""
        conn = self._get_reader()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,))
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))
        return None

    def get_recent_alerts(self, hours: int = 24, severity: Optional[str] = None, limit: int = 100) -> list:
        """Fetch recent alerts, most recent first."""
        conn = self._get_reader()
        with conn.cursor() as cur:
            query = "SELECT * FROM alerts WHERE created_at > NOW() - INTERVAL '%s hours'"
            params = [hours]
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update alert status."""
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET status = %s, updated_at = NOW() WHERE alert_id = %s",
                (status, alert_id)
            )
        return True

    def set_investigation_id(self, alert_id: str, investigation_id: str) -> bool:
        """Assign an investigation ID to an alert."""
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET investigation_id = %s, status = 'investigating', updated_at = NOW() WHERE alert_id = %s",
                (investigation_id, alert_id)
            )
        return True

    # ─────────────────────────────────────────────
    # Cases
    # ─────────────────────────────────────────────

    def create_case(self, case_data: dict) -> str:
        """Create a new case. Returns case_id."""
        case_id = case_data.get("case_id") or f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO cases (
                    case_id, alert_id, title, severity, status, category,
                    threat_actor, affected_assets, affected_users,
                    assigned_to
                ) VALUES (
                    %(case_id)s, %(alert_id)s, %(title)s, %(severity)s, %(status)s, %(category)s,
                    %(threat_actor)s, %(affected_assets)s, %(affected_users)s,
                    %(assigned_to)s
                )
                ON CONFLICT (case_id) DO NOTHING
            """, {**case_data, "case_id": case_id})
        return case_id

    # ─────────────────────────────────────────────
    # Audit log (immutable)
    # ─────────────────────────────────────────────

    def log_agent_action(self, action_data: dict) -> str:
        """Write an immutable record to agent_audit_log."""
        log_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO agent_audit_log (
                    log_id, session_id, analyst_id, agent_id, action,
                    alert_id, investigation_id, query_text, intent_classified,
                    entities_extracted, response_summary, actions_recommended,
                    human_decision, reasoning, latency_ms
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s
                )
            """, (
                log_id,
                action_data.get("session_id"),
                action_data.get("analyst_id"),
                action_data.get("agent_id"),
                action_data.get("action"),
                action_data.get("alert_id"),
                action_data.get("investigation_id"),
                action_data.get("query_text"),
                action_data.get("intent_classified"),
                Json(action_data.get("entities_extracted", {})),
                action_data.get("response_summary"),
                Json(action_data.get("actions_recommended", [])),
                action_data.get("human_decision"),
                action_data.get("reasoning"),
                action_data.get("latency_ms"),
            ))
        return log_id

    # ─────────────────────────────────────────────
    # IOCs
    # ─────────────────────────────────────────────

    def upsert_ioc(self, ioc_data: dict) -> str:
        """Insert or update an IOC."""
        ioc_id = ioc_data.get("ioc_id") or f"IOC-{uuid.uuid4().hex[:8].upper()}"
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ioc_registry (
                    ioc_id, ioc_type, ioc_value, threat_type, confidence,
                    source, first_seen, last_seen, tags, related_campaigns, raw_intel
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (ioc_id) DO UPDATE SET
                    last_seen  = NOW(),
                    raw_intel  = EXCLUDED.raw_intel,
                    tags       = EXCLUDED.tags
            """, (
                ioc_id,
                ioc_data.get("ioc_type"),
                ioc_data.get("ioc_value"),
                ioc_data.get("threat_type"),
                ioc_data.get("confidence"),
                ioc_data.get("source"),
                ioc_data.get("first_seen") or datetime.utcnow(),
                datetime.utcnow(),
                ioc_data.get("tags", []),
                ioc_data.get("related_campaigns", []),
                Json(ioc_data.get("raw_intel", {})),
            ))
        return ioc_id

    # ─────────────────────────────────────────────
    # Response actions
    # ─────────────────────────────────────────────

    def log_response_action(self, action_data: dict) -> str:
        """Log a response action to response_actions table."""
        action_id = action_data.get("action_id") or f"ACT-{uuid.uuid4().hex[:8].upper()}"
        conn = self._get_writer()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO response_actions (
                    action_id, command_id, alert_id, case_id,
                    action_type, target, approver, executor,
                    status, parameters, result, error, executed_at
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
            """, (
                action_id,
                action_data.get("command_id"),
                action_data.get("alert_id"),
                action_data.get("case_id"),
                action_data.get("action_type"),
                action_data.get("target"),
                action_data.get("approver"),
                action_data.get("executor"),
                action_data.get("status", "pending"),
                Json(action_data.get("parameters", {})),
                Json(action_data.get("result", {})),
                action_data.get("error"),
                action_data.get("executed_at"),
            ))
        return action_id

    # ─────────────────────────────────────────────
    # Close
    # ─────────────────────────────────────────────

    def close(self):
        """Close all connections."""
        if self._writer_conn and not self._writer_conn.closed:
            self._writer_conn.close()
        if self._reader_conn and not self._reader_conn.closed:
            self._reader_conn.close()
        logger.info("SOCDBClient connections closed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # Test without real DB (connection will fail but schema is printed)
    print("📋 SOC Schema:")
    print(SOC_SCHEMA_SQL[:500])
    print("... [truncated]")
    print("\n✅ Schema definition loaded")