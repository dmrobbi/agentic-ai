"""
SecurityOperationsAgent - SOC & Incident Response
==================================================

Provides SIEM integration, alert triage, incident response,
threat hunting, and security operations center automation.
"""

from agentic_ai.agents.base import BaseAgent
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from agentic_ai.infrastructure.utils import utcnow
from agentic_ai.infrastructure.wazuh_client import (
    WazuhPoller,
    WazuhPollerConfig,
    SeenStore,
    alert_to_soc_kwargs,
)
from agentic_ai.agents.schemas import IncidentReport


logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status states."""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class IncidentSeverity(Enum):
    """Incident severity levels."""
    CRITICAL = "critical"  # Active breach
    HIGH = "high"  # Confirmed compromise
    MEDIUM = "medium"  # Suspicious activity
    LOW = "low"  # Policy violation

    # Backward compatibility properties
    @property
    def sev1(self):
        return IncidentSeverity.CRITICAL

    @property
    def sev2(self):
        return IncidentSeverity.HIGH

    @property
    def sev3(self):
        return IncidentSeverity.MEDIUM

    @property
    def sev4(self):
        return IncidentSeverity.LOW


class IncidentStatus(Enum):
    """Incident status states."""
    DETECTED = "detected"
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"
    LESSONS_LEARNED = "lessons_learned"


class ThreatActor(Enum):
    """Threat actor types."""
    APT = "apt"  # Advanced Persistent Threat
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    SCRIPT_KIDDIE = "script_kiddie"
    UNKNOWN = "unknown"


@dataclass
class SecurityAlert:
    """Security alert from SIEM."""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str  # SIEM, IDS, EDR, etc.
    rule_name: str
    affected_asset: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    timestamp: datetime = field(default_factory=utcnow)
    assigned_to: Optional[str] = None
    investigation_notes: List[str] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)


@dataclass
class Incident:
    """Security incident."""
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    category: str = ""  # malware, phishing, data_breach, unauthorized_access, etc.
    description: str = ""
    threat_actor: Optional[ThreatActor] = None
    detected_at: datetime = field(default_factory=utcnow)
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    ioc: Dict[str, Any] = field(default_factory=dict)  # Indicators of Compromise
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    root_cause: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)


@dataclass
class ThreatIntel:
    """Threat intelligence indicator."""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    threat_type: str
    confidence: str  # low, medium, high
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    related_campaigns: List[str] = field(default_factory=list)


@dataclass
class HuntQuery:
    """Threat hunting query."""
    hunt_id: str
    name: str
    hypothesis: str
    query: str
    data_source: str
    status: str  # planned, running, completed
    findings: List[Dict[str, Any]] = field(default_factory=list)
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=utcnow)
    completed_at: Optional[datetime] = None


class SecurityOperationsAgent(BaseAgent):
    """
    Security Operations Agent for SIEM integration,
    incident response, and threat hunting.
    """

    def __init__(
        self,
        agent_id: str = "soc-agent",
        wazuh_poller: Optional[WazuhPoller] = None,
    ):
        super().__init__(agent_id=agent_id)
        self.agent_id = agent_id
        self.alerts: Dict[str, SecurityAlert] = {}
        self.incidents: Dict[str, Incident] = {}
        self.threat_intel: Dict[str, ThreatIntel] = {}
        self.hunts: Dict[str, HuntQuery] = {}
        self.wazuh_poller: Optional[WazuhPoller] = wazuh_poller

        # MITRE ATT&CK mapping
        self.attack_tactics = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact',
        }

        # Alert rules library
        self.alert_rules = self._init_alert_rules()

    def _init_alert_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize detection rule library."""
        return {
            'brute_force': {
                'name': 'Brute Force Login Detection',
                'severity': AlertSeverity.MEDIUM,
                'description': 'Multiple failed login attempts from same source',
                'threshold': 5,
                'window_minutes': 10,
            },
            'privilege_escalation': {
                'name': 'Privilege Escalation Attempt',
                'severity': AlertSeverity.HIGH,
                'description': 'User attempting to access elevated privileges',
            },
            'data_exfiltration': {
                'name': 'Potential Data Exfiltration',
                'severity': AlertSeverity.CRITICAL,
                'description': 'Large data transfer to external destination',
            },
            'malware_execution': {
                'name': 'Malware Execution Detected',
                'severity': AlertSeverity.CRITICAL,
                'description': 'Known malware signature or behavior detected',
            },
            'lateral_movement': {
                'name': 'Lateral Movement Detected',
                'severity': AlertSeverity.HIGH,
                'description': 'Unusual internal network connections',
            },
            'phishing_email': {
                'name': 'Phishing Email Detected',
                'severity': AlertSeverity.MEDIUM,
                'description': 'Email with suspicious characteristics',
            },
            'unauthorized_access': {
                'name': 'Unauthorized Access Attempt',
                'severity': AlertSeverity.HIGH,
                'description': 'Access attempt to restricted resource',
            },
            'anomalous_behavior': {
                'name': 'Anomalous User Behavior',
                'severity': AlertSeverity.MEDIUM,
                'description': 'User behavior deviates from baseline',
            },
        }

    # ============================================
    # Alert Management
    # ============================================

    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        rule_name: str,
        affected_asset: str,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        user: Optional[str] = None,
    ) -> SecurityAlert:
        """Create a security alert."""
        alert = SecurityAlert(
            alert_id=self._generate_id("alert"),
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.NEW,
            source=source,
            rule_name=rule_name,
            affected_asset=affected_asset,
            source_ip=source_ip,
            dest_ip=dest_ip,
            user=user,
        )

        self.alerts[alert.alert_id] = alert
        logger.info(f"Created alert: {alert.title} ({alert.severity.value})")
        return alert

    def triage_alert(
        self,
        alert_id: str,
        status: AlertStatus,
        assigned_to: Optional[str] = None,
        notes: str = "",
    ) -> bool:
        """Triage a security alert."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = status

        if assigned_to:
            alert.assigned_to = assigned_to

        if notes:
            alert.investigation_notes.append(f"[{utcnow().isoformat()}] {notes}")

        return True

    def escalate_alert(self, alert_id: str, incident_id: str) -> bool:
        """Escalate alert to incident."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = AlertStatus.ESCALATED

        if incident_id in self.incidents:
            self.incidents[incident_id].related_alerts.append(alert_id)
            alert.related_alerts.append(incident_id)

        return True

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        assigned_to: Optional[str] = None,
    ) -> List[SecurityAlert]:
        """Get alerts with filtering."""
        alerts = list(self.alerts.values())

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        if status:
            alerts = [a for a in alerts if a.status == status]

        if assigned_to:
            alerts = [a for a in alerts if a.assigned_to == assigned_to]

        return alerts

    # ============================================
    # Incident Management
    # ============================================

    def report_security_incident(self, title: str, description: str = "", severity: str = "high", incident_type: str = "", affected_systems: Optional[List[str]] = None, source_ip: str = "", target_user: str = "", **kwargs) -> Any:
        """Report a security incident. Convenience method that maps to create_incident.
        Returns the incident with string severity preserved."""
        severity_map = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW,
        }
        incident_severity = severity_map.get(severity, IncidentSeverity.MEDIUM)
        incident = self.create_incident(
            title=title,
            severity=incident_severity,
            category=incident_type or "unauthorized_access",
            affected_systems=affected_systems or [],
        )
        incident.description = description
        if source_ip:
            incident.source_ip = source_ip  # type: ignore[attr-defined]
        if target_user:
            incident.affected_users = [target_user]
        # Return a wrapper that preserves the string severity
        result = IncidentReport(  # type: ignore[arg-type,call-arg]
            incident_id=incident.incident_id,
            title=incident.title,
            severity=severity,
            status=str(incident.status.value) if hasattr(incident.status, 'value') else str(incident.status),
            category=incident.category,
            description=description,
            affected_systems=incident.affected_systems,
            affected_users=incident.affected_users,
            source_ip=source_ip or "",
            detected_at=str(incident.detected_at),
            _incident=incident,
        )
        return result

    def create_incident(
        self,
        title: str,
        severity: IncidentSeverity,
        category: str,
        threat_actor: Optional[ThreatActor] = None,
        affected_systems: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
    ) -> Incident:
        """Create a security incident."""
        incident = Incident(
            incident_id=self._generate_id("inc"),
            title=title,
            severity=severity,
            status=IncidentStatus.DETECTED,
            category=category,
            threat_actor=threat_actor,
            affected_systems=affected_systems or [],
            affected_users=affected_users or [],
        )

        self.incidents[incident.incident_id] = incident
        logger.info(f"Created incident: {incident.title} ({incident.severity.value})")
        return incident

    def update_incident_status(
        self,
        incident_id: str,
        status,
        notes: str = "",
    ) -> bool:
        """Update incident status. Accepts IncidentStatus enum or string."""
        if incident_id not in self.incidents:
            return False

        # Convert string to IncidentStatus if needed
        if isinstance(status, str):
            status_map = {s.value: s for s in IncidentStatus}
            status = status_map.get(status, IncidentStatus.CLOSED)

        incident = self.incidents[incident_id]
        old_status = incident.status
        incident.status = status

        # Track timeline
        incident.timeline.append({
            'timestamp': utcnow().isoformat(),
            'action': 'status_change',
            'from': old_status.value,
            'to': status.value,
            'notes': notes,
        })

        # Set timestamps for key milestones
        if status == IncidentStatus.CONTAINMENT and old_status != IncidentStatus.CONTAINMENT:
            incident.contained_at = utcnow()
        elif status == IncidentStatus.CLOSED:
            incident.resolved_at = utcnow()

        return True

    def add_ioc(
        self,
        incident_id: str,
        ioc_type: str,
        ioc_value: str,
        context: str = "",
    ) -> bool:
        """Add indicator of compromise to incident."""
        if incident_id not in self.incidents:
            return False

        incident = self.incidents[incident_id]

        if ioc_type not in incident.ioc:
            incident.ioc[ioc_type] = []

        incident.ioc[ioc_type].append({
            'value': ioc_value,
            'context': context,
            'added_at': utcnow().isoformat(),
        })

        return True

    def add_timeline_entry(
        self,
        incident_id: str,
        action: str,
        details: str,
        actor: Optional[str] = None,
    ) -> bool:
        """Add entry to incident timeline."""
        if incident_id not in self.incidents:
            return False

        incident = self.incidents[incident_id]
        incident.timeline.append({
            'timestamp': utcnow().isoformat(),
            'action': action,
            'details': details,
            'actor': actor,
        })

        return True

    def close_incident(
        self,
        incident_id: str,
        root_cause: str,
        remediation_steps: List[str],
        lessons_learned: List[str],
    ) -> bool:
        """Close an incident with full documentation."""
        if incident_id not in self.incidents:
            return False

        incident = self.incidents[incident_id]
        incident.status = IncidentStatus.CLOSED
        incident.resolved_at = utcnow()
        incident.root_cause = root_cause
        incident.remediation_steps = remediation_steps
        incident.lessons_learned = lessons_learned

        return True

    def get_incidents(
        self,
        severity: Optional[IncidentSeverity] = None,
        status: Optional[IncidentStatus] = None,
        category: Optional[str] = None,
    ) -> List[Incident]:
        """Get incidents with filtering."""
        incidents = list(self.incidents.values())

        if severity:
            incidents = [i for i in incidents if i.severity == severity]

        if status:
            incidents = [i for i in incidents if i.status == status]

        if category:
            incidents = [i for i in incidents if i.category == category]

        return incidents

    # ============================================
    # Threat Intelligence
    # ============================================

    def add_threat_intel(
        self,
        indicator_type: str,
        value: str,
        threat_type: str,
        confidence: str,
        source: str,
        tags: Optional[List[str]] = None,
    ) -> ThreatIntel:
        """Add threat intelligence indicator."""
        now = utcnow()

        intel = ThreatIntel(
            indicator_id=self._generate_id("intel"),
            indicator_type=indicator_type,
            value=value,
            threat_type=threat_type,
            confidence=confidence,
            source=source,
            first_seen=now,
            last_seen=now,
            tags=tags or [],
        )

        self.threat_intel[intel.indicator_id] = intel
        return intel

    def search_threat_intel(self, value: str) -> List[ThreatIntel]:
        """Search threat intel by value."""
        return [
            intel for intel in self.threat_intel.values()
            if intel.value == value or value in intel.value
        ]

    def get_threat_intel(
        self,
        indicator_type: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[ThreatIntel]:
        """Get threat intel with filtering."""
        intel = list(self.threat_intel.values())

        if indicator_type:
            intel = [i for i in intel if i.indicator_type == indicator_type]

        if confidence:
            intel = [i for i in intel if i.confidence == confidence]

        return intel

    # ============================================
    # Threat Hunting
    # ============================================

    def create_hunt(
        self,
        name: str,
        hypothesis: str,
        query: str,
        data_source: str,
        created_by: Optional[str] = None,
    ) -> HuntQuery:
        """Create a threat hunting query."""
        hunt = HuntQuery(
            hunt_id=self._generate_id("hunt"),
            name=name,
            hypothesis=hypothesis,
            query=query,
            data_source=data_source,
            status="planned",
            created_by=created_by,
        )

        self.hunts[hunt.hunt_id] = hunt
        return hunt

    def execute_hunt(self, hunt_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Execute a threat hunt and record findings."""
        if hunt_id not in self.hunts:
            return False

        hunt = self.hunts[hunt_id]
        hunt.status = "completed"
        hunt.findings = findings
        hunt.completed_at = utcnow()

        return True

    def get_hunts(self, status: Optional[str] = None) -> List[HuntQuery]:
        """Get hunts with filtering."""
        hunts = list(self.hunts.values())

        if status:
            hunts = [h for h in hunts if h.status == status]

        return hunts

    # ============================================
    # SOC Metrics & Reporting
    # ============================================

    def get_soc_metrics(self, period_hours: int = 24) -> Dict[str, Any]:
        """Get SOC operational metrics."""
        cutoff = utcnow() - timedelta(hours=period_hours)

        recent_alerts = [a for a in self.alerts.values() if a.timestamp >= cutoff]
        recent_incidents = [i for i in self.incidents.values() if i.detected_at >= cutoff]

        # Alert metrics
        alerts_by_severity = {}
        for severity in AlertSeverity:
            alerts_by_severity[severity.value] = len([
                a for a in recent_alerts if a.severity == severity
            ])

        # Incident metrics
        incidents_by_severity = {}
        for severity in IncidentSeverity:  # type: ignore[assignment]
            incidents_by_severity[severity.value] = len([
                i for i in recent_incidents if i.severity == severity
            ])

        # MTTR (Mean Time to Resolve)
        resolved = [i for i in recent_incidents if i.resolved_at]
        mttr_hours = 0
        if resolved:
            total_time = sum(
                (i.resolved_at - i.detected_at).total_seconds() / 3600  # type: ignore[misc,operator]
                for i in resolved if i.resolved_at > i.detected_at  # type: ignore[operator]
            )
            mttr_hours = total_time / len(resolved)  # type: ignore[assignment]

        return {
            'period_hours': period_hours,
            'alerts': {
                'total': len(recent_alerts),
                'by_severity': alerts_by_severity,
                'new': len([a for a in recent_alerts if a.status == AlertStatus.NEW]),
                'investigating': len([a for a in recent_alerts if a.status == AlertStatus.INVESTIGATING]),
            },
            'incidents': {
                'total': len(recent_incidents),
                'by_severity': incidents_by_severity,
                'active': len([i for i in recent_incidents if i.status != IncidentStatus.CLOSED]),
            },
            'response': {
                'mttr_hours': round(mttr_hours, 2),
                'resolved_count': len(resolved),
            },
            'threat_intel': {
                'indicators': len(self.threat_intel),
                'high_confidence': len([i for i in self.threat_intel.values() if i.confidence == 'high']),
            },
        }

    def get_attack_mapping(self, incident_id: str) -> Dict[str, Any]:
        """Map incident to MITRE ATT&CK framework."""
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}

        incident = self.incidents[incident_id]

        # Simple mapping based on category
        category_mapping = {
            'malware': ['TA0002', 'TA0003', 'TA0011'],
            'phishing': ['TA0001', 'TA0002'],
            'data_breach': ['TA0009', 'TA0010'],
            'unauthorized_access': ['TA0001', 'TA0004', 'TA0006'],
            'lateral_movement': ['TA0008'],
        }

        tactics = category_mapping.get(incident.category, [])

        return {
            'incident_id': incident_id,
            'category': incident.category,
            'tactics': [
                {'id': t, 'name': self.attack_tactics.get(t, 'Unknown')}
                for t in tactics
            ],
        }

    # ============================================
    # Utilities
    # ============================================


    def get_state(self) -> Dict[str, Any]:
        """Get agent state summary."""
        return {
            'agent_id': self.agent_id,
            'alerts_count': len(self.alerts),
            'active_alerts': len([a for a in self.alerts.values() if a.status not in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]]),
            'incidents_count': len(self.incidents),
            'active_incidents': len([i for i in self.incidents.values() if i.status != IncidentStatus.CLOSED]),
            'threat_intel_count': len(self.threat_intel),
            'hunts_count': len(self.hunts),
            'wazuh_poller': self.wazuh_poller.status() if self.wazuh_poller else None,
        }

    # ============================================
    # Wazuh integration
    # ============================================

    def ingest_wazuh_alert(self, wazuh_alert: Dict[str, Any]) -> SecurityAlert:
        """Convert one Wazuh alert JSON into a SecurityAlert and add to local state.

        Returns the SecurityAlert. The caller can decide whether to escalate to
        an incident based on severity.
        """
        kw = alert_to_soc_kwargs(wazuh_alert)
        try:
            severity_enum = AlertSeverity(kw["severity"])
        except ValueError:
            severity_enum = AlertSeverity.INFORMATIONAL
        alert = self.create_alert(
            title=kw["title"][:200],
            description=kw["description"][:500],
            severity=severity_enum,
            source=kw["source"],
            rule_name=str(kw["rule_name"]),
            affected_asset=str(kw["affected_asset"])[:200],
            source_ip=kw.get("source_ip"),
        )
        # Auto-escalate high/critical to incidents
        if severity_enum in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            self.escalate_alert(alert.alert_id, "")
            try:
                incident = self.create_incident(
                    title=f"Wazuh {kw['rule_name']} on {kw['affected_asset']}",
                    description=kw["description"],
                    severity=IncidentSeverity.HIGH if severity_enum == AlertSeverity.HIGH else IncidentSeverity.CRITICAL,
                    category="wazuh_alert",
                    threat_actor=ThreatActor.UNKNOWN,
                )
                # Link alert to incident by stamping note
                alert.investigation_notes.append(
                    f"[{utcnow().isoformat()}] auto-escalated to incident {incident.incident_id}"
                )
            except Exception as exc:
                logger.warning("auto-escalate failed: %s", exc)
        return alert

    def ingest_wazuh_alerts(self, alerts: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """Ingest a batch of Wazuh alerts."""
        out = []
        for a in alerts:
            try:
                out.append(self.ingest_wazuh_alert(a))
            except Exception as exc:
                logger.warning("ingest failed for one alert: %s", exc)
        return out

    def start_wazuh_poller(
        self,
        base_url: str = "https://192.168.1.106:55000",
        username: str = "wazuh-wui",
        password: Optional[str] = None,
        poll_interval_sec: int = 15,
    ) -> WazuhPoller:
        """Build a WazuhPoller that calls ingest_wazuh_alerts on each poll.

        Returns the running poller (also stored on self.wazuh_poller).
        """
        cfg = WazuhPollerConfig(
            base_url=base_url,
            username=username,
            password=password,
            poll_interval_sec=poll_interval_sec,
            on_alerts=self.ingest_wazuh_alerts,
        )
        self.wazuh_poller = WazuhPoller(cfg)
        self.wazuh_poller.start()
        return self.wazuh_poller

    def stop_wazuh_poller(self) -> None:
        if self.wazuh_poller:
            self.wazuh_poller.stop()
            self.wazuh_poller = None

    def get_wazuh_metrics(self) -> Dict[str, Any]:
        """Combined local+poller status, suitable for a daily report."""
        local = self.get_soc_metrics()
        poller = self.wazuh_poller.status() if self.wazuh_poller else None
        return {
            "agent_id": self.agent_id,
            "soc": local,
            "wazuh_poller": poller,
        }


def get_capabilities() -> Dict[str, Any]:
    """Return agent capabilities for orchestration."""
    return {
        'agent_type': 'soc',
        'version': '1.0.0',
        'capabilities': [
            'create_alert',
            'triage_alert',
            'escalate_alert',
            'get_alerts',
            'create_incident',
            'update_incident_status',
            'add_ioc',
            'add_timeline_entry',
            'close_incident',
            'get_incidents',
            'add_threat_intel',
            'search_threat_intel',
            'get_threat_intel',
            'create_hunt',
            'execute_hunt',
            'get_hunts',
            'get_soc_metrics',
            'get_attack_mapping',
        ],
        'alert_severities': [s.value for s in AlertSeverity],
        'alert_statuses': [s.value for s in AlertStatus],
        'incident_severities': [s.value for s in IncidentSeverity],
        'incident_statuses': [s.value for s in IncidentStatus],
        'threat_actors': [a.value for a in ThreatActor],
        'attack_tactics': list(SecurityOperationsAgent(None).attack_tactics.keys()),  # type: ignore[arg-type]
    }


if __name__ == "__main__":
    agent = SecurityOperationsAgent()

    # Create alert
    alert = agent.create_alert(
        title="Brute Force Attack Detected",
        description="Multiple failed login attempts from 192.168.1.100",
        severity=AlertSeverity.MEDIUM,
        source="SIEM",
        rule_name="brute_force",
        affected_asset="auth-server-01",
        source_ip="192.168.1.100",
        user="admin",
    )

    print(f"Created alert: {alert.title}")

    # Triage alert
    agent.triage_alert(alert.alert_id, AlertStatus.INVESTIGATING, assigned_to="analyst@soc.com")

    # Create incident
    incident = agent.create_incident(
        title="Ransomware Infection",
        severity=IncidentSeverity.CRITICAL,
        category="malware",
        threat_actor=ThreatActor.CYBERCRIMINAL,
        affected_systems=["workstation-42", "file-server-01"],
    )

    print(f"Created incident: {incident.title}")

    # Add IOC
    agent.add_ioc(incident.incident_id, "hash", "abc123def456", "Ransomware payload hash")
    agent.add_ioc(incident.incident_id, "ip", "10.0.0.99", "C2 server")

    # Add timeline
    agent.add_timeline_entry(incident.incident_id, "detection", "EDR detected suspicious process", actor="EDR")
    agent.add_timeline_entry(incident.incident_id, "containment", "Isolated affected systems", actor="SOC")

    # Add threat intel
    intel = agent.add_threat_intel(
        indicator_type="ip",
        value="10.0.0.99",
        threat_type="c2_server",
        confidence="high",
        source="internal",
        tags=['ransomware', 'apt'],
    )

    print(f"Added threat intel: {intel.value}")

    # Create hunt
    hunt = agent.create_hunt(
        name="Hunt for Lateral Movement",
        hypothesis="Attacker may be moving laterally using compromised credentials",
        query="EventID=4624 | stats count by src_ip, dest_ip",
        data_source="windows_events",
        created_by="hunter@soc.com",
    )

    # Get metrics
    metrics = agent.get_soc_metrics()
    print(f"\nAlerts (24h): {metrics['alerts']['total']}")
    print(f"Incidents (24h): {metrics['incidents']['total']}")
    print(f"MTTR: {metrics['response']['mttr_hours']}h")

    print(f"\nState: {agent.get_state()}")
