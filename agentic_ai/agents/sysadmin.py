"""
SysAdmin Agent — System administration and infrastructure management.

Part of the agentic-ai multi-agent system. Handles system monitoring,
incident management, configuration, and infrastructure operations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None


@dataclass
class SystemCheck:
    check_id: str
    name: str
    status: str = "healthy"  # healthy, degraded, unhealthy
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: Dict[str, Any] = field(default_factory=dict)


class SysAdminAgent:
    """System administration agent for infrastructure management."""

    agent_type = "sysadmin"

    def __init__(self, inference_engine=None, state_store=None, message_bus=None):
        self.inference_engine = inference_engine
        self.state_store = state_store
        self.message_bus = message_bus
        self.incidents: List[Incident] = []
        self.checks: List[SystemCheck] = []
        self._tools = {
            "create_incident": self.create_incident,
            "check_system": self.check_system,
            "run_command": self.run_command,
            "list_incidents": self.list_incidents,
            "resolve_incident": self.resolve_incident,
            "get_system_status": self.get_system_status,
        }

    @property
    def tools(self):
        return list(self._tools.keys())

    def create_incident(self, title: str, severity: str = "medium",
                        description: str = "") -> Incident:
        severity_enum = IncidentSeverity(severity.lower())
        incident_id = f"INC-{len(self.incidents)+1:04d}"
        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity_enum,
            description=description,
        )
        self.incidents.append(incident)
        logger.info(f"Created incident {incident_id}: {title}")
        return incident

    def check_system(self, name: str = "default") -> SystemCheck:
        check_id = f"CHK-{len(self.checks)+1:04d}"
        check = SystemCheck(
            check_id=check_id,
            name=name,
            status="healthy",
            message="All systems operational",
        )
        self.checks.append(check)
        return check

    def run_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Simulate running a system command (safe — no actual execution)."""
        return {
            "command": command,
            "exit_code": 0,
            "stdout": f"Simulated execution of: {command}",
            "stderr": "",
            "timed_out": False,
        }

    def list_incidents(self, status: Optional[str] = None) -> List[Incident]:
        if status:
            status_enum = IncidentStatus(status.lower())
            return [i for i in self.incidents if i.status == status_enum]
        return self.incidents

    def resolve_incident(self, incident_id: str,
                         resolution: str = "") -> Optional[Incident]:
        for incident in self.incidents:
            if incident.incident_id == incident_id:
                incident.status = IncidentStatus.RESOLVED
                incident.resolution = resolution
                incident.updated_at = datetime.now()
                return incident
        return None

    def get_system_status(self) -> Dict[str, Any]:
        return {
            "total_incidents": len(self.incidents),
            "open_incidents": len([i for i in self.incidents
                                   if i.status == IncidentStatus.OPEN]),
            "critical_incidents": len([i for i in self.incidents
                                       if i.severity == IncidentSeverity.CRITICAL]),
            "total_checks": len(self.checks),
            "healthy_checks": len([c for c in self.checks
                                   if c.status == "healthy"]),
        }