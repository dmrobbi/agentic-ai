"""Structured output schemas for agent responses."""
from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, Dict, Any, List, Union
from datetime import datetime


def _coerce_datetime(v: Any) -> str:
    """Coerce datetime objects to ISO strings for Pydantic fields."""
    if isinstance(v, datetime):
        return v.isoformat()
    return v if v is not None else ""


class AgentResponse(BaseModel):
    """Base response model for all agent operations."""
    model_config = ConfigDict(extra="allow")  # Allow extra fields for backward compat

    status: str = "ok"
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class SecurityAssessment(AgentResponse):
    """Security assessment response."""
    assessment_id: str = ""
    title: str = ""
    assessment_type: str = ""
    scope: str = ""
    assessor: str = ""
    status: str = "planned"
    risk_level: str = "medium"
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: Any = ""
    updated_at: Any = ""

    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def coerce_dt(cls, v):
        return _coerce_datetime(v)


class SecurityControl(AgentResponse):
    """Security control response."""
    control_id: str = ""
    name: str = ""
    control_type: str = ""
    category: str = ""
    status: str = "active"
    implementation: str = ""
    effectiveness: str = "moderate"
    owner: str = ""


class ComplianceAssessment(AgentResponse):
    """Compliance assessment response."""
    assessment_id: str = ""
    title: str = ""
    name: str = ""  # Alias for title
    framework: str = ""
    scope: str = ""
    assessor: str = ""
    assessment_type: str = ""
    status: str = "planned"
    compliance_score: float = 0.0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    controls_evaluated: List[str] = Field(default_factory=list)
    created_at: Any = ""

    @field_validator('created_at', mode='before')
    @classmethod
    def coerce_dt(cls, v):
        return _coerce_datetime(v)


class IncidentReport(AgentResponse):
    """Security incident report response."""
    incident_id: str = ""
    title: str = ""
    severity: str = "medium"
    status: str = "open"
    description: str = ""
    affected_systems: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    category: str = ""
    detected_at: Any = ""
    source_ip: str = ""
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    response_actions: List[str] = Field(default_factory=list)
    reporter: str = ""
    created_at: Any = ""

    @field_validator('created_at', mode='before')
    @classmethod
    def coerce_dt(cls, v):
        return _coerce_datetime(v)


class LegalMatter(AgentResponse):
    """Legal matter response."""
    matter_id: str = ""
    title: str = ""
    matter_type: str = ""
    status: str = "open"
    priority: str = "medium"
    description: str = ""
    parties: List[str] = Field(default_factory=list)
    key_dates: Dict[str, str] = Field(default_factory=dict)
    assigned_to: str = ""
    created_at: Any = ""

    @field_validator('created_at', mode='before')
    @classmethod
    def coerce_dt(cls, v):
        return _coerce_datetime(v)