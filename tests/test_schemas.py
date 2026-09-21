"""Tests for structured output schemas and Pydantic model validation."""
import json
import pytest
from agentic_ai.agents.schemas import (
    AgentResponse,
    SecurityAssessment,
    SecurityControl,
    ComplianceAssessment,
    IncidentReport,
    LegalMatter,
)


# ============================================
# AgentResponse base model
# ============================================

class TestAgentResponse:
    """Tests for the base AgentResponse model."""

    def test_creates_with_defaults(self):
        r = AgentResponse()
        assert r.status == "ok"
        assert r.data is None
        assert r.error is None

    def test_creates_with_all_fields(self):
        r = AgentResponse(status="error", data={"key": "val"}, error="something failed")
        assert r.status == "error"
        assert r.data == {"key": "val"}
        assert r.error == "something failed"

    def test_allows_extra_fields(self):
        """Backward compat: extra fields should be accepted."""
        r = AgentResponse(status="ok", extra_field="hello", another=42)
        assert r.extra_field == "hello"
        assert r.another == 42

    def test_serializes_to_dict(self):
        r = AgentResponse(status="ok", data={"x": 1})
        d = r.model_dump()
        assert isinstance(d, dict)
        assert d["status"] == "ok"
        assert d["data"] == {"x": 1}

    def test_serializes_to_json(self):
        r = AgentResponse(status="ok")
        j = r.model_dump_json()
        parsed = json.loads(j)
        assert parsed["status"] == "ok"

    def test_deserializes_from_dict(self):
        d = {"status": "error", "data": None, "error": "oops"}
        r = AgentResponse(**d)
        assert r.status == "error"
        assert r.error == "oops"


# ============================================
# SecurityAssessment
# ============================================

class TestSecurityAssessment:
    """Tests for SecurityAssessment model."""

    def test_creates_with_defaults(self):
        s = SecurityAssessment()
        assert s.assessment_id == ""
        assert s.title == ""
        assert s.status == "planned"
        assert s.risk_level == "medium"
        assert s.findings == []
        assert s.recommendations == []

    def test_creates_with_all_fields(self):
        s = SecurityAssessment(
            assessment_id="assess-123",
            title="Test Assessment",
            assessment_type="pen_test",
            scope="internal",
            assessor="alice",
            status="in_progress",
            risk_level="high",
            findings=[{"id": 1, "desc": "XSS"}],
            recommendations=["Fix XSS", "Update deps"],
            created_at="2026-01-01T00:00:00",
            updated_at="2026-01-02T00:00:00",
        )
        assert s.assessment_id == "assess-123"
        assert s.title == "Test Assessment"
        assert s.risk_level == "high"
        assert len(s.findings) == 1
        assert len(s.recommendations) == 2

    def test_allows_extra_fields(self):
        """target_vendor is an extra field from security.py."""
        s = SecurityAssessment(assessment_id="a1", title="T", target_vendor="acme")
        assert s.target_vendor == "acme"

    def test_serializes_to_dict(self):
        s = SecurityAssessment(assessment_id="a1", title="T")
        d = s.model_dump()
        assert d["assessment_id"] == "a1"
        assert d["title"] == "T"

    def test_serializes_to_json(self):
        s = SecurityAssessment(assessment_id="a1", title="T")
        j = s.model_dump_json()
        parsed = json.loads(j)
        assert parsed["assessment_id"] == "a1"

    def test_deserializes_from_dict(self):
        d = {"assessment_id": "a1", "title": "T", "status": "planned"}
        s = SecurityAssessment(**d)
        assert s.assessment_id == "a1"
        assert s.title == "T"


# ============================================
# SecurityControl
# ============================================

class TestSecurityControl:
    """Tests for SecurityControl model."""

    def test_creates_with_defaults(self):
        c = SecurityControl()
        assert c.control_id == ""
        assert c.name == ""
        assert c.status == "active"
        assert c.effectiveness == "moderate"

    def test_creates_with_all_fields(self):
        c = SecurityControl(
            control_id="ctrl-1",
            name="MFA",
            control_type="preventive",
            category="access",
            status="effective",
            implementation="fully deployed",
            effectiveness="high",
            owner="security-team",
        )
        assert c.control_id == "ctrl-1"
        assert c.name == "MFA"
        assert c.effectiveness == "high"

    def test_allows_extra_fields(self):
        """assessment_id and description are extra fields from security.py."""
        c = SecurityControl(control_id="c1", name="N", assessment_id="a1", description="desc")
        assert c.assessment_id == "a1"
        assert c.description == "desc"

    def test_serializes_to_dict(self):
        c = SecurityControl(control_id="c1", name="N")
        d = c.model_dump()
        assert d["control_id"] == "c1"

    def test_deserializes_from_dict(self):
        d = {"control_id": "c1", "name": "Test"}
        c = SecurityControl(**d)
        assert c.control_id == "c1"


# ============================================
# ComplianceAssessment
# ============================================

class TestComplianceAssessment:
    """Tests for ComplianceAssessment model."""

    def test_creates_with_defaults(self):
        c = ComplianceAssessment()
        assert c.assessment_id == ""
        assert c.title == ""
        assert c.framework == ""
        assert c.status == "planned"
        assert c.compliance_score == 0.0
        assert c.findings == []
        assert c.controls_evaluated == []

    def test_creates_with_all_fields(self):
        c = ComplianceAssessment(
            assessment_id="assess-1",
            title="SOC2 Review",
            framework="SOC2",
            scope="Cloud",
            assessor="bob",
            status="completed",
            compliance_score=0.85,
            findings=[{"ctrl": "MFA", "pass": True}],
            controls_evaluated=["CC6.1", "CC6.2"],
            created_at="2026-01-01",
        )
        assert c.assessment_id == "assess-1"
        assert c.compliance_score == 0.85
        assert len(c.findings) == 1
        assert len(c.controls_evaluated) == 2

    def test_allows_extra_fields(self):
        """name and assessment_type are extra fields from compliance.py."""
        c = ComplianceAssessment(assessment_id="a1", name="Review", assessment_type="annual")
        assert c.name == "Review"
        assert c.assessment_type == "annual"

    def test_serializes_to_dict(self):
        c = ComplianceAssessment(assessment_id="a1")
        d = c.model_dump()
        assert d["assessment_id"] == "a1"

    def test_deserializes_from_dict(self):
        d = {"assessment_id": "a1", "title": "T", "status": "planned"}
        c = ComplianceAssessment(**d)
        assert c.assessment_id == "a1"


# ============================================
# IncidentReport
# ============================================

class TestIncidentReport:
    """Tests for IncidentReport model."""

    def test_creates_with_defaults(self):
        r = IncidentReport()
        assert r.incident_id == ""
        assert r.title == ""
        assert r.severity == "medium"
        assert r.status == "open"
        assert r.affected_systems == []
        assert r.timeline == []
        assert r.response_actions == []

    def test_creates_with_all_fields(self):
        r = IncidentReport(
            incident_id="inc-1",
            title="Breach",
            severity="critical",
            status="investigating",
            description="Data exfiltration",
            affected_systems=["db", "api"],
            timeline=[{"t": "10:00", "event": "detected"}],
            response_actions=["isolate", "notify"],
            reporter="soc",
            created_at="2026-01-01",
        )
        assert r.incident_id == "inc-1"
        assert r.severity == "critical"
        assert len(r.affected_systems) == 2
        assert len(r.response_actions) == 2

    def test_allows_extra_fields(self):
        """category, affected_users, source_ip, detected_at, _incident are extra from soc.py."""
        r = IncidentReport(
            incident_id="inc-1",
            title="T",
            category="unauthorized_access",
            affected_users=["admin"],
            source_ip="198.51.100.1",
            detected_at="2026-01-01",
            _incident="mock",
        )
        assert r.category == "unauthorized_access"
        assert r.source_ip == "198.51.100.1"
        assert r._incident == "mock"

    def test_serializes_to_dict(self):
        r = IncidentReport(incident_id="inc-1")
        d = r.model_dump()
        assert d["incident_id"] == "inc-1"

    def test_deserializes_from_dict(self):
        d = {"incident_id": "inc-1", "title": "T", "severity": "high"}
        r = IncidentReport(**d)
        assert r.incident_id == "inc-1"
        assert r.severity == "high"


# ============================================
# LegalMatter
# ============================================

class TestLegalMatter:
    """Tests for LegalMatter model."""

    def test_creates_with_defaults(self):
        m = LegalMatter()
        assert m.matter_id == ""
        assert m.title == ""
        assert m.matter_type == ""
        assert m.status == "open"
        assert m.parties == []
        assert m.key_dates == {}

    def test_creates_with_all_fields(self):
        m = LegalMatter(
            matter_id="legal-1",
            title="Contract Review",
            matter_type="contract_review",
            status="in_progress",
            description="MSA review",
            parties=["Acme Corp", "Beta LLC"],
            key_dates={"filing": "2026-01-01", "deadline": "2026-06-01"},
            assigned_to="legal-team",
            created_at="2026-01-01",
        )
        assert m.matter_id == "legal-1"
        assert len(m.parties) == 2
        assert m.key_dates["filing"] == "2026-01-01"

    def test_allows_extra_fields(self):
        """priority is an extra field from legal.py."""
        m = LegalMatter(matter_id="l1", title="T", priority="urgent")
        assert m.priority == "urgent"

    def test_serializes_to_dict(self):
        m = LegalMatter(matter_id="l1")
        d = m.model_dump()
        assert d["matter_id"] == "l1"

    def test_deserializes_from_dict(self):
        d = {"matter_id": "l1", "title": "T"}
        m = LegalMatter(**d)
        assert m.matter_id == "l1"


# ============================================
# Integration: Agent methods return Pydantic models
# ============================================

class TestAgentMethodReturns:
    """Test that agent methods now return Pydantic model instances."""

    def test_security_create_assessment_returns_model(self):
        from agentic_ai.agents.security import SecurityAgent
        agent = SecurityAgent()
        result = agent.create_assessment(title="Test", assessment_type="vendor")
        assert isinstance(result, SecurityAssessment)
        assert result.assessment_id.startswith("assess-")
        assert result.title == "Test"

    def test_security_add_control_returns_model(self):
        from agentic_ai.agents.security import SecurityAgent
        agent = SecurityAgent()
        assessment = agent.create_assessment(title="Test")
        result = agent.add_control(
            assessment_id=assessment.assessment_id,
            name="MFA",
            description="Multi-factor auth",
            control_type="preventive",
            category="access",
        )
        assert isinstance(result, SecurityControl)
        assert result.control_id.startswith("ctrl-")
        assert result.name == "MFA"

    def test_compliance_create_assessment_returns_model(self):
        from agentic_ai.agents.compliance import ComplianceAgent
        agent = ComplianceAgent()
        result = agent.create_assessment(name="Test", assessment_type="annual")
        assert isinstance(result, ComplianceAssessment)
        assert result.assessment_id.startswith("assess-")

    def test_soc_report_incident_returns_model(self):
        from agentic_ai.agents.cyber.soc import SecurityOperationsAgent
        agent = SecurityOperationsAgent()
        result = agent.report_security_incident(
            title="Test Incident",
            description="Something bad",
            severity="high",
        )
        assert isinstance(result, IncidentReport)
        assert result.incident_id.startswith("inc-")
        assert result.severity == "high"

    def test_legal_create_matter_returns_model(self):
        from agentic_ai.agents.legal import LegalAgent
        agent = LegalAgent()
        result = agent.create_legal_matter(
            title="Test Matter",
            matter_type="contract_review",
        )
        assert isinstance(result, LegalMatter)
        assert result.matter_id.startswith("legal-")
        assert result.title == "Test Matter"


# ============================================
# BaseAgent.think() response_model
# ============================================

class TestThinkResponseModel:
    """Test response_model parameter in BaseAgent.think()."""

    @pytest.mark.asyncio
    async def test_think_without_response_model(self):
        from agentic_ai.agents.base import BaseAgent
        agent = BaseAgent(agent_id="test")
        result = await agent.think("What is 2+2?")
        # Without inference engine, returns "Generated response"
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_think_with_response_model_valid_json(self):
        from agentic_ai.agents.base import BaseAgent

        # Create a mock inference engine that returns valid JSON
        class MockEngine:
            def generate(self, prompt, ctx):
                return json.dumps({
                    "assessment_id": "a1",
                    "title": "Test",
                    "assessment_type": "pen_test",
                    "scope": "internal",
                    "assessor": "alice",
                    "status": "planned",
                    "risk_level": "high",
                    "findings": [],
                    "recommendations": [],
                    "created_at": "2026-01-01",
                    "updated_at": "",
                })

        agent = BaseAgent(agent_id="test")
        agent.inference_engine = MockEngine()
        # Bypass guardrails for test
        agent.guardrails = []

        result = await agent.think("Assess security", response_model=SecurityAssessment)
        parsed = json.loads(result)
        assert parsed["assessment_id"] == "a1"
        assert parsed["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_think_with_response_model_invalid_json(self):
        from agentic_ai.agents.base import BaseAgent

        class MockEngine:
            def generate(self, prompt, ctx):
                return "This is not JSON at all"

        agent = BaseAgent(agent_id="test")
        agent.inference_engine = MockEngine()
        agent.guardrails = []

        result = await agent.think("Assess security", response_model=SecurityAssessment)
        # Should return raw result if parsing fails
        assert result == "This is not JSON at all"