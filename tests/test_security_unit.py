"""Unit tests for SecurityAgent."""
import pytest
from agentic_ai.agents.security import (
    SecurityAgent,
    SeverityLevel,
    ThreatType,
    SecurityFinding,
    SecurityIncident,
    SecretRotation,
    SecurityPolicy,
    SimpleStateStore,
)
from agentic_ai.agents.schemas import SecurityAssessment, SecurityControl


class TestSecurityAgentInit:
    def test_default_init(self):
        agent = SecurityAgent()
        assert agent.agent_id == "security-agent"
        assert isinstance(agent.findings, dict)
        assert isinstance(agent.incidents, dict)
        assert isinstance(agent.secret_rotations, dict)
        assert isinstance(agent.policies, dict)
        assert isinstance(agent.access_logs, list)

    def test_custom_id(self):
        agent = SecurityAgent(agent_id="custom-sec-001")
        assert agent.agent_id == "custom-sec-001"

    def test_custom_state_store(self):
        store = SimpleStateStore()
        agent = SecurityAgent(state_store=store)
        assert agent.state_store is store

    def test_default_policies_initialized(self):
        agent = SecurityAgent()
        assert "password-complexity" in agent.policies
        assert "session-timeout" in agent.policies
        assert "rate-limiting" in agent.policies
        assert "secret-rotation" in agent.policies

    def test_permission_levels(self):
        from agentic_ai.agents.base import Permission
        agent = SecurityAgent()
        # BaseAgent default is STANDARD
        assert agent.permission.value == Permission.STANDARD.value


class TestSecurityAgentCreateAssessment:
    def test_create_assessment_basic(self):
        agent = SecurityAgent()
        result = agent.create_assessment(title="Pen Test 2025")
        assert isinstance(result, SecurityAssessment)
        assert result.title == "Pen Test 2025"
        assert result.status == "planned"
        assert result.assessment_id.startswith("assess-")

    def test_create_assessment_with_all_fields(self):
        agent = SecurityAgent()
        result = agent.create_assessment(
            title="Annual Review",
            assessment_type="external",
            scope="All systems",
            assessor="Pentest Co",
            target_vendor="CloudProvider",
        )
        assert result.assessment_type == "external"
        assert result.scope == "All systems"
        assert result.assessor == "Pentest Co"
        assert result.target_vendor == "CloudProvider"

    def test_create_assessment_returns_security_assessment_type(self):
        agent = SecurityAgent()
        result = agent.create_assessment(title="Test")
        assert isinstance(result, SecurityAssessment)

    def test_create_assessment_empty_title(self):
        agent = SecurityAgent()
        result = agent.create_assessment(title="")
        assert result.title == ""


class TestSecurityAgentAddControl:
    def test_add_control_basic(self):
        agent = SecurityAgent()
        result = agent.add_control(
            assessment_id="assess-1",
            name="MFA",
            description="Multi-factor auth",
            control_type="preventive",
            category="authentication",
        )
        assert isinstance(result, SecurityControl)
        assert result.name == "MFA"
        assert result.control_type == "preventive"
        assert result.status == "effective"

    def test_add_control_with_all_fields(self):
        agent = SecurityAgent()
        result = agent.add_control(
            assessment_id="assess-1",
            name="Encryption",
            description="AES-256 at rest",
            control_type="technical",
            category="data_protection",
            status="effective",
        )
        assert result.category == "data_protection"
        assert result.description == "AES-256 at rest"

    def test_add_control_default_status(self):
        agent = SecurityAgent()
        result = agent.add_control(name="Test", description="desc", control_type="admin")
        assert result.status == "effective"


class TestSecurityAgentScanCode:
    def test_scan_clean_code(self):
        agent = SecurityAgent()
        findings = agent.scan_code("x = 1\ny = 2", "clean.py")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_scan_hardcoded_secrets(self):
        agent = SecurityAgent()
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = agent.scan_code(code, "config.py")
        assert len(findings) > 0
        assert any(f.threat_type == ThreatType.HARDCODED_SECRETS for f in findings)

    def test_scan_sql_injection(self):
        agent = SecurityAgent()
        code = 'query = "SELECT * FROM users WHERE id=" + user_id'
        findings = agent.scan_code(code, "db.py")
        assert len(findings) > 0
        assert any(f.threat_type == ThreatType.SQL_INJECTION for f in findings)

    def test_scan_xss(self):
        agent = SecurityAgent()
        code = '<script>alert("xss")</script>'
        findings = agent.scan_code(code, "page.html")
        assert len(findings) > 0
        assert any(f.threat_type == ThreatType.XSS for f in findings)

    def test_scan_finding_has_required_fields(self):
        agent = SecurityAgent()
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = agent.scan_code(code, "config.py")
        f = findings[0]
        assert f.finding_id.startswith("finding-")
        assert isinstance(f.threat_type, ThreatType)
        assert isinstance(f.severity, SeverityLevel)
        assert f.location == "config.py"
        assert f.line_number is not None

    def test_scan_parameterized_query_skipped(self):
        agent = SecurityAgent()
        code = 'query = "SELECT * FROM users WHERE username = :username AND password = :password"'
        findings = agent.scan_code(code, "safe.py")
        sql_findings = [f for f in findings if f.threat_type == ThreatType.SQL_INJECTION]
        assert len(sql_findings) == 0


class TestSecurityAgentIncident:
    def test_create_incident(self):
        agent = SecurityAgent()
        incident = agent.create_incident(
            title="Breach attempt",
            description="SQL injection attempt detected",
            severity=SeverityLevel.HIGH,
            threat_type=ThreatType.SQL_INJECTION,
            source_ip="10.0.0.1",
            target_resource="user-db",
        )
        assert isinstance(incident, SecurityIncident)
        assert incident.title == "Breach attempt"
        assert incident.severity == SeverityLevel.HIGH
        assert incident.status == "investigating"  # HIGH triggers auto-respond
        assert len(incident.response_actions) > 0

    def test_create_incident_critical_auto_responds(self):
        agent = SecurityAgent()
        incident = agent.create_incident(
            title="Critical breach",
            description="Data exfiltration detected",
            severity=SeverityLevel.CRITICAL,
            threat_type=ThreatType.SENSITIVE_DATA_EXPOSURE,
        )
        assert incident.status == "investigating"
        assert len(incident.response_actions) > 0

    def test_create_incident_low_severity_no_auto(self):
        agent = SecurityAgent()
        incident = agent.create_incident(
            title="Info alert",
            description="Minor issue",
            severity=SeverityLevel.LOW,
            threat_type=ThreatType.SECURITY_MISCONFIGURATION,
        )
        assert incident.status == "detected"
        assert len(incident.response_actions) == 0

    def test_update_incident_status(self):
        agent = SecurityAgent()
        incident = agent.create_incident(
            title="Test",
            description="desc",
            severity=SeverityLevel.MEDIUM,
            threat_type=ThreatType.XSS,
        )
        result = agent.update_incident_status(incident.incident_id, "resolved", resolved_by="admin")
        assert result is not None
        assert result.status == "resolved"
        assert result.resolved_by == "admin"
        assert result.resolved_at is not None

    def test_update_incident_nonexistent(self):
        agent = SecurityAgent()
        result = agent.update_incident_status("nonexistent-id", "resolved")
        assert result is None

    def test_get_incidents_filter_by_status(self):
        agent = SecurityAgent()
        agent.create_incident("T1", "d", SeverityLevel.LOW, ThreatType.XSS)
        agent.create_incident("T2", "d", SeverityLevel.HIGH, ThreatType.SQL_INJECTION)
        detected = agent.get_incidents(status="detected")
        assert all(i.status == "detected" for i in detected)

    def test_get_incidents_filter_by_severity(self):
        agent = SecurityAgent()
        agent.create_incident("T1", "d", SeverityLevel.LOW, ThreatType.XSS)
        agent.create_incident("T2", "d", SeverityLevel.HIGH, ThreatType.SQL_INJECTION)
        high = agent.get_incidents(severity=SeverityLevel.HIGH)
        assert all(i.severity == SeverityLevel.HIGH for i in high)

    def test_get_incidents_limit(self):
        agent = SecurityAgent()
        for i in range(10):
            agent.create_incident(f"T{i}", "d", SeverityLevel.LOW, ThreatType.XSS)
        limited = agent.get_incidents(limit=3)
        assert len(limited) <= 3


class TestSecurityAgentSecrets:
    def test_register_secret(self):
        agent = SecurityAgent()
        rotation = agent.register_secret("db-password", "password", rotation_days=90)
        assert isinstance(rotation, SecretRotation)
        assert rotation.secret_name == "db-password"
        assert rotation.secret_type == "password"
        assert rotation.status == "active"
        assert rotation.next_rotation is not None

    def test_rotate_secret(self):
        agent = SecurityAgent()
        rotation = agent.register_secret("api-key", "api_key")
        result = agent.rotate_secret(rotation.rotation_id, "new-value")
        assert result is True
        assert rotation.rotation_count == 1

    def test_rotate_nonexistent_secret(self):
        agent = SecurityAgent()
        result = agent.rotate_secret("nonexistent", "val")
        assert result is False

    def test_secrets_due_for_rotation(self):
        agent = SecurityAgent()
        agent.register_secret("old-key", "api_key", rotation_days=0)
        due = agent.get_secrets_due_for_rotation(days_ahead=1)
        assert isinstance(due, list)

    def test_generate_secure_secret_api_key(self):
        agent = SecurityAgent()
        secret = agent.generate_secure_secret("api_key")
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_generate_secure_secret_password(self):
        agent = SecurityAgent()
        secret = agent.generate_secure_secret("password", length=20)
        assert isinstance(secret, str)
        assert len(secret) == 20

    def test_generate_secure_secret_token(self):
        agent = SecurityAgent()
        secret = agent.generate_secure_secret("token", length=16)
        assert isinstance(secret, str)
        assert len(secret) == 32  # hex doubles the length


class TestSecurityAgentPolicy:
    def test_get_policy(self):
        agent = SecurityAgent()
        policy = agent.get_policy("password-complexity")
        assert isinstance(policy, SecurityPolicy)
        assert policy.name == "Password Complexity Policy"
        assert policy.enabled is True

    def test_get_nonexistent_policy(self):
        agent = SecurityAgent()
        result = agent.get_policy("nonexistent")
        assert result is None

    def test_update_policy(self):
        agent = SecurityAgent()
        result = agent.update_policy("password-complexity", enabled=False)
        assert result is True
        assert agent.policies["password-complexity"].enabled is False

    def test_update_policy_with_enforcement_level(self):
        agent = SecurityAgent()
        result = agent.update_policy("password-complexity", enabled=True, enforcement_level="warn")
        assert result is True
        assert agent.policies["password-complexity"].enforcement_level == "warn"

    def test_update_nonexistent_policy(self):
        agent = SecurityAgent()
        result = agent.update_policy("nonexistent", enabled=True)
        assert result is False

    def test_validate_password_valid(self):
        agent = SecurityAgent()
        is_valid, violations = agent.validate_password("Str0ng!Pass123")
        assert is_valid is True
        assert len(violations) == 0

    def test_validate_password_weak(self):
        agent = SecurityAgent()
        is_valid, violations = agent.validate_password("weak")
        assert is_valid is False
        assert len(violations) > 0

    def test_validate_password_empty(self):
        agent = SecurityAgent()
        is_valid, violations = agent.validate_password("")
        assert is_valid is False


class TestSecurityAgentReporting:
    def test_get_state(self):
        agent = SecurityAgent()
        state = agent.get_state()
        assert state["agent_id"] == "security-agent"
        assert "findings_count" in state
        assert "incidents_count" in state
        assert "policies_count" in state

    def test_generate_security_report(self):
        agent = SecurityAgent()
        report = agent.generate_security_report()
        assert "findings" in report
        assert "incidents" in report
        assert "secrets" in report
        assert "anomalies_detected" in report
        assert "policies" in report