"""Unit tests for ComplianceAgent."""
import pytest
from datetime import datetime, timedelta
from agentic_ai.agents.compliance import (
    ComplianceAgent,
    ComplianceStatus,
    RiskLevel,
    AuditStatus,
    ControlType,
    Regulation,
    Control,
    Audit,
    Policy,
    Finding,
    Certificate,
)
from agentic_ai.infrastructure.utils import utcnow
from agentic_ai.agents.schemas import ComplianceAssessment


class TestComplianceAgentInit:
    def test_default_init(self):
        agent = ComplianceAgent()
        assert agent.agent_id == "compliance-agent"
        assert isinstance(agent.regulations, dict)
        assert isinstance(agent.controls, dict)
        assert isinstance(agent.audits, dict)
        assert isinstance(agent.policies, dict)
        assert isinstance(agent.findings, dict)
        assert isinstance(agent.certificates, dict)

    def test_custom_id(self):
        agent = ComplianceAgent(agent_id="comp-001")
        assert agent.agent_id == "comp-001"

    def test_framework_templates_initialized(self):
        agent = ComplianceAgent()
        assert "SOC2" in agent.framework_templates
        assert "ISO27001" in agent.framework_templates
        assert "GDPR" in agent.framework_templates
        assert "HIPAA" in agent.framework_templates


class TestComplianceAgentRegulation:
    def test_add_regulation(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation(
            name="SOC 2 Type II",
            framework="SOC2",
            jurisdiction="USA",
            owner="compliance-team",
        )
        assert isinstance(reg, Regulation)
        assert reg.name == "SOC 2 Type II"
        assert reg.framework == "SOC2"
        assert reg.status == ComplianceStatus.NOT_ASSESSED
        assert reg.regulation_id.startswith("reg-")

    def test_add_regulation_with_dates(self):
        agent = ComplianceAgent()
        next_date = utcnow() + timedelta(days=180)
        reg = agent.add_regulation("GDPR", "GDPR", "EU", next_assessment=next_date)
        assert reg.next_assessment == next_date

    def test_update_regulation_status_compliant(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        # 80/85 = 94.1% which is < 95% threshold → partially_compliant
        result = agent.update_regulation_status(reg.regulation_id, 80, 85)
        assert result is True
        assert reg.status == ComplianceStatus.PARTIALLY_COMPLIANT

    def test_update_regulation_status_fully_compliant(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        result = agent.update_regulation_status(reg.regulation_id, 95, 100)
        assert reg.status == ComplianceStatus.COMPLIANT  # 95%

    def test_update_regulation_status_partially_compliant(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        result = agent.update_regulation_status(reg.regulation_id, 75, 100)
        assert reg.status == ComplianceStatus.PARTIALLY_COMPLIANT

    def test_update_regulation_status_non_compliant(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        result = agent.update_regulation_status(reg.regulation_id, 50, 100)
        assert reg.status == ComplianceStatus.NON_COMPLIANT

    def test_update_regulation_status_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.update_regulation_status("nonexistent", 10, 20)
        assert result is False

    def test_get_regulations_all(self):
        agent = ComplianceAgent()
        agent.add_regulation("R1", "SOC2", "USA")
        agent.add_regulation("R2", "GDPR", "EU")
        regs = agent.get_regulations()
        assert len(regs) == 2

    def test_get_regulations_filter_framework(self):
        agent = ComplianceAgent()
        agent.add_regulation("R1", "SOC2", "USA")
        agent.add_regulation("R2", "GDPR", "EU")
        soc2 = agent.get_regulations(framework="SOC2")
        assert len(soc2) == 1


class TestComplianceAgentControl:
    def test_create_control(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        ctrl = agent.create_control(
            name="Access Control",
            description="Proper access controls",
            control_type=ControlType.ADMINISTRATIVE,
            regulation_id=reg.regulation_id,
            risk_level=RiskLevel.HIGH,
        )
        assert isinstance(ctrl, Control)
        assert ctrl.name == "Access Control"
        assert ctrl.status == ComplianceStatus.NOT_ASSESSED

    def test_create_control_updates_regulation_count(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        agent.create_control("C1", "d", ControlType.ADMINISTRATIVE, reg.regulation_id)
        assert reg.controls_count == 1

    def test_test_control_pass(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        ctrl = agent.create_control("C", "d", ControlType.TECHNICAL, reg.regulation_id)
        result = agent.test_control(ctrl.control_id, passed=True, evidence_locations=["/doc.pdf"])
        assert result is True
        assert ctrl.status == ComplianceStatus.COMPLIANT
        assert ctrl.last_tested is not None

    def test_test_control_fail(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        ctrl = agent.create_control("C", "d", ControlType.TECHNICAL, reg.regulation_id)
        agent.test_control(ctrl.control_id, passed=False)
        assert ctrl.status == ComplianceStatus.NON_COMPLIANT

    def test_test_control_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.test_control("nonexistent", True)
        assert result is False

    def test_get_controls_filter_status(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        c1 = agent.create_control("C1", "d", ControlType.ADMINISTRATIVE, reg.regulation_id)
        c2 = agent.create_control("C2", "d", ControlType.TECHNICAL, reg.regulation_id)
        agent.test_control(c1.control_id, True)
        compliant = agent.get_controls(status=ComplianceStatus.COMPLIANT)
        assert len(compliant) == 1

    def test_get_controls_filter_type(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        agent.create_control("C1", "d", ControlType.ADMINISTRATIVE, reg.regulation_id)
        agent.create_control("C2", "d", ControlType.TECHNICAL, reg.regulation_id)
        tech = agent.get_controls(control_type=ControlType.TECHNICAL)
        assert len(tech) == 1


class TestComplianceAgentAudit:
    def test_create_audit(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        audit = agent.create_audit(
            name="SOC 2 Annual",
            audit_type="external",
            regulation_id=reg.regulation_id,
            start_date=utcnow(),
            auditor="Big4 LLP",
        )
        assert isinstance(audit, Audit)
        assert audit.status == AuditStatus.PLANNED
        assert audit.auditor == "Big4 LLP"

    def test_start_audit(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        audit = agent.create_audit("Test", "internal", reg.regulation_id, utcnow())
        result = agent.start_audit(audit.audit_id)
        assert result is True
        assert audit.status == AuditStatus.IN_PROGRESS

    def test_start_audit_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.start_audit("nonexistent")
        assert result is False

    def test_complete_audit(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        audit = agent.create_audit("Test", "internal", reg.regulation_id, utcnow())
        result = agent.complete_audit(
            audit.audit_id,
            score=85.0,
            findings=[{"severity": "high", "title": "Missing MFA"}],
            recommendations=["Enable MFA"],
        )
        assert result is True
        assert audit.status == AuditStatus.COMPLETED
        assert audit.score == 85.0
        assert audit.end_date is not None

    def test_complete_audit_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.complete_audit("nonexistent", 50.0)
        assert result is False

    def test_get_audits_filter(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC2", "SOC2", "USA")
        a1 = agent.create_audit("A1", "internal", reg.regulation_id, utcnow())
        agent.start_audit(a1.audit_id)
        planned = agent.get_audits(status=AuditStatus.PLANNED)
        assert len(planned) == 0


class TestComplianceAgentPolicy:
    def test_create_policy(self):
        agent = ComplianceAgent()
        policy = agent.create_policy(
            title="InfoSec Policy",
            category="security",
            version="1.0",
            owner="ciso",
        )
        assert isinstance(policy, Policy)
        assert policy.title == "InfoSec Policy"
        assert policy.status == "draft"

    def test_approve_policy_single_approver(self):
        agent = ComplianceAgent()
        policy = agent.create_policy("P", "sec", "1.0")
        result = agent.approve_policy(policy.policy_id, "approver1")
        assert result is True
        assert len(policy.approvers) == 1
        # Still draft - needs 2 approvers
        assert policy.status == "draft"

    def test_approve_policy_two_approvers(self):
        agent = ComplianceAgent()
        policy = agent.create_policy("P", "sec", "1.0")
        agent.approve_policy(policy.policy_id, "approver1")
        agent.approve_policy(policy.policy_id, "approver2")
        assert policy.status == "approved"
        assert policy.effective_date is not None

    def test_approve_policy_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.approve_policy("nonexistent", "approver")
        assert result is False

    def test_get_policies_filter_category(self):
        agent = ComplianceAgent()
        agent.create_policy("P1", "security", "1.0")
        agent.create_policy("P2", "privacy", "1.0")
        sec = agent.get_policies(category="security")
        assert len(sec) == 1

    def test_get_policies_due_for_review(self):
        agent = ComplianceAgent()
        policy = agent.create_policy("P1", "security", "1.0", review_date=utcnow() + timedelta(days=10))
        # Approve it so it can be due for review
        agent.approve_policy(policy.policy_id, "a1")
        agent.approve_policy(policy.policy_id, "a2")
        due = agent.get_policies_due_for_review(days_ahead=30)
        assert len(due) == 1


class TestComplianceAgentFinding:
    def test_create_finding(self):
        agent = ComplianceAgent()
        finding = agent.create_finding(
            title="Missing MFA",
            description="Admin accounts lack MFA",
            severity=RiskLevel.HIGH,
            assigned_to="security-team",
        )
        assert isinstance(finding, Finding)
        assert finding.title == "Missing MFA"
        assert finding.status == "open"
        assert finding.severity == RiskLevel.HIGH

    def test_resolve_finding(self):
        agent = ComplianceAgent()
        finding = agent.create_finding("T", "D", RiskLevel.HIGH)
        result = agent.resolve_finding(finding.finding_id, "Enable MFA for all admins")
        assert result is True
        assert finding.status == "resolved"
        assert finding.remediation_plan == "Enable MFA for all admins"
        assert finding.resolved_date is not None

    def test_resolve_finding_nonexistent(self):
        agent = ComplianceAgent()
        result = agent.resolve_finding("nonexistent", "plan")
        assert result is False

    def test_get_findings_filter_severity(self):
        agent = ComplianceAgent()
        agent.create_finding("T1", "D", RiskLevel.HIGH)
        agent.create_finding("T2", "D", RiskLevel.CRITICAL)
        high = agent.get_findings(severity=RiskLevel.HIGH)
        assert len(high) == 1

    def test_get_findings_filter_status(self):
        agent = ComplianceAgent()
        f1 = agent.create_finding("T1", "D", RiskLevel.HIGH)
        agent.resolve_finding(f1.finding_id, "plan")
        agent.create_finding("T2", "D", RiskLevel.MEDIUM)
        open_f = agent.get_findings(status="open")
        assert len(open_f) == 1


class TestComplianceAgentCertificate:
    def test_add_certificate(self):
        agent = ComplianceAgent()
        cert = agent.add_certificate(
            certificate_type="SOC2",
            issuer="Big4 Auditor",
            issued_date=utcnow(),
            expiry_date=utcnow() + timedelta(days=365),
        )
        assert isinstance(cert, Certificate)
        assert cert.certificate_type == "SOC2"
        assert cert.status == "valid"

    def test_add_certificate_with_status(self):
        agent = ComplianceAgent()
        cert = agent.add_certificate(
            certificate_type="ISO",
            issuer="Cert Body",
            issued_date=utcnow(),
            status="pending",
        )
        assert cert.status == "pending"


class TestComplianceAgentAssessment:
    def test_create_assessment(self):
        agent = ComplianceAgent()
        assessment = agent.create_assessment(
            name="Q1 Assessment",
            assessment_type="internal",
            scope="All controls",
            assessor="compliance-team",
        )
        assert isinstance(assessment, ComplianceAssessment)
        assert assessment.name == "Q1 Assessment"
        assert assessment.status == "planned"


class TestComplianceAgentReporting:
    def test_get_compliance_report(self):
        agent = ComplianceAgent()
        report = agent.get_compliance_report()
        assert "summary" in report
        assert "regulations" in report
        assert "findings" in report
        assert "audits" in report
        assert "risk_score" in report

    def test_get_framework_status(self):
        agent = ComplianceAgent()
        reg = agent.add_regulation("SOC 2", "SOC2", "USA")
        ctrl = agent.create_control("C", "d", ControlType.TECHNICAL, reg.regulation_id)
        agent.test_control(ctrl.control_id, True)
        status = agent.get_framework_status("SOC2")
        assert "framework" in status
        assert "compliance_rate" in status

    def test_get_framework_status_nonexistent(self):
        agent = ComplianceAgent()
        status = agent.get_framework_status("NONEXISTENT")
        assert "error" in status

    def test_get_state(self):
        agent = ComplianceAgent()
        state = agent.get_state()
        assert state["agent_id"] == "compliance-agent"
        assert "regulations_count" in state
        assert "controls_count" in state
        assert "open_findings" in state

    def test_risk_score_calculation(self):
        agent = ComplianceAgent()
        # 0 critical, 0 high, 100% compliance -> risk = 0
        score = agent._calculate_risk_score(0, 0, 100.0)
        assert score == 0.0

    def test_risk_score_with_findings(self):
        agent = ComplianceAgent()
        score = agent._calculate_risk_score(2, 3, 80.0)
        # base = 100-80=20, crit=2*15=30, high=3*8=24, total=74
        assert score == 74.0