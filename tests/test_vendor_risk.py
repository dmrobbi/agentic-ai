"""
VendorRiskAgent Tests
=====================

Unit tests for VendorRiskAgent - Third-party risk management.
"""

import pytest
from datetime import datetime, timedelta

from agentic_ai.agents.vendor_risk import (
    VendorRiskAgent,
    VendorTier,
    RiskDomain,
    AssessmentType,
    QuestionnaireType,
    ResidualRisk,
)


class TestVendorRiskAgent:
    """Test VendorRiskAgent."""
    
    @pytest.fixture
    def vr_agent(self):
        """Create VendorRiskAgent instance."""
        return VendorRiskAgent()
    
    def test_add_vendor(self, vr_agent):
        """Test adding vendor."""
        vendor = vr_agent.add_vendor(
            name="CloudProvider",
            legal_name="CloudProvider Inc",
            tier=VendorTier.TIER_1,
            category="cloud",
            relationship_type="vendor",
            contract_start=datetime.utcnow(),
            contract_end=datetime.utcnow() + timedelta(days=365),
            contract_value=500000.0,
            primary_contact="contact@example.com",
            security_contact="security@example.com",
            risk_owner="cto@example.com",
        )
        
        assert vendor.vendor_id.startswith("vendor-")
        assert vendor.tier == VendorTier.TIER_1
        assert vendor.inherent_risk == 0.9  # Tier 1 inherent risk
    
    def test_vendor_inherent_risk_by_tier(self, vr_agent):
        """Test inherent risk calculation by tier."""
        v1 = vr_agent.add_vendor("V1", "Legal1", VendorTier.TIER_1, "cat", "vendor", datetime.utcnow())
        v2 = vr_agent.add_vendor("V2", "Legal2", VendorTier.TIER_2, "cat", "vendor", datetime.utcnow())
        v3 = vr_agent.add_vendor("V3", "Legal3", VendorTier.TIER_3, "cat", "vendor", datetime.utcnow())
        v4 = vr_agent.add_vendor("V4", "Legal4", VendorTier.TIER_4, "cat", "vendor", datetime.utcnow())
        
        assert v1.inherent_risk == 0.9
        assert v2.inherent_risk == 0.7
        assert v3.inherent_risk == 0.5
        assert v4.inherent_risk == 0.3
    
    def test_get_vendors_by_tier(self, vr_agent):
        """Test filtering vendors by tier."""
        vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        vr_agent.add_vendor("V2", "L2", VendorTier.TIER_2, "software", "vendor", datetime.utcnow())
        vr_agent.add_vendor("V3", "L3", VendorTier.TIER_1, "hardware", "vendor", datetime.utcnow())
        
        tier1 = vr_agent.get_vendors(tier=VendorTier.TIER_1)
        tier2 = vr_agent.get_vendors(tier=VendorTier.TIER_2)
        
        assert len(tier1) == 2
        assert len(tier2) == 1
    
    def test_update_vendor_risk(self, vr_agent):
        """Test updating vendor residual risk."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_2, "cat", "vendor", datetime.utcnow())
        
        result = vr_agent.update_vendor_risk(vendor.vendor_id, 0.4)
        
        assert result is True
        assert vendor.residual_risk == 0.4
    
    def test_create_questionnaire(self, vr_agent):
        """Test creating questionnaire."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        questionnaire = vr_agent.create_questionnaire(
            vendor.vendor_id,
            QuestionnaireType.SIG_CORE,
            version="1.0",
        )
        
        assert questionnaire.questionnaire_id.startswith("quest-")
        assert questionnaire.questionnaire_type == QuestionnaireType.SIG_CORE
        assert questionnaire.status == "draft"
        assert questionnaire.total_questions > 0
    
    def test_send_questionnaire(self, vr_agent):
        """Test sending questionnaire."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        questionnaire = vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_LITE)
        
        result = vr_agent.send_questionnaire(questionnaire.questionnaire_id)
        
        assert result is True
        assert questionnaire.status == "sent"
        assert questionnaire.sent_at is not None
    
    def test_respond_to_question(self, vr_agent):
        """Test responding to questionnaire question."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        questionnaire = vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_LITE)
        
        # Get a question
        questions = [q for q in vr_agent.questions.values() if q.questionnaire_id == questionnaire.questionnaire_id]
        question = questions[0]
        
        result = vr_agent.respond_to_question(
            question.question_id,
            response="Yes",
            evidence_provided=True,
            notes="Implemented",
        )
        
        assert result is True
        assert question.response == "Yes"
        assert question.score == 1.0
        assert question.evidence_provided is True
    
    def test_respond_to_question_scoring(self, vr_agent):
        """Test question response scoring."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        questionnaire = vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_LITE)
        
        questions = [q for q in vr_agent.questions.values() if q.questionnaire_id == questionnaire.questionnaire_id]
        
        # Yes = 1.0
        vr_agent.respond_to_question(questions[0].question_id, "Yes")
        assert questions[0].score == 1.0
        
        # Partial = 0.5
        vr_agent.respond_to_question(questions[1].question_id, "Partial")
        assert questions[1].score == 0.5
        
        # No = 0.0
        vr_agent.respond_to_question(questions[2].question_id, "No")
        assert questions[2].score == 0.0
    
    def test_get_questionnaires_by_status(self, vr_agent):
        """Test filtering questionnaires by status."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        q1 = vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_LITE)
        vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_CORE)
        
        vr_agent.send_questionnaire(q1.questionnaire_id)
        
        draft = vr_agent.get_questionnaires(status="draft")
        sent = vr_agent.get_questionnaires(status="sent")
        
        assert len(draft) == 1
        assert len(sent) == 1
    
    def test_create_assessment(self, vr_agent):
        """Test creating vendor assessment."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        questionnaire = vr_agent.create_questionnaire(vendor.vendor_id, QuestionnaireType.SIG_CORE)
        
        assessment = vr_agent.create_assessment(
            vendor.vendor_id,
            AssessmentType.ANNUAL,
            assessor="risk-team@example.com",
            questionnaire_id=questionnaire.questionnaire_id,
        )
        
        assert assessment.assessment_id.startswith("assess-")
        assert assessment.assessment_type == AssessmentType.ANNUAL
        assert assessment.status == "planned"
    
    def test_start_assessment(self, vr_agent):
        """Test starting assessment."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "assessor")
        
        result = vr_agent.start_assessment(assessment.assessment_id)
        
        assert result is True
        assert assessment.status == "in_progress"
    
    def test_complete_assessment(self, vr_agent):
        """Test completing assessment."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "assessor")
        vr_agent.start_assessment(assessment.assessment_id)
        
        result = vr_agent.complete_assessment(
            assessment.assessment_id,
            inherent_risk_score=0.8,
            control_effectiveness=0.6,
            residual_risk_score=0.5,
            findings=[
                {
                    'domain': RiskDomain.INFORMATION_SECURITY,
                    'title': 'Finding 1',
                    'description': 'Desc',
                    'severity': 'high',
                    'inherent_risk': 0.7,
                    'control_effectiveness': 0.5,
                    'residual_risk': 0.4,
                },
            ],
            recommendations=["Recommendation 1"],
            overall_opinion="Acceptable with remediation",
        )
        
        assert result is True
        assert assessment.status == "completed"
        assert assessment.completed_at is not None
        assert assessment.residual_risk_score == 0.5
        assert assessment.residual_risk_level == ResidualRisk.MEDIUM
        assert assessment.findings_count == 1
        assert vendor.residual_risk == 0.5
        assert vendor.last_assessment is not None
    
    def test_assessment_risk_levels(self, vr_agent):
        """Test residual risk level determination."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        # Extreme (>= 0.8)
        a1 = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.complete_assessment(a1.assessment_id, 0.9, 0.1, 0.85)
        assert a1.residual_risk_level == ResidualRisk.EXTREME
        
        # High (>= 0.6)
        a2 = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.complete_assessment(a2.assessment_id, 0.8, 0.2, 0.65)
        assert a2.residual_risk_level == ResidualRisk.HIGH
        
        # Medium (>= 0.4)
        a3 = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.complete_assessment(a3.assessment_id, 0.7, 0.4, 0.45)
        assert a3.residual_risk_level == ResidualRisk.MEDIUM
        
        # Low (>= 0.2)
        a4 = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.complete_assessment(a4.assessment_id, 0.5, 0.5, 0.25)
        assert a4.residual_risk_level == ResidualRisk.LOW
    
    def test_get_assessments_by_type(self, vr_agent):
        """Test filtering assessments by type."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        vr_agent.create_assessment(vendor.vendor_id, AssessmentType.INITIAL, "a")
        vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.create_assessment(vendor.vendor_id, AssessmentType.EVENT_DRIVEN, "a")
        
        annual = vr_agent.get_assessments(assessment_type=AssessmentType.ANNUAL)
        initial = vr_agent.get_assessments(assessment_type=AssessmentType.INITIAL)
        
        assert len(annual) == 1
        assert len(initial) == 1
    
    def test_create_finding(self, vr_agent):
        """Test creating assessment finding."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        
        finding = vr_agent.create_finding(
            assessment.assessment_id,
            RiskDomain.INFORMATION_SECURITY,
            title="MFA Not Enforced",
            description="MFA not enforced for all users",
            severity="high",
            inherent_risk=0.7,
            control_effectiveness=0.4,
            residual_risk=0.5,
        )
        
        assert finding.finding_id.startswith("finding-")
        assert finding.severity == "high"
        assert finding.status == "open"
        assert assessment.findings_count == 1
    
    def test_update_finding(self, vr_agent):
        """Test updating finding details."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        finding = vr_agent.create_finding(
            assessment.assessment_id, RiskDomain.INFO_SECURITY if hasattr(RiskDomain, 'INFO_SECURITY') else RiskDomain.INFORMATION_SECURITY,
            "Title", "Desc", "high", 0.7, 0.4, 0.5,
        )
        
        due_date = datetime.utcnow() + timedelta(days=90)
        
        result = vr_agent.update_finding(
            finding.finding_id,
            recommendation="Implement MFA",
            management_response="Will implement in Q2",
            remediation_plan="Deploy MFA solution",
            due_date=due_date,
        )
        
        assert result is True
        assert finding.recommendation == "Implement MFA"
        assert finding.due_date == due_date
    
    def test_update_finding_status(self, vr_agent):
        """Test updating finding status."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        finding = vr_agent.create_finding(
            assessment.assessment_id, RiskDomain.INFORMATION_SECURITY,
            "Title", "Desc", "high", 0.7, 0.4, 0.5,
        )
        
        # Move to in progress
        vr_agent.update_finding_status(finding.finding_id, "in_progress")
        assert finding.status == "in_progress"
        
        # Close finding
        vr_agent.update_finding_status(finding.finding_id, "closed")
        assert finding.status == "closed"
        assert finding.closed_at is not None
    
    def test_get_findings_by_severity(self, vr_agent):
        """Test filtering findings by severity."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        
        vr_agent.create_finding(assessment.assessment_id, RiskDomain.INFORMATION_SECURITY, "T", "D", "critical", 0.9, 0.3, 0.8)
        vr_agent.create_finding(assessment.assessment_id, RiskDomain.INFORMATION_SECURITY, "T", "D", "high", 0.7, 0.4, 0.5)
        vr_agent.create_finding(assessment.assessment_id, RiskDomain.INFORMATION_SECURITY, "T", "D", "medium", 0.5, 0.5, 0.3)
        
        high = vr_agent.get_findings(severity="high")
        critical = vr_agent.get_findings(severity="critical")
        
        assert len(high) == 1
        assert len(critical) == 1
    
    def test_enable_monitoring(self, vr_agent):
        """Test enabling continuous monitoring."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        monitor = vr_agent.enable_monitoring(
            vendor.vendor_id,
            monitoring_types=['security_ratings', 'breaches', 'news'],
            check_frequency="daily",
        )
        
        assert monitor.monitor_id.startswith("monitor-")
        assert monitor.enabled is True
        assert len(monitor.monitoring_types) == 3
    
    def test_record_monitoring_result(self, vr_agent):
        """Test recording monitoring result."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        monitor = vr_agent.enable_monitoring(vendor.vendor_id, ['security_ratings'])
        
        result = vr_agent.record_monitoring_result(
            monitor.monitor_id,
            risk_trend="stable",
            alerts=["Alert 1"],
        )
        
        assert result is True
        assert monitor.last_check is not None
        assert monitor.risk_trend == "stable"
        assert len(monitor.alerts) == 1
    
    def test_create_alert(self, vr_agent):
        """Test creating vendor alert."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        alert = vr_agent.create_alert(
            vendor.vendor_id,
            alert_type="security_rating_change",
            severity="medium",
            title="Security Rating Downgrade",
            description="Rating dropped from A to B",
            source="security_ratings",
        )
        
        assert alert.alert_id.startswith("alert-")
        assert alert.status == "new"
        assert alert.severity == "medium"
    
    def test_acknowledge_alert(self, vr_agent):
        """Test acknowledging alert."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        alert = vr_agent.create_alert(vendor.vendor_id, "type", "high", "Title", "Desc", "source")
        
        result = vr_agent.acknowledge_alert(alert.alert_id)
        
        assert result is True
        assert alert.status == "acknowledged"
        assert alert.acknowledged_at is not None
    
    def test_resolve_alert(self, vr_agent):
        """Test resolving alert."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        alert = vr_agent.create_alert(vendor.vendor_id, "type", "high", "Title", "Desc", "source")
        
        result = vr_agent.resolve_alert(alert.alert_id)
        
        assert result is True
        assert alert.status == "resolved"
        assert alert.resolved_at is not None
    
    def test_get_alerts_by_status(self, vr_agent):
        """Test filtering alerts by status."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        a1 = vr_agent.create_alert(vendor.vendor_id, "type", "high", "T1", "D", "s")
        a2 = vr_agent.create_alert(vendor.vendor_id, "type", "medium", "T2", "D", "s")
        vr_agent.create_alert(vendor.vendor_id, "type", "low", "T3", "D", "s")
        
        vr_agent.acknowledge_alert(a1.alert_id)
        vr_agent.resolve_alert(a2.alert_id)
        
        new = vr_agent.get_alerts(status="new")
        acknowledged = vr_agent.get_alerts(status="acknowledged")
        resolved = vr_agent.get_alerts(status="resolved")
        
        assert len(new) == 1
        assert len(acknowledged) == 1
        assert len(resolved) == 1
    
    def test_get_vendor_risk_report(self, vr_agent):
        """Test vendor risk report generation."""
        vendor = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        
        assessment = vr_agent.create_assessment(vendor.vendor_id, AssessmentType.ANNUAL, "a")
        vr_agent.complete_assessment(assessment.assessment_id, 0.8, 0.6, 0.5)
        
        vr_agent.create_finding(assessment.assessment_id, RiskDomain.INFORMATION_SECURITY, "Finding", "Desc", "high", 0.7, 0.4, 0.5)
        
        report = vr_agent.get_vendor_risk_report(vendor.vendor_id)
        
        assert 'vendor' in report
        assert 'risk' in report
        assert 'assessments' in report
        assert 'findings' in report
        assert 'alerts' in report
    
    def test_get_vendor_risk_dashboard(self, vr_agent):
        """Test vendor risk dashboard."""
        vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        vr_agent.add_vendor("V2", "L2", VendorTier.TIER_2, "software", "vendor", datetime.utcnow())
        vr_agent.add_vendor("V3", "L3", VendorTier.TIER_1, "hardware", "vendor", datetime.utcnow())
        
        dashboard = vr_agent.get_vendor_risk_dashboard()
        
        assert 'vendors' in dashboard
        assert 'assessments' in dashboard
        assert 'findings' in dashboard
        assert 'alerts' in dashboard
        assert dashboard['vendors']['total'] == 3
        assert dashboard['vendors']['by_tier']['tier_1'] == 2
    
    def test_get_vendors_due_for_assessment(self, vr_agent):
        """Test getting vendors due for assessment."""
        v1 = vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        v2 = vr_agent.add_vendor("V2", "L2", VendorTier.TIER_2, "software", "vendor", datetime.utcnow())
        
        # Set v1's next assessment to 15 days from now
        v1.next_assessment = datetime.utcnow() + timedelta(days=15)
        
        # Set v2's next assessment to 60 days from now
        v2.next_assessment = datetime.utcnow() + timedelta(days=60)
        
        due_soon = vr_agent.get_vendors_due_for_assessment(days=30)
        
        assert len(due_soon) == 1
        assert due_soon[0].vendor_id == v1.vendor_id
    
    def test_get_state(self, vr_agent):
        """Test agent state summary."""
        vr_agent.add_vendor("V1", "L1", VendorTier.TIER_1, "cloud", "vendor", datetime.utcnow())
        vr_agent.add_vendor("V2", "L2", VendorTier.TIER_2, "software", "vendor", datetime.utcnow())
        
        state = vr_agent.get_state()
        
        assert state['vendors_count'] == 2
        assert state['by_tier']['tier_1'] == 1
        assert state['by_tier']['tier_2'] == 1
        assert 'agent_id' in state


class TestVendorRiskCapabilities:
    """Test VendorRiskAgent capabilities export."""
    
    def test_capabilities(self):
        """Test capabilities export."""
        from agentic_ai.agents.vendor_risk import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'vendor_risk'
        assert len(caps['capabilities']) >= 25
        assert 'add_vendor' in caps['capabilities']
        assert 'create_questionnaire' in caps['capabilities']
        assert 'complete_assessment' in caps['capabilities']
        assert 'enable_monitoring' in caps['capabilities']
    
    def test_vendor_tiers(self):
        """Test vendor tiers in capabilities."""
        from agentic_ai.agents.vendor_risk import get_capabilities
        caps = get_capabilities()
        
        assert 'tier_1' in caps['vendor_tiers']
        assert 'tier_2' in caps['vendor_tiers']
        assert 'tier_3' in caps['vendor_tiers']
        assert 'tier_4' in caps['vendor_tiers']
    
    def test_risk_domains(self):
        """Test risk domains in capabilities."""
        from agentic_ai.agents.vendor_risk import get_capabilities
        caps = get_capabilities()
        
        assert 'information_security' in caps['risk_domains']
        assert 'privacy' in caps['risk_domains']
        assert 'business_continuity' in caps['risk_domains']
        assert 'compliance' in caps['risk_domains']
    
    def test_questionnaire_types(self):
        """Test questionnaire types in capabilities."""
        from agentic_ai.agents.vendor_risk import get_capabilities
        caps = get_capabilities()
        
        assert 'sig_lite' in caps['questionnaire_types']
        assert 'sig_core' in caps['questionnaire_types']
        assert 'sig_full' in caps['questionnaire_types']
        assert 'caiq' in caps['questionnaire_types']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
