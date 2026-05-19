"""
Governance, Risk & Ethics Tests
================================

Unit tests for DataGovernanceAgent, EthicsAgent, and RiskAgent.
"""

import pytest
from datetime import datetime, timedelta

from agentic_ai.agents.data_governance import (
    DataGovernanceAgent,
    DataClassification,
    DataType,
    DataQualityDimension,
    RetentionAction,
)
from agentic_ai.agents.ethics import (
    EthicsAgent,
    EthicsPrinciple,
    BiasType,
    FairnessMetric,
    RiskLevel,
    AssessmentStatus,
)
from agentic_ai.agents.risk import (
    RiskAgent,
    RiskCategory,
    RiskStatus,
    TreatmentStrategy,
)


class TestDataGovernanceAgent:
    """Test DataGovernanceAgent."""
    
    @pytest.fixture
    def governance(self):
        """Create DataGovernanceAgent instance."""
        return DataGovernanceAgent()
    
    def test_register_asset(self, governance):
        """Test registering data asset."""
        asset = governance.register_asset(
            name="Customer Database",
            description="Main customer PII database",
            data_type=DataType.PII,
            classification=DataClassification.RESTRICTED,
            owner="data-team@example.com",
            location="postgres://db-prod/customers",
            system="CRM",
            steward="privacy@example.com",
        )
        
        assert asset.asset_id.startswith("asset-")
        assert asset.data_type == DataType.PII
        assert asset.classification == DataClassification.RESTRICTED
    
    def test_classify_data(self, governance):
        """Test auto-classification of data."""
        # Test restricted content
        classification = governance.classify_data("SSN: 123-45-6789")
        assert classification == DataClassification.RESTRICTED
        
        # Test confidential content
        classification = governance.classify_data("Confidential internal memo")
        assert classification == DataClassification.CONFIDENTIAL
        
        # Test public content
        classification = governance.classify_data("Public press release")
        assert classification == DataClassification.PUBLIC
    
    def test_create_retention_policy(self, governance):
        """Test creating retention policy."""
        policy = governance.create_retention_policy(
            name="PII Retention",
            data_types=[DataType.PII],
            retention_period=730,
            action=RetentionAction.DELETE,
            regulatory_requirement="GDPR Art. 5(1)(e)",
        )
        
        assert policy.policy_id.startswith("policy-")
        assert policy.retention_period == 730
        assert policy.action == RetentionAction.DELETE
    
    def test_get_retention_period(self, governance):
        """Test getting retention period for asset."""
        asset = governance.register_asset(
            "Test DB",
            "Description",
            DataType.PII,
            DataClassification.RESTRICTED,
            "owner@example.com",
            "location",
            "system",
        )
        
        retention = governance.get_retention_period(asset.asset_id)
        
        assert 'retention_period' in retention
        assert retention['retention_period'] == 730  # Default for PII
    
    def test_add_lineage(self, governance):
        """Test adding data lineage."""
        source = governance.register_asset(
            "Source DB", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        target = governance.register_asset(
            "Target DB", "Desc", DataType.ANALYTICS,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        lineage = governance.add_lineage(
            source_asset=source.asset_id,
            target_asset=target.asset_id,
            transformation="ETL - anonymized",
            process_name="daily_etl",
            frequency="daily",
        )
        
        assert lineage.lineage_id.startswith("lineage-")
        assert lineage.source_asset == source.asset_id
    
    def test_create_quality_rule(self, governance):
        """Test creating quality rule."""
        asset = governance.register_asset(
            "Test DB", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        rule = governance.create_quality_rule(
            name="Email Completeness",
            asset_id=asset.asset_id,
            dimension=DataQualityDimension.COMPLETENESS,
            rule_expression="email IS NOT NULL",
            threshold=95.0,
            severity="high",
        )
        
        assert rule.rule_id.startswith("rule-")
        assert rule.dimension == DataQualityDimension.COMPLETENESS
        assert rule.threshold == 95.0
    
    def test_execute_quality_check(self, governance):
        """Test executing quality check."""
        asset = governance.register_asset(
            "Test DB", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        rule = governance.create_quality_rule(
            "Test Rule",
            asset.asset_id,
            DataQualityDimension.ACCURACY,
            "expression",
            threshold=90.0,
        )
        
        # Pass
        result = governance.execute_quality_check(rule.rule_id, result=95.0)
        assert result is True
        assert rule.last_result == 95.0
        
        # Fail - should create issue
        governance.execute_quality_check(rule.rule_id, result=80.0)
        
        issues = governance.get_quality_issues(asset_id=asset.asset_id)
        assert len(issues) >= 1
    
    def test_resolve_quality_issue(self, governance):
        """Test resolving quality issue."""
        asset = governance.register_asset(
            "Test", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        rule = governance.create_quality_rule(
            "Test", asset.asset_id, DataQualityDimension.ACCURACY,
            "expr", threshold=90.0,
        )
        
        governance.execute_quality_check(rule.rule_id, result=50.0)
        
        issues = governance.get_quality_issues(status="open")
        assert len(issues) >= 1
        
        result = governance.resolve_quality_issue(
            issues[0].issue_id,
            remediation="Fixed data source",
        )
        
        assert result is True
        assert issues[0].status == "resolved"
    
    def test_request_access(self, governance):
        """Test requesting data access."""
        asset = governance.register_asset(
            "Restricted DB", "Desc", DataType.PII,
            DataClassification.RESTRICTED, "owner", "loc", "sys",
        )
        
        request = governance.request_access(
            asset_id=asset.asset_id,
            requester="analyst@example.com",
            purpose="Q2 analysis",
            access_level="read",
            justification="Business need",
        )
        
        assert request.request_id.startswith("access-")
        assert request.status == "pending"
    
    def test_approve_access(self, governance):
        """Test approving access."""
        asset = governance.register_asset(
            "Test", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        request = governance.request_access(
            asset.asset_id, "user@example.com",
            "purpose", "read",
        )
        
        result = governance.approve_access(
            request.request_id,
            "approver@example.com",
            expires_in_days=30,
        )
        
        assert result is True
        assert request.status == "approved"
        assert request.expires_at is not None
    
    def test_get_quality_score(self, governance):
        """Test quality score calculation."""
        asset = governance.register_asset(
            "Test", "Desc", DataType.OPERATIONAL,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        governance.create_quality_rule(
            "Rule 1", asset.asset_id, DataQualityDimension.ACCURACY,
            "expr", threshold=90.0,
        )
        governance.create_quality_rule(
            "Rule 2", asset.asset_id, DataQualityDimension.COMPLETENESS,
            "expr", threshold=95.0,
        )
        
        # Execute checks
        rules = governance.quality_rules.values()
        for rule in rules:
            governance.execute_quality_check(rule.rule_id, result=92.0)
        
        score = governance.get_quality_score(asset.asset_id)
        
        assert score['score'] == 92.0
        assert 'dimension_scores' in score
    
    def test_get_governance_report(self, governance):
        """Test governance report generation."""
        governance.register_asset(
            "Asset 1", "Desc", DataType.PII,
            DataClassification.RESTRICTED, "owner", "loc", "sys",
        )
        governance.register_asset(
            "Asset 2", "Desc", DataType.FINANCIAL,
            DataClassification.CONFIDENTIAL, "owner", "loc", "sys",
        )
        
        report = governance.get_governance_report()
        
        assert 'assets' in report
        assert 'quality' in report
        assert 'access' in report
        assert report['assets']['total'] == 2
    
    def test_get_compliance_summary(self, governance):
        """Test compliance summary for regulated data."""
        governance.register_asset(
            "PII DB", "Desc", DataType.PII,
            DataClassification.RESTRICTED, "owner", "loc", "sys",
        )
        governance.register_asset(
            "PHI DB", "Desc", DataType.PHI,
            DataClassification.RESTRICTED, "owner", "loc", "sys",
        )
        governance.register_asset(
            "Logs", "Desc", DataType.LOGS,
            DataClassification.INTERNAL, "owner", "loc", "sys",
        )
        
        summary = governance.get_compliance_summary()
        
        assert 'regulated_data_types' in summary
        assert summary['total_regulated_assets'] == 2


class TestEthicsAgent:
    """Test EthicsAgent."""
    
    @pytest.fixture
    def ethics(self):
        """Create EthicsAgent instance."""
        return EthicsAgent()
    
    def test_register_model(self, ethics):
        """Test registering AI model."""
        model = ethics.register_model(
            name="Credit Scoring Model",
            description="ML model for creditworthiness",
            model_type="classification",
            purpose="Loan eligibility",
            developer="ml-team@example.com",
            risk_level=RiskLevel.HIGH,
            training_data_description="Historical loans 2020-2024",
        )
        
        assert model.model_id.startswith("model-")
        assert model.risk_level == RiskLevel.HIGH
    
    def test_create_ethics_assessment(self, ethics):
        """Test creating ethics assessment."""
        model = ethics.register_model(
            "Test Model", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.MEDIUM,
        )
        
        assessment = ethics.create_ethics_assessment(
            model.model_id,
            assessment_type="initial",
            principles_evaluated=[EthicsPrinciple.FAIRNESS, EthicsPrinciple.TRANSPARENCY],
        )
        
        assert assessment.assessment_id.startswith("ethics-")
        assert assessment.status == AssessmentStatus.DRAFT
    
    def test_add_finding(self, ethics):
        """Test adding ethics finding."""
        model = ethics.register_model(
            "Test", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        
        assessment = ethics.create_ethics_assessment(model.model_id, "initial")
        
        result = ethics.add_finding(
            assessment.assessment_id,
            EthicsPrinciple.FAIRNESS,
            "Discriminatory outcomes detected",
            RiskLevel.HIGH,
            "Investigate training data",
        )
        
        assert result is True
        assert len(assessment.findings) == 1
    
    def test_detect_bias(self, ethics):
        """Test bias detection."""
        model = ethics.register_model(
            "Test Model", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        
        bias = ethics.detect_bias(
            model.model_id,
            bias_type=BiasType.HISTORICAL,
            affected_group="Age 18-25",
            description="Lower approval rates for young applicants",
            evidence={'rate_young': 0.45, 'rate_overall': 0.68},
            metric_used=FairnessMetric.DEMOGRAPHIC_PARITY,
            metric_value=0.23,
        )
        
        assert bias.bias_id.startswith("bias-")
        assert bias.severity == RiskLevel.HIGH  # 0.23 > 0.1 threshold * 2
    
    def test_generate_fairness_report(self, ethics):
        """Test fairness report generation."""
        model = ethics.register_model(
            "Test", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.MEDIUM,
        )
        
        report = ethics.generate_fairness_report(
            model.model_id,
            dataset="test_2024",
            protected_attributes=['age', 'gender'],
            metrics={
                'demographic_parity': {'disparity': 0.15},
                'equalized_odds': {'disparity': 0.08},
            },
        )
        
        assert report.report_id.startswith("fairness-")
        assert 'overall_score' in report
        assert len(report.disparities) >= 1
    
    def test_add_explainability_record(self, ethics):
        """Test adding explainability record."""
        model = ethics.register_model(
            "Test", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.MEDIUM,
        )
        
        record = ethics.add_explainability_record(
            model.model_id,
            technique="SHAP",
            explanation_type="global",
            features=[{'name': 'income', 'importance': 0.35}],
        )
        
        assert record.record_id.startswith("explain-")
        assert record.technique == "SHAP"
    
    def test_report_incident(self, ethics):
        """Test reporting ethical incident."""
        model = ethics.register_model(
            "Test", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        
        incident = ethics.report_incident(
            title="Discriminatory Outcomes",
            description="Model showing bias against protected group",
            severity=RiskLevel.HIGH,
            principles_violated=[EthicsPrinciple.FAIRNESS, EthicsPrinciple.NON_DISCRIMINATION],
            model_id=model.model_id,
            affected_parties=["Age 18-25"],
        )
        
        assert incident.incident_id.startswith("incident-")
        assert len(incident.principles_violated) == 2
    
    def test_configure_oversight(self, ethics):
        """Test configuring human oversight."""
        model = ethics.register_model(
            "Test", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        
        oversight = ethics.configure_oversight(
            model.model_id,
            oversight_type="human_in_loop",
            trigger_conditions=["Low confidence", "Borderline decision"],
            reviewers=["senior@example.com"],
            escalation_path=["manager@example.com"],
        )
        
        assert oversight.oversight_id.startswith("oversight-")
        assert oversight.enabled is True
    
    def test_get_ethics_report(self, ethics):
        """Test ethics report generation."""
        ethics.register_model(
            "Model 1", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        ethics.register_model(
            "Model 2", "Desc", "regression",
            "Purpose", "dev@example.com", RiskLevel.MEDIUM,
        )
        
        report = ethics.get_ethics_report()
        
        assert 'models' in report
        assert 'assessments' in report
        assert 'bias' in report
        assert report['models']['total'] == 2
    
    def test_get_model_ethics_profile(self, ethics):
        """Test model ethics profile."""
        model = ethics.register_model(
            "Test Model", "Desc", "classification",
            "Purpose", "dev@example.com", RiskLevel.HIGH,
        )
        
        ethics.create_ethics_assessment(model.model_id, "initial")
        
        profile = ethics.get_model_ethics_profile(model.model_id)
        
        assert profile['model']['name'] == "Test Model"
        assert 'assessments' in profile
        assert 'bias' in profile


class TestRiskAgent:
    """Test RiskAgent."""
    
    @pytest.fixture
    def risk(self):
        """Create RiskAgent instance."""
        return RiskAgent()
    
    def test_identify_risk(self, risk):
        """Test identifying risk."""
        risk_item = risk.identify_risk(
            title="Data Breach",
            description="Potential unauthorized access",
            category=RiskCategory.CYBERSECURITY,
            owner="ciso@example.com",
            inherent_likelihood=4,
            inherent_impact=5,
            tags=['security', 'data'],
        )
        
        assert risk_item.risk_id.startswith("risk-")
        assert risk_item.inherent_score == 20  # 4 * 5
        assert risk_item.category == RiskCategory.CYBERSECURITY
    
    def test_assess_risk(self, risk):
        """Test risk assessment."""
        risk_item = risk.identify_risk(
            "Test Risk", "Description",
            RiskCategory.OPERATIONAL, "owner@example.com",
            inherent_likelihood=3,
            inherent_impact=4,
        )
        
        result = risk.assess_risk(
            risk_item.risk_id,
            controls=['control-1'],
            residual_likelihood=2,
            residual_impact=4,
        )
        
        assert result is True
        assert risk_item.residual_score == 8  # 2 * 4
        assert risk_item.status == RiskStatus.ASSESSED
    
    def test_plan_treatment(self, risk):
        """Test treatment planning."""
        risk_item = risk.identify_risk(
            "Test", "Desc",
            RiskCategory.FINANCIAL, "owner@example.com",
            inherent_likelihood=3,
            inherent_impact=3,
        )
        
        result = risk.plan_treatment(
            risk_item.risk_id,
            strategy=TreatmentStrategy.REDUCE,
            treatment_plan="Implement additional controls",
            target_resolution=datetime.utcnow() + timedelta(days=90),
        )
        
        assert result is True
        assert risk_item.treatment_strategy == TreatmentStrategy.REDUCE
    
    def test_create_control(self, risk):
        """Test creating control."""
        risk_item = risk.identify_risk(
            "Test", "Desc",
            RiskCategory.CYBERSECURITY, "owner@example.com",
            inherent_likelihood=3,
            inherent_impact=3,
        )
        
        control = risk.create_control(
            name="Multi-Factor Authentication",
            description="MFA for all access",
            control_type="preventive",
            owner="security@example.com",
            risk_id=risk_item.risk_id,
            automated=True,
        )
        
        assert control.control_id.startswith("ctrl-")
        assert control.control_type == "preventive"
        assert control.automated is True
    
    def test_test_control(self, risk):
        """Test control testing."""
        control = risk.create_control(
            "Test Control", "Description",
            "preventive", "owner@example.com",
        )
        
        result = risk.test_control(
            control.control_id,
            effectiveness="effective",
            test_results="All tests passed",
        )
        
        assert result is True
        assert control.effectiveness == "effective"
        assert control.last_tested is not None
    
    def test_create_kri(self, risk):
        """Test creating KRI."""
        kri = risk.create_kri(
            name="Failed Login Attempts",
            description="Daily failed login count",
            category=RiskCategory.CYBERSECURITY,
            metric_type="count",
            threshold_green=100,
            threshold_yellow=500,
            threshold_red=1000,
            direction="lower_is_better",
        )
        
        assert kri.kri_id.startswith("kri-")
        assert kri.threshold_green == 100
        assert kri.threshold_red == 1000
    
    def test_update_kri_value(self, risk):
        """Test updating KRI value."""
        kri = risk.create_kri(
            "Test KRI", "Description",
            RiskCategory.CYBERSECURITY, "count",
            threshold_green=100,
            threshold_yellow=500,
            threshold_red=1000,
        )
        
        # Green
        risk.update_kri_value(kri.kri_id, current_value=50)
        assert kri.status == "green"
        
        # Yellow
        risk.update_kri_value(kri.kri_id, current_value=600)
        assert kri.status == "yellow"
        
        # Red
        risk.update_kri_value(kri.kri_id, current_value=1200)
        assert kri.status == "red"
    
    def test_get_kris_at_risk(self, risk):
        """Test getting KRIs at risk."""
        kri1 = risk.create_kri(
            "KRI 1", "Desc", RiskCategory.CYBERSECURITY,
            "count", 100, 500, 1000,
        )
        kri2 = risk.create_kri(
            "KRI 2", "Desc", RiskCategory.CYBERSECURITY,
            "count", 100, 500, 1000,
        )
        
        risk.update_kri_value(kri1.kri_id, current_value=800)  # Yellow
        risk.update_kri_value(kri2.kri_id, current_value=50)   # Green
        
        at_risk = risk.get_kris_at_risk()
        
        assert len(at_risk) == 1
        assert at_risk[0].kri_id == kri1.kri_id
    
    def test_create_assessment(self, risk):
        """Test creating risk assessment."""
        assessment = risk.create_assessment(
            name="Q1 Cybersecurity Assessment",
            scope="All IT systems",
            assessor="risk-team@example.com",
            start_date=datetime.utcnow(),
        )
        
        assert assessment.assessment_id.startswith("assess-")
        assert assessment.status == "planned"
    
    def test_complete_assessment(self, risk):
        """Test completing assessment."""
        assessment = risk.create_assessment(
            "Test Assessment", "Scope",
            "assessor@example.com", datetime.utcnow(),
        )
        
        result = risk.complete_assessment(
            assessment.assessment_id,
            risks_identified=10,
            findings=[
                {'severity': 'high', 'finding': 'Finding 1'},
                {'severity': 'critical', 'finding': 'Finding 2'},
            ],
            recommendations=["Recommendation 1"],
        )
        
        assert result is True
        assert assessment.status == "completed"
        assert assessment.critical_risks == 1
    
    def test_report_event(self, risk):
        """Test reporting risk event."""
        risk_item = risk.identify_risk(
            "Test Risk", "Desc",
            RiskCategory.CYBERSECURITY, "owner@example.com",
            inherent_likelihood=3,
            inherent_impact=3,
        )
        
        event = risk.report_event(
            title="Phishing Attack",
            description="Targeted phishing campaign",
            actual_impact="2 employees clicked",
            financial_impact=5000.0,
            risk_id=risk_item.risk_id,
        )
        
        assert event.event_id.startswith("event-")
        assert event.financial_impact == 5000.0
    
    def test_resolve_event(self, risk):
        """Test resolving event."""
        event = risk.report_event(
            "Test Event", "Description",
            "Impact description", financial_impact=1000.0,
        )
        
        result = risk.resolve_event(
            event.event_id,
            root_cause="Root cause identified",
            lessons_learned=["Lesson 1", "Lesson 2"],
        )
        
        assert result is True
        assert event.status == "resolved"
    
    def test_get_high_priority_risks(self, risk):
        """Test getting high priority risks."""
        risk.identify_risk(
            "Low Risk", "Desc", RiskCategory.OPERATIONAL,
            "owner@example.com", inherent_likelihood=1, inherent_impact=1,
        )
        risk.identify_risk(
            "High Risk", "Desc", RiskCategory.CYBERSECURITY,
            "owner@example.com", inherent_likelihood=5, inherent_impact=5,
        )
        risk.identify_risk(
            "Medium Risk", "Desc", RiskCategory.FINANCIAL,
            "owner@example.com", inherent_likelihood=3, inherent_impact=3,
        )
        
        high_priority = risk.get_high_priority_risks(limit=2)
        
        assert len(high_priority) == 2
        assert high_priority[0].residual_score == 25  # Highest first
    
    def test_get_risk_register(self, risk):
        """Test risk register generation."""
        risk.identify_risk(
            "Risk 1", "Desc", RiskCategory.CYBERSECURITY,
            "owner@example.com", inherent_likelihood=4, inherent_impact=5,
        )
        risk.identify_risk(
            "Risk 2", "Desc", RiskCategory.FINANCIAL,
            "owner@example.com", inherent_likelihood=3, inherent_impact=3,
        )
        
        register = risk.get_risk_register()
        
        assert 'total_risks' in register
        assert 'by_category' in register
        assert 'by_score' in register
        assert register['total_risks'] == 2
    
    def test_get_risk_dashboard(self, risk):
        """Test risk dashboard."""
        risk.identify_risk(
            "Critical Risk", "Desc", RiskCategory.CYBERSECURITY,
            "owner@example.com", inherent_likelihood=5, inherent_impact=5,
        )
        
        dashboard = risk.get_risk_dashboard()
        
        assert 'overview' in dashboard
        assert 'top_risks' in dashboard
        assert 'kris' in dashboard
        assert 'events' in dashboard
        assert 'controls' in dashboard
    
    def test_get_risk_appetite_status(self, risk):
        """Test risk appetite compliance."""
        risk.identify_risk(
            "Cyber Risk", "Desc", RiskCategory.CYBERSECURITY,
            "owner@example.com", inherent_likelihood=5, inherent_impact=5,
        )
        
        status = risk.get_risk_appetite_status()
        
        assert 'cybersecurity' in status
        assert 'compliant' in status['cybersecurity']


class TestCapabilities:
    """Test capabilities export for GRC agents."""
    
    def test_governance_capabilities(self):
        """Test DataGovernanceAgent capabilities."""
        from agentic_ai.agents.data_governance import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'data_governance'
        assert len(caps['capabilities']) >= 22
        assert 'register_asset' in caps['capabilities']
        assert 'create_retention_policy' in caps['capabilities']
    
    def test_ethics_capabilities(self):
        """Test EthicsAgent capabilities."""
        from agentic_ai.agents.ethics import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'ethics'
        assert len(caps['capabilities']) >= 21
        assert 'register_model' in caps['capabilities']
        assert 'detect_bias' in caps['capabilities']
    
    def test_risk_capabilities(self):
        """Test RiskAgent capabilities."""
        from agentic_ai.agents.risk import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'risk'
        assert len(caps['capabilities']) >= 22
        assert 'identify_risk' in caps['capabilities']
        assert 'create_kri' in caps['capabilities']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
