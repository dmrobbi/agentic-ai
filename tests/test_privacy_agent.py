"""
PrivacyAgent Tests
==================

Unit tests for PrivacyAgent - GDPR, CCPA, and privacy compliance.
"""

import pytest
from datetime import datetime, timedelta

from agentic_ai.agents.privacy import (
    PrivacyAgent,
    PrivacyRegulation,
    DataSubjectRight,
    RequestStatus,
    ConsentStatus,
    ProcessingPurpose,
)


class TestPrivacyAgent:
    """Test PrivacyAgent."""
    
    @pytest.fixture
    def privacy(self):
        """Create PrivacyAgent instance."""
        return PrivacyAgent()
    
    def test_register_data_subject(self, privacy):
        """Test data subject registration."""
        subject = privacy.register_data_subject(
            name="John Doe",
            email="john@example.com",
            jurisdiction="EU",
            applicable_regulations=[PrivacyRegulation.GDPR],
        )
        
        assert subject.subject_id.startswith("subj-")
        assert subject.email == "john@example.com"
        assert subject.jurisdiction == "EU"
        assert PrivacyRegulation.GDPR in subject.applicable_regulations
    
    def test_verify_data_subject(self, privacy):
        """Test data subject verification."""
        subject = privacy.register_data_subject(
            "Jane Doe",
            "jane@example.com",
            "California",
            [PrivacyRegulation.CCPA],
        )
        
        result = privacy.verify_data_subject(subject.subject_id, "email")
        
        assert result is True
        assert subject.verified is True
    
    def test_create_access_request(self, privacy):
        """Test creating access request."""
        subject = privacy.register_data_subject(
            "Test User",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        request = privacy.create_request(
            subject_id=subject.subject_id,
            right_type=DataSubjectRight.ACCESS,
            assigned_to="privacy@example.com",
        )
        
        assert request.request_id.startswith("req-")
        assert request.right_type == DataSubjectRight.ACCESS
        assert request.status == RequestStatus.SUBMITTED
        assert request.deadline > datetime.utcnow()
    
    def test_fulfill_access_request(self, privacy):
        """Test fulfilling access request."""
        subject = privacy.register_data_subject(
            "Test User",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        request = privacy.create_request(
            subject_id=subject.subject_id,
            right_type=DataSubjectRight.ACCESS,
        )
        
        result = privacy.fulfill_access_request(
            request.request_id,
            data={'profile': {'name': 'Test'}, 'orders': []},
        )
        
        assert result is True
        assert request.status == RequestStatus.COMPLETED
        assert request.response_data is not None
    
    def test_fulfill_erasure_request(self, privacy):
        """Test fulfilling erasure request."""
        subject = privacy.register_data_subject(
            "Test User",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        request = privacy.create_request(
            subject_id=subject.subject_id,
            right_type=DataSubjectRight.ERASURE,
        )
        
        result = privacy.fulfill_erasure_request(
            request.request_id,
            systems_cleared=['db', 'analytics', 'marketing'],
        )
        
        assert result is True
        assert request.status == RequestStatus.COMPLETED
    
    def test_get_overdue_requests(self, privacy):
        """Test getting overdue requests."""
        subject = privacy.register_data_subject(
            "Test",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        request = privacy.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        
        # Manually set deadline to past
        request.deadline = datetime.utcnow() - timedelta(days=1)
        request.status = RequestStatus.IN_PROGRESS
        
        overdue = privacy.get_requests(overdue_only=True)
        
        assert len(overdue) >= 1
    
    def test_record_consent(self, privacy):
        """Test recording consent."""
        subject = privacy.register_data_subject(
            "Test User",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        consent = privacy.record_consent(
            subject_id=subject.subject_id,
            purpose=ProcessingPurpose.MARKETING,
            method="web_form",
            ip_address="192.168.1.100",
            expires_in_days=365,
        )
        
        assert consent.consent_id.startswith("consent-")
        assert consent.status == ConsentStatus.GIVEN
        assert consent.purpose == ProcessingPurpose.MARKETING
        assert consent.expires_at > datetime.utcnow()
    
    def test_withdraw_consent(self, privacy):
        """Test withdrawing consent."""
        subject = privacy.register_data_subject(
            "Test",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        consent = privacy.record_consent(
            subject.subject_id,
            ProcessingPurpose.MARKETING,
            "web_form",
        )
        
        result = privacy.withdraw_consent(consent.consent_id)
        
        assert result is True
        assert consent.status == ConsentStatus.WITHDRAWN
        assert consent.withdrawn_at is not None
    
    def test_check_valid_consent(self, privacy):
        """Test checking valid consent."""
        subject = privacy.register_data_subject(
            "Test",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        # Record valid consent
        privacy.record_consent(
            subject.subject_id,
            ProcessingPurpose.ANALYTICS,
            "web_form",
            expires_in_days=365,
        )
        
        result = privacy.check_valid_consent(subject.subject_id, ProcessingPurpose.ANALYTICS)
        
        assert result is True
    
    def test_add_processing_activity(self, privacy):
        """Test adding processing activity."""
        activity = privacy.add_processing_activity(
            name="Customer Analytics",
            description="Analyze customer behavior",
            data_categories=['behavioral', 'transactional'],
            purposes=[ProcessingPurpose.ANALYTICS],
            legal_basis="legitimate_interest",
            retention_days=365,
            risk_level="medium",
        )
        
        assert activity.activity_id.startswith("ropa-")
        assert activity.name == "Customer Analytics"
        assert activity.risk_level == "medium"
    
    def test_create_pia(self, privacy):
        """Test creating Privacy Impact Assessment."""
        pia = privacy.create_pia(
            name="AI System PIA",
            project_description="ML-based recommendations",
            data_categories=['purchase_history', 'browsing'],
            purposes=[ProcessingPurpose.PERSONALIZATION],
        )
        
        assert pia.pia_id.startswith("pia-")
        assert pia.status == "draft"
        assert pia.risk_level == "pending"
    
    def test_add_risk_to_pia(self, privacy):
        """Test adding risk to PIA."""
        pia = privacy.create_pia(
            "Test PIA",
            "Description",
            ['data'],
            [ProcessingPurpose.ANALYTICS],
        )
        
        privacy.add_risk_to_pia(
            pia.pia_id,
            "Discrimination risk",
            likelihood="high",
            impact="high",
            mitigations=["Bias testing"],
        )
        
        assert len(pia.risks_identified) == 1
        assert pia.risk_level == "high"
    
    def test_approve_pia(self, privacy):
        """Test approving PIA."""
        pia = privacy.create_pia("Test", "Desc", ['data'], [ProcessingPurpose.ANALYTICS])
        
        result = privacy.approve_pia(pia.pia_id, dpo_reviewed=True)
        
        assert result is True
        assert pia.status == "approved"
        assert pia.dpo_review is True
    
    def test_report_breach(self, privacy):
        """Test reporting data breach."""
        breach = privacy.report_breach(
            title="Email Exposure",
            description="Customer emails exposed",
            severity="high",
            affected_subjects=5000,
            data_categories=['email', 'names'],
        )
        
        assert breach.breach_id.startswith("breach-")
        assert breach.status == "detected"
        assert breach.notification_required is True
    
    def test_contain_breach(self, privacy):
        """Test containing breach."""
        breach = privacy.report_breach(
            "Test Breach",
            "Description",
            "high",
            100,
            ['email'],
        )
        
        result = privacy.contain_breach(breach.breach_id)
        
        assert result is True
        assert breach.status == "contained"
        assert breach.contained_at is not None
    
    def test_notify_authority(self, privacy):
        """Test notifying authority of breach."""
        breach = privacy.report_breach(
            "Test",
            "Desc",
            "high",
            100,
            ['data'],
        )
        
        privacy.contain_breach(breach.breach_id)
        result = privacy.notify_authority(breach.breach_id, "ICO")
        
        assert result is True
        assert breach.notified_authority is not None
    
    def test_close_breach(self, privacy):
        """Test closing breach."""
        breach = privacy.report_breach(
            "Test",
            "Desc",
            "high",
            100,
            ['data'],
        )
        
        result = privacy.close_breach(
            breach.breach_id,
            root_cause="Misconfigured API",
            remediation=["Fix config", "Add monitoring"],
        )
        
        assert result is True
        assert breach.status == "closed"
        assert breach.root_cause == "Misconfigured API"
    
    def test_get_compliance_report(self, privacy):
        """Test compliance report generation."""
        # Add some data
        subject = privacy.register_data_subject(
            "Test",
            "test@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        privacy.record_consent(subject.subject_id, ProcessingPurpose.MARKETING, "web")
        privacy.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        
        report = privacy.get_compliance_report()
        
        assert 'data_subjects' in report
        assert 'requests' in report
        assert 'consents' in report
        assert 'breaches' in report
        assert 'pias' in report
        assert 'completion_rate' in report['requests']
    
    def test_get_regulation_compliance(self, privacy):
        """Test regulation-specific compliance."""
        privacy.register_data_subject(
            "EU User",
            "eu@example.com",
            "EU",
            [PrivacyRegulation.GDPR],
        )
        
        compliance = privacy.get_regulation_compliance(PrivacyRegulation.GDPR)
        
        assert compliance['regulation'] == 'gdpr'
        assert compliance['jurisdiction'] == 'EU'
        assert 'response_deadline_days' in compliance
        assert compliance['response_deadline_days'] == 30
    
    def test_get_data_subjects_by_jurisdiction(self, privacy):
        """Test filtering data subjects by jurisdiction."""
        privacy.register_data_subject("EU User", "eu@example.com", "EU", [PrivacyRegulation.GDPR])
        privacy.register_data_subject("CA User", "ca@example.com", "California", [PrivacyRegulation.CCPA])
        
        eu_subjects = privacy.get_data_subjects(jurisdiction="EU")
        
        assert len(eu_subjects) == 1
        assert eu_subjects[0].jurisdiction == "EU"
    
    def test_get_breaches_by_severity(self, privacy):
        """Test filtering breaches by severity."""
        privacy.report_breach("Low", "Desc", "low", 10, ['data'])
        privacy.report_breach("High", "Desc", "high", 100, ['data'])
        privacy.report_breach("Critical", "Desc", "critical", 1000, ['data'])
        
        high_breaches = privacy.get_breaches(severity="high")
        
        assert len(high_breaches) == 1


class TestPrivacyAgentCapabilities:
    """Test PrivacyAgent capabilities export."""
    
    def test_capabilities(self):
        """Test capabilities export."""
        from agentic_ai.agents.privacy import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'privacy'
        assert len(caps['capabilities']) >= 26
        assert 'register_data_subject' in caps['capabilities']
        assert 'create_request' in caps['capabilities']
        assert 'record_consent' in caps['capabilities']
        assert 'report_breach' in caps['capabilities']
        assert 'get_compliance_report' in caps['capabilities']
    
    def test_regulations_list(self):
        """Test regulations list in capabilities."""
        from agentic_ai.agents.privacy import get_capabilities
        caps = get_capabilities()
        
        assert 'gdpr' in caps['regulations']
        assert 'ccpa' in caps['regulations']
        assert 'lgpd' in caps['regulations']
        assert 'hipaa' in caps['regulations']
    
    def test_data_subject_rights(self):
        """Test data subject rights in capabilities."""
        from agentic_ai.agents.privacy import get_capabilities
        caps = get_capabilities()
        
        assert 'access' in caps['data_subject_rights']
        assert 'erasure' in caps['data_subject_rights']
        assert 'portability' in caps['data_subject_rights']
        assert 'rectification' in caps['data_subject_rights']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
