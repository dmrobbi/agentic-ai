"""Unit tests for PrivacyAgent."""
import pytest
from agentic_ai.agents.privacy import (
    PrivacyAgent,
    PrivacyRegulation,
    DataSubjectRight,
    RequestStatus,
    ConsentStatus,
    ProcessingPurpose,
    DataSubject,
    DataProcessingActivity,
    DataSubjectRequest,
    ConsentRecord,
    PrivacyImpactAssessment,
    DataBreach,
)


class TestPrivacyAgentInit:
    def test_default_init(self):
        agent = PrivacyAgent()
        assert agent.agent_id == "privacy-agent"
        assert isinstance(agent.data_subjects, dict)
        assert isinstance(agent.requests, dict)
        assert isinstance(agent.consent_records, dict)
        assert isinstance(agent.processing_activities, dict)
        assert isinstance(agent.pias, dict)
        assert isinstance(agent.breaches, dict)

    def test_custom_id(self):
        agent = PrivacyAgent(agent_id="privacy-001")
        assert agent.agent_id == "privacy-001"

    def test_regulation_requirements_initialized(self):
        agent = PrivacyAgent()
        assert PrivacyRegulation.GDPR.value in agent.regulation_requirements
        assert PrivacyRegulation.CCPA.value in agent.regulation_requirements
        assert agent.regulation_requirements["gdpr"]["response_days"] == 30

    def test_retention_policies_initialized(self):
        agent = PrivacyAgent()
        assert "customer_data" in agent.retention_policies


class TestPrivacyAgentDataSubject:
    def test_register_data_subject(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(
            name="John Doe",
            email="john@example.com",
            jurisdiction="EU",
            applicable_regulations=[PrivacyRegulation.GDPR],
        )
        assert isinstance(subject, DataSubject)
        assert subject.name == "John Doe"
        assert subject.email == "john@example.com"
        assert subject.verified is False
        assert subject.subject_id.startswith("subj-")

    def test_register_data_subject_with_custom_id(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(
            name="Jane",
            email="jane@test.com",
            jurisdiction="US",
            subject_id="custom-subj-1",
        )
        assert subject.subject_id == "custom-subj-1"

    def test_register_data_subject_empty_fields(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject()
        assert subject.name == ""
        assert subject.email == ""
        assert subject.jurisdiction == "US"

    def test_verify_data_subject(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="Test", email="t@t.com", jurisdiction="EU")
        result = agent.verify_data_subject(subject.subject_id, "id_check")
        assert result is True
        assert subject.verified is True

    def test_verify_data_subject_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.verify_data_subject("nonexistent", "id_check")
        assert result is False

    def test_get_data_subject(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="Test", email="t@t.com", jurisdiction="EU")
        found = agent.get_data_subject(subject.subject_id)
        assert found is not None
        assert found.name == "Test"

    def test_get_data_subject_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.get_data_subject("nonexistent")
        assert result is None

    def test_get_data_subjects_filter_jurisdiction(self):
        agent = PrivacyAgent()
        agent.register_data_subject(name="A", email="a@a.com", jurisdiction="EU")
        agent.register_data_subject(name="B", email="b@b.com", jurisdiction="US")
        eu = agent.get_data_subjects(jurisdiction="EU")
        assert len(eu) == 1

    def test_get_data_subjects_filter_regulation(self):
        agent = PrivacyAgent()
        agent.register_data_subject(name="A", email="a@a.com", jurisdiction="EU",
                                     applicable_regulations=[PrivacyRegulation.GDPR])
        gdpr = agent.get_data_subjects(regulation=PrivacyRegulation.GDPR)
        assert len(gdpr) == 1


class TestPrivacyAgentRequest:
    def test_create_request(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="Test", email="t@t.com", jurisdiction="EU",
                                              applicable_regulations=[PrivacyRegulation.GDPR])
        request = agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        assert isinstance(request, DataSubjectRequest)
        assert request.right_type == DataSubjectRight.ACCESS
        assert request.status == RequestStatus.SUBMITTED
        assert request.deadline is not None

    def test_create_request_nonexistent_subject_raises(self):
        agent = PrivacyAgent()
        with pytest.raises(ValueError, match="not found"):
            agent.create_request("nonexistent", DataSubjectRight.ACCESS)

    def test_verify_request(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        result = agent.verify_request(request.request_id)
        assert result is True
        assert request.status == RequestStatus.VERIFIED
        assert request.verified_at is not None

    def test_verify_request_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.verify_request("nonexistent")
        assert result is False

    def test_update_request_status_completed(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        result = agent.update_request_status(request.request_id, RequestStatus.COMPLETED)
        assert result is True
        assert request.completed_at is not None

    def test_update_request_status_denied(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        result = agent.update_request_status(request.request_id, RequestStatus.DENIED, denial_reason="Invalid")
        assert result is True
        assert request.denial_reason == "Invalid"

    def test_update_request_status_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.update_request_status("nonexistent", RequestStatus.COMPLETED)
        assert result is False

    def test_fulfill_access_request(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        result = agent.fulfill_access_request(request.request_id, {"profile": {"name": "T"}})
        assert result is True
        assert request.status == RequestStatus.COMPLETED
        assert request.response_data is not None

    def test_fulfill_access_request_wrong_type(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ERASURE)
        result = agent.fulfill_access_request(request.request_id, {"data": "x"})
        assert result is False

    def test_fulfill_erasure_request(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        request = agent.create_request(subject.subject_id, DataSubjectRight.ERASURE)
        result = agent.fulfill_erasure_request(request.request_id, ["db1", "db2"])
        assert result is True
        assert request.response_data["systems_cleared"] == ["db1", "db2"]

    def test_get_requests_filter(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        agent.create_request(subject.subject_id, DataSubjectRight.ACCESS)
        agent.create_request(subject.subject_id, DataSubjectRight.ERASURE)
        access = agent.get_requests(right_type=DataSubjectRight.ACCESS)
        assert len(access) == 1


class TestPrivacyAgentConsent:
    def test_record_consent(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        consent = agent.record_consent(
            subject_id=subject.subject_id,
            purpose=ProcessingPurpose.MARKETING,
            method="web_form",
            ip_address="1.2.3.4",
        )
        assert isinstance(consent, ConsentRecord)
        assert consent.status == ConsentStatus.GIVEN
        assert consent.purpose == ProcessingPurpose.MARKETING
        assert consent.method == "web_form"

    def test_record_consent_with_expiry(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        consent = agent.record_consent(
            subject_id=subject.subject_id,
            purpose=ProcessingPurpose.ANALYTICS,
            method="api",
            expires_in_days=30,
        )
        assert consent.expires_at is not None

    def test_withdraw_consent(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        consent = agent.record_consent(subject.subject_id, ProcessingPurpose.MARKETING, "web_form")
        result = agent.withdraw_consent(consent.consent_id)
        assert result is True
        assert consent.status == ConsentStatus.WITHDRAWN
        assert consent.withdrawn_at is not None

    def test_withdraw_consent_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.withdraw_consent("nonexistent")
        assert result is False

    def test_check_valid_consent_true(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        agent.record_consent(subject.subject_id, ProcessingPurpose.MARKETING, "web_form")
        result = agent.check_valid_consent(subject.subject_id, ProcessingPurpose.MARKETING)
        assert result is True

    def test_check_valid_consent_false(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        result = agent.check_valid_consent(subject.subject_id, ProcessingPurpose.MARKETING)
        assert result is False

    def test_get_consents_filter(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(name="T", email="t@t.com", jurisdiction="EU")
        agent.record_consent(subject.subject_id, ProcessingPurpose.MARKETING, "web")
        agent.record_consent(subject.subject_id, ProcessingPurpose.ANALYTICS, "api")
        marketing = agent.get_consents(purpose=ProcessingPurpose.MARKETING)
        assert len(marketing) == 1


class TestPrivacyAgentProcessing:
    def test_add_processing_activity(self):
        agent = PrivacyAgent()
        activity = agent.add_processing_activity(
            name="Customer Analytics",
            description="Analyze customer behavior",
            data_categories=["behavioral", "transactional"],
            purposes=[ProcessingPurpose.ANALYTICS],
            legal_basis="legitimate_interest",
            retention_days=365,
            risk_level="medium",
        )
        assert isinstance(activity, DataProcessingActivity)
        assert activity.name == "Customer Analytics"
        assert activity.legal_basis == "legitimate_interest"

    def test_get_processing_activities_filter(self):
        agent = PrivacyAgent()
        agent.add_processing_activity("A", "d", ["cat1"], [ProcessingPurpose.ANALYTICS], "consent", 365, risk_level="high")
        agent.add_processing_activity("B", "d", ["cat2"], [ProcessingPurpose.SERVICE_DELIVERY], "contract", 365, risk_level="low")
        high = agent.get_processing_activities(risk_level="high")
        assert len(high) == 1

    def test_register_processing_activity_alias(self):
        agent = PrivacyAgent()
        activity = agent.register_processing_activity(
            name="Alias Test",
            description="Test alias",
            data_categories=["cat1"],
            legal_basis="consent",
        )
        assert activity.name == "Alias Test"


class TestPrivacyAgentPIA:
    def test_create_pia(self):
        agent = PrivacyAgent()
        pia = agent.create_pia(
            name="AI Recommender PIA",
            project_description="ML-based recommendations",
            data_categories=["browsing", "purchase"],
            processing_purposes=[ProcessingPurpose.PERSONALIZATION],
        )
        assert isinstance(pia, PrivacyImpactAssessment)
        assert pia.status == "draft"

    def test_add_risk_to_pia(self):
        agent = PrivacyAgent()
        pia = agent.create_pia("Test PIA", "desc", ["cat1"], [ProcessingPurpose.ANALYTICS])
        result = agent.add_risk_to_pia(pia.pia_id, "Profiling risk", "high", "high")
        assert result is True
        assert len(pia.risks_identified) == 1
        assert pia.risk_level == "high"

    def test_add_risk_to_pia_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.add_risk_to_pia("nonexistent", "risk", "low", "low")
        assert result is False

    def test_approve_pia(self):
        agent = PrivacyAgent()
        pia = agent.create_pia("Test", "desc", ["cat1"], [ProcessingPurpose.ANALYTICS])
        result = agent.approve_pia(pia.pia_id, dpo_reviewed=True)
        assert result is True
        assert pia.status == "approved"
        assert pia.dpo_review is True
        assert pia.approved_at is not None

    def test_approve_pia_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.approve_pia("nonexistent")
        assert result is False

    def test_get_pias_filter(self):
        agent = PrivacyAgent()
        agent.create_pia("A", "desc", ["cat1"], [ProcessingPurpose.ANALYTICS])
        drafts = agent.get_pias(status="draft")
        assert len(drafts) == 1


class TestPrivacyAgentBreach:
    def test_report_breach(self):
        agent = PrivacyAgent()
        breach = agent.report_breach(
            title="Email Exposure",
            description="Emails leaked via API",
            severity="high",
            affected_subjects=5000,
            data_categories=["email", "names"],
        )
        assert isinstance(breach, DataBreach)
        assert breach.status == "detected"
        assert breach.notification_required is True

    def test_report_breach_low_severity(self):
        agent = PrivacyAgent()
        breach = agent.report_breach("Low", "desc", "low", 10, ["logs"])
        assert breach.notification_required is False

    def test_contain_breach(self):
        agent = PrivacyAgent()
        breach = agent.report_breach("T", "d", "high", 100, ["email"])
        result = agent.contain_breach(breach.breach_id)
        assert result is True
        assert breach.status == "contained"
        assert breach.contained_at is not None

    def test_contain_breach_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.contain_breach("nonexistent")
        assert result is False

    def test_notify_authority(self):
        agent = PrivacyAgent()
        breach = agent.report_breach("T", "d", "high", 100, ["email"])
        agent.contain_breach(breach.breach_id)
        result = agent.notify_authority(breach.breach_id, "ICO")
        assert result is True
        assert breach.notified_authority is not None
        assert breach.status == "notified"

    def test_close_breach(self):
        agent = PrivacyAgent()
        breach = agent.report_breach("T", "d", "high", 100, ["email"])
        result = agent.close_breach(breach.breach_id, "misconfiguration", ["fix config"])
        assert result is True
        assert breach.status == "closed"
        assert breach.root_cause == "misconfiguration"

    def test_close_breach_nonexistent(self):
        agent = PrivacyAgent()
        result = agent.close_breach("nonexistent", "rc", ["fix"])
        assert result is False

    def test_get_breaches_filter(self):
        agent = PrivacyAgent()
        agent.report_breach("T1", "d", "high", 100, ["email"])
        agent.report_breach("T2", "d", "low", 10, ["logs"])
        high = agent.get_breaches(severity="high")
        assert len(high) == 1


class TestPrivacyAgentReporting:
    def test_get_compliance_report(self):
        agent = PrivacyAgent()
        report = agent.get_compliance_report()
        assert "data_subjects" in report
        assert "requests" in report
        assert "consents" in report
        assert "breaches" in report
        assert "pias" in report

    def test_get_regulation_compliance(self):
        agent = PrivacyAgent()
        subject = agent.register_data_subject(
            name="T", email="t@t.com", jurisdiction="EU",
            applicable_regulations=[PrivacyRegulation.GDPR],
        )
        status = agent.get_regulation_compliance(PrivacyRegulation.GDPR)
        assert status["regulation"] == "gdpr"
        assert "requests" in status
        assert status["data_subjects"] >= 1

    def test_create_data_request_alias(self):
        agent = PrivacyAgent()
        request = agent.create_data_request(subject_id="auto-subj", right_type=DataSubjectRight.ACCESS)
        assert request.subject_id == "auto-subj"
        assert request.right_type == DataSubjectRight.ACCESS

    def test_get_state(self):
        agent = PrivacyAgent()
        state = agent.get_state()
        assert state["agent_id"] == "privacy-agent"
        assert "data_subjects_count" in state
        assert "requests_count" in state