"""Unit tests for RiskAgent."""
import pytest
from datetime import datetime, timedelta
from agentic_ai.agents.risk import (
    RiskAgent,
    RiskCategory,
    RiskLevel,
    RiskStatus,
    TreatmentStrategy,
    Risk,
    Control,
    KeyRiskIndicator,
    RiskAssessment,
    RiskEvent,
)
from agentic_ai.infrastructure.utils import utcnow


class TestRiskAgentInit:
    def test_default_init(self):
        agent = RiskAgent()
        assert agent.agent_id == "risk-agent"
        assert isinstance(agent.risks, dict)
        assert isinstance(agent.controls, dict)
        assert isinstance(agent.kris, dict)
        assert isinstance(agent.assessments, dict)
        assert isinstance(agent.events, dict)

    def test_custom_id(self):
        agent = RiskAgent(agent_id="risk-001")
        assert agent.agent_id == "risk-001"

    def test_risk_appetite_initialized(self):
        agent = RiskAgent()
        assert RiskCategory.STRATEGIC in agent.risk_appetite
        assert RiskCategory.COMPLIANCE in agent.risk_appetite
        assert agent.risk_appetite[RiskCategory.COMPLIANCE]["tolerance"] == "very_low"

    def test_risk_matrix_initialized(self):
        agent = RiskAgent()
        assert isinstance(agent.risk_matrix, dict)
        assert len(agent.risk_matrix) > 0


class TestRiskAgentIdentify:
    def test_identify_risk_basic(self):
        agent = RiskAgent()
        risk = agent.identify_risk(
            title="Data Breach",
            description="Unauthorized access",
            category=RiskCategory.CYBERSECURITY,
            owner="ciso",
            inherent_likelihood=4,
            inherent_impact=5,
        )
        assert isinstance(risk, Risk)
        assert risk.title == "Data Breach"
        assert risk.status == RiskStatus.IDENTIFIED
        assert risk.inherent_score == 20
        assert risk.residual_score == 20  # same as inherent initially

    def test_identify_risk_with_tags(self):
        agent = RiskAgent()
        risk = agent.identify_risk(
            "T", "D", RiskCategory.FINANCIAL, "cfo", 3, 3, tags=["audit"]
        )
        assert risk.tags == ["audit"]

    def test_identify_risk_score_calculation(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.OPERATIONAL, "own", 2, 3)
        assert risk.inherent_score == 6
        assert risk.residual_score == 6

    def test_identify_risk_empty_tags(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.LEGAL, "own", 1, 1)
        assert risk.tags == []


class TestRiskAgentAssess:
    def test_assess_risk(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.CYBERSECURITY, "own", 4, 5)
        result = agent.assess_risk(
            risk.risk_id,
            controls=["ctrl-1"],
            residual_likelihood=2,
            residual_impact=3,
        )
        assert result is True
        assert risk.status == RiskStatus.ASSESSED
        assert risk.residual_score == 6
        assert risk.assessed_at is not None

    def test_assess_risk_nonexistent(self):
        agent = RiskAgent()
        result = agent.assess_risk("nonexistent")
        assert result is False

    def test_assess_risk_partial_update(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.FINANCIAL, "own", 3, 4)
        agent.assess_risk(risk.risk_id, residual_likelihood=1)
        assert risk.residual_likelihood == 1
        assert risk.residual_impact == 4  # unchanged
        assert risk.residual_score == 4


class TestRiskAgentTreatment:
    def test_plan_treatment(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.CYBERSECURITY, "own", 4, 5)
        target = utcnow() + timedelta(days=90)
        result = agent.plan_treatment(
            risk.risk_id,
            TreatmentStrategy.REDUCE,
            "Implement MFA",
            target_resolution=target,
        )
        assert result is True
        assert risk.treatment_strategy == TreatmentStrategy.REDUCE
        assert risk.treatment_plan == "Implement MFA"
        assert risk.status == RiskStatus.TREATMENT_PLANNED
        assert risk.target_resolution == target

    def test_plan_treatment_nonexistent(self):
        agent = RiskAgent()
        result = agent.plan_treatment("nonexistent", TreatmentStrategy.ACCEPT, "plan")
        assert result is False


class TestRiskAgentUpdateStatus:
    def test_update_risk_status(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.OPERATIONAL, "own", 2, 2)
        result = agent.update_risk_status(risk.risk_id, RiskStatus.MONITORED)
        assert result is True
        assert risk.status == RiskStatus.MONITORED

    def test_update_risk_status_closed(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.LEGAL, "own", 1, 1)
        result = agent.update_risk_status(risk.risk_id, RiskStatus.CLOSED)
        assert result is True
        assert risk.closed_at is not None

    def test_update_risk_status_nonexistent(self):
        agent = RiskAgent()
        result = agent.update_risk_status("nonexistent", RiskStatus.CLOSED)
        assert result is False


class TestRiskAgentGetRisks:
    def test_get_risks_all(self):
        agent = RiskAgent()
        agent.identify_risk("T1", "D", RiskCategory.FINANCIAL, "own", 2, 2)
        agent.identify_risk("T2", "D", RiskCategory.CYBERSECURITY, "own", 3, 3)
        risks = agent.get_risks()
        assert len(risks) == 2

    def test_get_risks_filter_category(self):
        agent = RiskAgent()
        agent.identify_risk("T1", "D", RiskCategory.FINANCIAL, "own", 2, 2)
        agent.identify_risk("T2", "D", RiskCategory.CYBERSECURITY, "own", 3, 3)
        fin = agent.get_risks(category=RiskCategory.FINANCIAL)
        assert len(fin) == 1

    def test_get_risks_filter_owner(self):
        agent = RiskAgent()
        agent.identify_risk("T1", "D", RiskCategory.FINANCIAL, "alice", 2, 2)
        agent.identify_risk("T2", "D", RiskCategory.FINANCIAL, "bob", 3, 3)
        alice = agent.get_risks(owner="alice")
        assert len(alice) == 1

    def test_get_risks_filter_min_score(self):
        agent = RiskAgent()
        agent.identify_risk("Low", "D", RiskCategory.OPERATIONAL, "own", 1, 1)
        agent.identify_risk("High", "D", RiskCategory.CYBERSECURITY, "own", 5, 5)
        high = agent.get_risks(min_score=10)
        assert len(high) == 1
        assert high[0].title == "High"

    def test_get_high_priority_risks(self):
        agent = RiskAgent()
        agent.identify_risk("Low", "D", RiskCategory.OPERATIONAL, "own", 1, 1)
        agent.identify_risk("High", "D", RiskCategory.CYBERSECURITY, "own", 5, 5)
        high = agent.get_high_priority_risks(limit=5)
        assert len(high) <= 5
        if len(high) >= 2:
            assert high[0].residual_score >= high[1].residual_score


class TestRiskAgentControls:
    def test_create_control(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.CYBERSECURITY, "own", 4, 5)
        ctrl = agent.create_control(
            name="MFA",
            description="Multi-factor auth",
            control_type="preventive",
            owner="sec-team",
            risk_id=risk.risk_id,
            automated=True,
        )
        assert isinstance(ctrl, Control)
        assert ctrl.name == "MFA"
        assert ctrl.automated is True

    def test_create_control_links_to_risk(self):
        agent = RiskAgent()
        risk = agent.identify_risk("T", "D", RiskCategory.CYBERSECURITY, "own", 4, 5)
        ctrl = agent.create_control("MFA", "desc", "preventive", "own", risk_id=risk.risk_id)
        assert ctrl.control_id in risk.controls

    def test_test_control(self):
        agent = RiskAgent()
        ctrl = agent.create_control("MFA", "desc", "preventive", "own")
        result = agent.test_control(ctrl.control_id, "effective", "All tests passed")
        assert result is True
        assert ctrl.effectiveness == "effective"
        assert ctrl.last_tested is not None

    def test_test_control_nonexistent(self):
        agent = RiskAgent()
        result = agent.test_control("nonexistent", "effective", "test")
        assert result is False

    def test_get_controls_filter(self):
        agent = RiskAgent()
        agent.create_control("A", "d", "preventive", "own")
        agent.create_control("B", "d", "detective", "own")
        prev = agent.get_controls(control_type="preventive")
        assert len(prev) == 1


class TestRiskAgentKRI:
    def test_create_kri(self):
        agent = RiskAgent()
        kri = agent.create_kri(
            name="Failed Logins",
            description="Failed login attempts per day",
            category=RiskCategory.CYBERSECURITY,
            metric_type="count",
            threshold_green=100,
            threshold_yellow=500,
            threshold_red=1000,
            direction="lower_is_better",
        )
        assert isinstance(kri, KeyRiskIndicator)
        assert kri.status == "green"  # default
        assert kri.name == "Failed Logins"

    def test_update_kri_value_green(self):
        agent = RiskAgent()
        kri = agent.create_kri("F", "d", RiskCategory.CYBERSECURITY, "count", 100, 500, 1000, "lower_is_better")
        agent.update_kri_value(kri.kri_id, 50)
        assert kri.status == "green"

    def test_update_kri_value_yellow(self):
        agent = RiskAgent()
        kri = agent.create_kri("F", "d", RiskCategory.CYBERSECURITY, "count", 100, 500, 1000, "lower_is_better")
        agent.update_kri_value(kri.kri_id, 600)
        assert kri.status == "yellow"

    def test_update_kri_value_red(self):
        agent = RiskAgent()
        kri = agent.create_kri("F", "d", RiskCategory.CYBERSECURITY, "count", 100, 500, 1000, "lower_is_better")
        agent.update_kri_value(kri.kri_id, 1200)
        assert kri.status == "red"

    def test_update_kri_value_higher_is_better(self):
        agent = RiskAgent()
        kri = agent.create_kri("U", "d", RiskCategory.OPERATIONAL, "percentage", 95, 80, 60, "higher_is_better")
        agent.update_kri_value(kri.kri_id, 97)
        assert kri.status == "green"

    def test_update_kri_nonexistent(self):
        agent = RiskAgent()
        result = agent.update_kri_value("nonexistent", 50)
        assert result is False

    def test_get_kris_at_risk(self):
        agent = RiskAgent()
        kri = agent.create_kri("F", "d", RiskCategory.CYBERSECURITY, "count", 100, 500, 1000, "lower_is_better")
        agent.update_kri_value(kri.kri_id, 1200)
        at_risk = agent.get_kris_at_risk()
        assert len(at_risk) == 1


class TestRiskAgentAssessments:
    def test_create_assessment(self):
        agent = RiskAgent()
        assessment = agent.create_assessment(
            name="Q1 Review",
            scope="All systems",
            assessor="risk-team",
            start_date=utcnow(),
        )
        assert isinstance(assessment, RiskAssessment)
        assert assessment.name == "Q1 Review"
        assert assessment.status == "planned"

    def test_complete_assessment(self):
        agent = RiskAgent()
        assessment = agent.create_assessment("Q1", "All", "team", utcnow())
        result = agent.complete_assessment(
            assessment.assessment_id,
            risks_identified=15,
            findings=[{"severity": "high", "finding": "X"}],
            recommendations=["Fix X"],
        )
        assert result is True
        assert assessment.status == "completed"
        assert assessment.risks_identified == 15

    def test_complete_assessment_nonexistent(self):
        agent = RiskAgent()
        result = agent.complete_assessment("nonexistent", 5)
        assert result is False


class TestRiskAgentEvents:
    def test_report_event(self):
        agent = RiskAgent()
        event = agent.report_event(
            title="Phishing",
            description="Phishing campaign",
            actual_impact="2 users affected",
            financial_impact=5000.0,
        )
        assert isinstance(event, RiskEvent)
        assert event.title == "Phishing"
        assert event.financial_impact == 5000.0
        assert event.status == "reported"

    def test_resolve_event(self):
        agent = RiskAgent()
        event = agent.report_event("T", "D", "impact")
        result = agent.resolve_event(event.event_id, "insufficient training", ["more training"])
        assert result is True
        assert event.status == "resolved"
        assert event.root_cause == "insufficient training"

    def test_resolve_event_nonexistent(self):
        agent = RiskAgent()
        result = agent.resolve_event("nonexistent", "rc", ["lesson"])
        assert result is False

    def test_get_events_filter(self):
        agent = RiskAgent()
        event = agent.report_event("T", "D", "impact")
        resolved = agent.get_events(status="resolved")
        assert len(resolved) == 0


class TestRiskAgentReporting:
    def test_get_risk_register(self):
        agent = RiskAgent()
        agent.identify_risk("T", "D", RiskCategory.CYBERSECURITY, "own", 3, 3)
        register = agent.get_risk_register()
        assert "total_risks" in register
        assert "by_category" in register
        assert "by_status" in register
        assert "by_score" in register

    def test_get_risk_dashboard(self):
        agent = RiskAgent()
        dashboard = agent.get_risk_dashboard()
        assert "overview" in dashboard
        assert "top_risks" in dashboard
        assert "kris" in dashboard
        assert "events" in dashboard
        assert "controls" in dashboard

    def test_get_risk_appetite_status(self):
        agent = RiskAgent()
        status = agent.get_risk_appetite_status()
        assert isinstance(status, dict)
        for cat in agent.risk_appetite:
            assert cat.value in status

    def test_get_state(self):
        agent = RiskAgent()
        state = agent.get_state()
        assert state["agent_id"] == "risk-agent"
        assert "risks_count" in state
        assert "controls_count" in state