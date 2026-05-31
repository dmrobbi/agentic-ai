"""Unit tests for EthicsAgent."""
import pytest
from agentic_ai.agents.ethics import (
    EthicsAgent,
    EthicsPrinciple,
    BiasType,
    FairnessMetric,
    RiskLevel,
    AssessmentStatus,
    AIModel,
    EthicsAssessment,
    BiasAssessment,
    FairnessReport,
    ExplainabilityRecord,
    EthicalIncident,
    HumanOversight,
)


class TestEthicsAgentInit:
    def test_default_init(self):
        agent = EthicsAgent()
        assert agent.agent_id == "ethics-agent"
        assert isinstance(agent.models, dict)
        assert isinstance(agent.assessments, dict)
        assert isinstance(agent.bias_assessments, dict)
        assert isinstance(agent.fairness_reports, dict)
        assert isinstance(agent.explainability, dict)
        assert isinstance(agent.incidents, dict)
        assert isinstance(agent.oversight, dict)

    def test_custom_id(self):
        agent = EthicsAgent(agent_id="ethics-custom-01")
        assert agent.agent_id == "ethics-custom-01"

    def test_ethics_guidelines_initialized(self):
        agent = EthicsAgent()
        assert EthicsPrinciple.FAIRNESS in agent.ethics_guidelines
        assert EthicsPrinciple.TRANSPARENCY in agent.ethics_guidelines
        assert len(agent.ethics_guidelines) >= 5

    def test_bias_thresholds_initialized(self):
        agent = EthicsAgent()
        assert FairnessMetric.DEMOGRAPHIC_PARITY in agent.bias_thresholds
        assert agent.bias_thresholds[FairnessMetric.DEMOGRAPHIC_PARITY] == 0.1


class TestEthicsAgentRegisterModel:
    def test_register_model_basic(self):
        agent = EthicsAgent()
        model = agent.register_model(
            name="Credit Model",
            description="Scoring model",
            model_type="classification",
            purpose="Credit scoring",
            developer="ml-team",
            risk_level=RiskLevel.HIGH,
        )
        assert isinstance(model, AIModel)
        assert model.name == "Credit Model"
        assert model.risk_level == RiskLevel.HIGH
        assert model.model_id.startswith("model-")

    def test_register_model_with_tags(self):
        agent = EthicsAgent()
        model = agent.register_model(
            name="Test",
            description="desc",
            model_type="nlp",
            purpose="sentiment",
            developer="team",
            risk_level=RiskLevel.LOW,
            tags=["finance", "test"],
        )
        assert model.tags == ["finance", "test"]

    def test_register_model_default_tags_empty(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.MEDIUM)
        assert model.tags == []

    def test_update_model_risk(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.LOW)
        result = agent.update_model_risk(model.model_id, RiskLevel.HIGH)
        assert result is True
        assert model.risk_level == RiskLevel.HIGH

    def test_update_model_risk_nonexistent(self):
        agent = EthicsAgent()
        result = agent.update_model_risk("nonexistent", RiskLevel.HIGH)
        assert result is False

    def test_get_models_filter_by_risk(self):
        agent = EthicsAgent()
        agent.register_model("A", "d", "cls", "p", "dev", RiskLevel.HIGH)
        agent.register_model("B", "d", "cls", "p", "dev", RiskLevel.LOW)
        high = agent.get_models(risk_level=RiskLevel.HIGH)
        assert len(high) == 1
        assert high[0].name == "A"

    def test_get_models_filter_by_type(self):
        agent = EthicsAgent()
        agent.register_model("A", "d", "classification", "p", "dev", RiskLevel.LOW)
        agent.register_model("B", "d", "nlp", "p", "dev", RiskLevel.LOW)
        cls_models = agent.get_models(model_type="classification")
        assert len(cls_models) == 1


class TestEthicsAgentAssessment:
    def test_create_ethics_assessment(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.MEDIUM)
        assessment = agent.create_ethics_assessment(model.model_id, "initial")
        assert isinstance(assessment, EthicsAssessment)
        assert assessment.status == AssessmentStatus.DRAFT
        assert assessment.assessment_type == "initial"
        assert len(assessment.principles_evaluated) > 0

    def test_create_ethics_assessment_custom_principles(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.MEDIUM)
        assessment = agent.create_ethics_assessment(
            model.model_id, "periodic",
            principles_evaluated=[EthicsPrinciple.FAIRNESS, EthicsPrinciple.TRANSPARENCY],
        )
        assert len(assessment.principles_evaluated) == 2

    def test_create_assessment_nonexistent_model_raises(self):
        agent = EthicsAgent()
        with pytest.raises(ValueError, match="not found"):
            agent.create_ethics_assessment("nonexistent", "initial")

    def test_add_finding(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.MEDIUM)
        assessment = agent.create_ethics_assessment(model.model_id, "initial")
        result = agent.add_finding(
            assessment.assessment_id,
            EthicsPrinciple.FAIRNESS,
            "Lower approval rates",
            RiskLevel.HIGH,
            "Investigate data",
        )
        assert result is True
        assert len(assessment.findings) == 1
        assert assessment.overall_risk == RiskLevel.HIGH

    def test_add_finding_nonexistent_assessment(self):
        agent = EthicsAgent()
        result = agent.add_finding("nonexistent", EthicsPrinciple.FAIRNESS, "f", RiskLevel.LOW, "r")
        assert result is False

    def test_complete_assessment(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.MEDIUM)
        assessment = agent.create_ethics_assessment(model.model_id, "initial")
        result = agent.complete_assessment(
            assessment.assessment_id,
            reviewer="board",
            status=AssessmentStatus.APPROVED,
            mitigations=["Retrain"],
        )
        assert result is True
        assert assessment.status == AssessmentStatus.APPROVED
        assert assessment.reviewer == "board"

    def test_complete_assessment_nonexistent(self):
        agent = EthicsAgent()
        result = agent.complete_assessment("nonexistent", "r", AssessmentStatus.APPROVED)
        assert result is False


class TestEthicsAgentBias:
    def test_detect_bias(self):
        agent = EthicsAgent()
        bias = agent.detect_bias(
            model_id="model-1",
            bias_type=BiasType.HISTORICAL,
            affected_group="Age 18-25",
            description="Lower approval rates",
            evidence={"rate": 0.45},
            metric_used=FairnessMetric.DEMOGRAPHIC_PARITY,
            metric_value=0.23,
        )
        assert isinstance(bias, BiasAssessment)
        assert bias.bias_type == BiasType.HISTORICAL
        assert bias.affected_group == "Age 18-25"
        assert bias.status == "identified"

    def test_detect_bias_high_severity(self):
        agent = EthicsAgent()
        bias = agent.detect_bias(
            model_id="model-1",
            bias_type=BiasType.REPRESENTATION,
            affected_group="Women",
            description="Under-represented",
            evidence={},
            metric_used=FairnessMetric.DEMOGRAPHIC_PARITY,
            metric_value=0.5,
        )
        assert bias.severity == RiskLevel.HIGH

    def test_create_remediation_plan(self):
        agent = EthicsAgent()
        bias = agent.detect_bias("m1", BiasType.HISTORICAL, "g", "d", {})
        result = agent.create_remediation_plan(bias.bias_id, "Retrain with balanced data")
        assert result is True
        assert bias.remediation_plan == "Retrain with balanced data"
        assert bias.status == "investigating"

    def test_create_remediation_plan_nonexistent(self):
        agent = EthicsAgent()
        result = agent.create_remediation_plan("nonexistent", "plan")
        assert result is False

    def test_mark_bias_mitigated(self):
        agent = EthicsAgent()
        bias = agent.detect_bias("m1", BiasType.HISTORICAL, "g", "d", {})
        result = agent.mark_bias_mitigated(bias.bias_id)
        assert result is True
        assert bias.status == "mitigated"

    def test_mark_bias_mitigated_nonexistent(self):
        agent = EthicsAgent()
        result = agent.mark_bias_mitigated("nonexistent")
        assert result is False

    def test_get_bias_assessments_filter(self):
        agent = EthicsAgent()
        agent.detect_bias("m1", BiasType.HISTORICAL, "g1", "d", {})
        agent.detect_bias("m2", BiasType.REPRESENTATION, "g2", "d", {})
        historical = agent.get_bias_assessments(bias_type=BiasType.HISTORICAL)
        assert len(historical) == 1


class TestEthicsAgentFairness:
    def test_generate_fairness_report(self):
        agent = EthicsAgent()
        report = agent.generate_fairness_report(
            model_id="model-1",
            dataset="test_data",
            protected_attributes=["age", "gender"],
            metrics={"demographic_parity": {"disparity": 0.05}},
        )
        assert isinstance(report, FairnessReport)
        assert report.model_id == "model-1"
        assert report.overall_score >= 0

    def test_generate_fairness_report_with_disparities(self):
        agent = EthicsAgent()
        report = agent.generate_fairness_report(
            model_id="model-1",
            dataset="test",
            protected_attributes=["age"],
            metrics={"demographic_parity": {"disparity": 0.3}},
        )
        assert len(report.disparities) > 0
        assert len(report.recommendations) > 0

    def test_get_fairness_reports_filter(self):
        agent = EthicsAgent()
        agent.generate_fairness_report("m1", "d", ["age"], {"demographic_parity": {"disparity": 0.05}})
        agent.generate_fairness_report("m2", "d", ["gender"], {"equalized_odds": {"disparity": 0.02}})
        m1_reports = agent.get_fairness_reports(model_id="m1")
        assert len(m1_reports) == 1


class TestEthicsAgentExplainability:
    def test_add_explainability_record(self):
        agent = EthicsAgent()
        record = agent.add_explainability_record(
            model_id="model-1",
            technique="SHAP",
            explanation_type="global",
            features=[{"name": "income", "importance": 0.35}],
        )
        assert isinstance(record, ExplainabilityRecord)
        assert record.technique == "SHAP"
        assert record.explanation_type == "global"
        assert len(record.features) == 1

    def test_get_explainability(self):
        agent = EthicsAgent()
        agent.add_explainability_record("m1", "SHAP", "global")
        agent.add_explainability_record("m1", "LIME", "local")
        agent.add_explainability_record("m2", "SHAP", "global")
        m1_records = agent.get_explainability("m1")
        assert len(m1_records) == 2


class TestEthicsAgentIncidents:
    def test_report_incident(self):
        agent = EthicsAgent()
        incident = agent.report_incident(
            title="Discriminatory output",
            description="Model produces biased results",
            severity=RiskLevel.HIGH,
            principles_violated=[EthicsPrinciple.FAIRNESS, EthicsPrinciple.NON_DISCRIMINATION],
            affected_parties=["customers"],
        )
        assert isinstance(incident, EthicalIncident)
        assert incident.status == "reported"

    def test_resolve_incident(self):
        agent = EthicsAgent()
        incident = agent.report_incident("t", "d", RiskLevel.HIGH, [EthicsPrinciple.FAIRNESS])
        result = agent.resolve_incident(incident.incident_id, "bias in data", ["retrain"])
        assert result is True
        assert incident.status == "resolved"
        assert incident.root_cause == "bias in data"

    def test_resolve_incident_nonexistent(self):
        agent = EthicsAgent()
        result = agent.resolve_incident("nonexistent", "rc", ["rem"])
        assert result is False

    def test_get_incidents_filter_by_severity(self):
        agent = EthicsAgent()
        agent.report_incident("T1", "d", RiskLevel.HIGH, [EthicsPrinciple.FAIRNESS])
        agent.report_incident("T2", "d", RiskLevel.LOW, [EthicsPrinciple.SAFETY])
        high = agent.get_incidents(severity=RiskLevel.HIGH)
        assert len(high) == 1


class TestEthicsAgentOversight:
    def test_configure_oversight(self):
        agent = EthicsAgent()
        ov = agent.configure_oversight(
            model_id="model-1",
            oversight_type="human_in_loop",
            trigger_conditions=["low confidence"],
            reviewers=["analyst@example.com"],
            escalation_path=["manager@example.com"],
        )
        assert isinstance(ov, HumanOversight)
        assert ov.oversight_type == "human_in_loop"
        assert ov.enabled is True

    def test_get_oversight_config(self):
        agent = EthicsAgent()
        agent.configure_oversight("m1", "human_on_loop", ["trigger"], ["reviewer"])
        config = agent.get_oversight_config("m1")
        assert config is not None
        assert config.oversight_type == "human_on_loop"

    def test_get_oversight_config_not_found(self):
        agent = EthicsAgent()
        config = agent.get_oversight_config("nonexistent")
        assert config is None


class TestEthicsAgentReporting:
    def test_get_ethics_report(self):
        agent = EthicsAgent()
        report = agent.get_ethics_report()
        assert "models" in report
        assert "assessments" in report
        assert "bias" in report
        assert "incidents" in report
        assert "oversight" in report

    def test_get_model_ethics_profile(self):
        agent = EthicsAgent()
        model = agent.register_model("M", "d", "cls", "p", "dev", RiskLevel.HIGH)
        profile = agent.get_model_ethics_profile(model.model_id)
        assert "model" in profile
        assert profile["model"]["risk_level"] == "high"

    def test_get_model_ethics_profile_nonexistent(self):
        agent = EthicsAgent()
        profile = agent.get_model_ethics_profile("nonexistent")
        assert "error" in profile

    def test_get_state(self):
        agent = EthicsAgent()
        state = agent.get_state()
        assert state["agent_id"] == "ethics-agent"
        assert "models_count" in state
        assert "incidents_count" in state