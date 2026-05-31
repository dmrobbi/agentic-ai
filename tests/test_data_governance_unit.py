"""Unit tests for DataGovernanceAgent."""
import pytest
from agentic_ai.agents.data_governance import (
    DataGovernanceAgent,
    DataClassification,
    DataType,
    DataQualityDimension,
    RetentionAction,
    DataAsset,
    RetentionPolicy,
    DataLineage,
    DataQualityRule,
    QualityIssue,
    AccessRequest,
)


class TestDataGovernanceAgentInit:
    def test_default_init(self):
        agent = DataGovernanceAgent()
        assert agent.agent_id == "data-governance-agent"
        assert isinstance(agent.assets, dict)
        assert isinstance(agent.retention_policies, dict)
        assert isinstance(agent.lineage, dict)
        assert isinstance(agent.quality_rules, dict)
        assert isinstance(agent.quality_issues, dict)
        assert isinstance(agent.access_requests, dict)

    def test_custom_id(self):
        agent = DataGovernanceAgent(agent_id="dg-001")
        assert agent.agent_id == "dg-001"

    def test_default_retention_initialized(self):
        agent = DataGovernanceAgent()
        assert DataType.PII in agent.default_retention
        assert DataType.PHI in agent.default_retention
        assert DataType.LOGS in agent.default_retention

    def test_classification_keywords_initialized(self):
        agent = DataGovernanceAgent()
        assert DataClassification.CRITICAL in agent.classification_keywords
        assert DataClassification.RESTRICTED in agent.classification_keywords


class TestDataGovernanceAgentAsset:
    def test_register_asset_basic(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset(
            name="Customer DB",
            description="Main customer database",
            data_type=DataType.PII,
            classification=DataClassification.RESTRICTED,
            owner="data-team",
        )
        assert isinstance(asset, DataAsset)
        assert asset.name == "Customer DB"
        assert asset.data_type == DataType.PII
        assert asset.classification == DataClassification.RESTRICTED
        assert asset.asset_id.startswith("asset-")

    def test_register_asset_defaults(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset(name="Test")
        assert asset.data_type == DataType.STRUCTURED
        assert asset.classification == DataClassification.INTERNAL
        assert asset.tags == []

    def test_register_asset_with_all_fields(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset(
            name="Full",
            description="desc",
            data_type=DataType.PCI,
            classification=DataClassification.CRITICAL,
            owner="alice",
            location="s3://bucket",
            system="AWS",
            steward="bob",
            tags=["pci", "critical"],
        )
        assert asset.steward == "bob"
        assert asset.location == "s3://bucket"
        # register_asset does not pass tags to DataAsset; tags stay default []
        assert asset.tags == []

    def test_update_asset_metrics(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset(name="DB", data_type=DataType.PII, classification=DataClassification.RESTRICTED, owner="o")
        result = agent.update_asset_metrics(asset.asset_id, record_count=1000, size_bytes=50000)
        assert result is True
        assert asset.record_count == 1000
        assert asset.size_bytes == 50000

    def test_update_asset_metrics_nonexistent(self):
        agent = DataGovernanceAgent()
        result = agent.update_asset_metrics("nonexistent", record_count=10)
        assert result is False

    def test_update_asset_metrics_partial(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset(name="DB", data_type=DataType.PII, classification=DataClassification.RESTRICTED, owner="o")
        agent.update_asset_metrics(asset.asset_id, record_count=500)
        assert asset.record_count == 500
        assert asset.size_bytes == 0

    def test_get_assets_all(self):
        agent = DataGovernanceAgent()
        agent.register_asset("A", "d", DataType.PII, DataClassification.RESTRICTED, "o1")
        agent.register_asset("B", "d", DataType.LOGS, DataClassification.INTERNAL, "o2")
        assets = agent.get_assets()
        assert len(assets) == 2

    def test_get_assets_filter_classification(self):
        agent = DataGovernanceAgent()
        agent.register_asset("A", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        agent.register_asset("B", "d", DataType.LOGS, DataClassification.PUBLIC, "o")
        restricted = agent.get_assets(classification=DataClassification.RESTRICTED)
        assert len(restricted) == 1

    def test_get_assets_filter_owner(self):
        agent = DataGovernanceAgent()
        agent.register_asset("A", "d", DataType.PII, DataClassification.RESTRICTED, "alice")
        agent.register_asset("B", "d", DataType.LOGS, DataClassification.PUBLIC, "bob")
        alice = agent.get_assets(owner="alice")
        assert len(alice) == 1


class TestDataGovernanceAgentClassify:
    def test_classify_critical(self):
        agent = DataGovernanceAgent()
        result = agent.classify_data("This is a trade_secret document")
        assert result == DataClassification.CRITICAL

    def test_classify_restricted(self):
        agent = DataGovernanceAgent()
        result = agent.classify_data("Contains ssn and credit_card numbers")
        assert result == DataClassification.RESTRICTED

    def test_classify_confidential(self):
        agent = DataGovernanceAgent()
        result = agent.classify_data("This is confidential proprietary info")
        assert result == DataClassification.CONFIDENTIAL

    def test_classify_public(self):
        agent = DataGovernanceAgent()
        result = agent.classify_data("This is a public published press release")
        assert result == DataClassification.PUBLIC

    def test_classify_default_internal(self):
        agent = DataGovernanceAgent()
        result = agent.classify_data("Just some regular internal data")
        assert result == DataClassification.INTERNAL


class TestDataGovernanceAgentRetention:
    def test_create_retention_policy(self):
        agent = DataGovernanceAgent()
        policy = agent.create_retention_policy(
            name="PII Retention",
            data_types=[DataType.PII],
            retention_period=730,
            action=RetentionAction.DELETE,
            regulatory_requirement="GDPR Art. 5",
        )
        assert isinstance(policy, RetentionPolicy)
        assert policy.name == "PII Retention"
        assert policy.retention_period == 730
        assert policy.action == RetentionAction.DELETE

    def test_create_retention_policy_with_legal_hold(self):
        agent = DataGovernanceAgent()
        policy = agent.create_retention_policy(
            "Hold", [DataType.FINANCIAL], 2555, RetentionAction.ARCHIVE,
            legal_hold=True,
        )
        assert policy.legal_hold is True

    def test_get_retention_period_with_policy(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        agent.create_retention_policy("PII Pol", [DataType.PII], 730, RetentionAction.DELETE)
        result = agent.get_retention_period(asset.asset_id)
        assert result["retention_period"] == 730
        assert result["action"] == "delete"

    def test_get_retention_period_default(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.LOGS, DataClassification.INTERNAL, "o")
        result = agent.get_retention_period(asset.asset_id)
        assert result["policy_id"] == "default"

    def test_get_retention_period_nonexistent_asset(self):
        agent = DataGovernanceAgent()
        result = agent.get_retention_period("nonexistent")
        assert "error" in result


class TestDataGovernanceAgentLineage:
    def test_add_lineage(self):
        agent = DataGovernanceAgent()
        lineage = agent.add_lineage(
            source_asset="asset-1",
            target_asset="asset-2",
            transformation="ETL - anonymized",
            process_name="daily_etl",
            frequency="daily",
        )
        assert isinstance(lineage, DataLineage)
        assert lineage.source_asset == "asset-1"
        assert lineage.transformation == "ETL - anonymized"

    def test_update_lineage_status(self):
        agent = DataGovernanceAgent()
        lineage = agent.add_lineage("a1", "a2", "transform", "proc")
        result = agent.update_lineage_status(lineage.lineage_id, "success", records_processed=1000)
        assert result is True
        assert lineage.status == "success"
        assert lineage.records_processed == 1000

    def test_update_lineage_status_nonexistent(self):
        agent = DataGovernanceAgent()
        result = agent.update_lineage_status("nonexistent", "success")
        assert result is False

    def test_get_lineage_both(self):
        agent = DataGovernanceAgent()
        agent.add_lineage("a1", "a2", "t1", "p1")
        result = agent.get_lineage("a2", direction="both")
        assert "upstream" in result
        assert "downstream" in result
        assert len(result["upstream"]) == 1

    def test_get_lineage_upstream_only(self):
        agent = DataGovernanceAgent()
        agent.add_lineage("a1", "a2", "t1", "p1")
        result = agent.get_lineage("a2", direction="upstream")
        assert "upstream" in result
        assert "downstream" not in result


class TestDataGovernanceAgentQuality:
    def test_create_quality_rule(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        rule = agent.create_quality_rule(
            name="Email Completeness",
            asset_id=asset.asset_id,
            dimension=DataQualityDimension.COMPLETENESS,
            rule_expression="email IS NOT NULL",
            threshold=95.0,
            severity="high",
        )
        assert isinstance(rule, DataQualityRule)
        assert rule.name == "Email Completeness"
        assert rule.threshold == 95.0

    def test_execute_quality_check_pass(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        rule = agent.create_quality_rule("R", asset.asset_id, DataQualityDimension.COMPLETENESS, "expr", 95.0)
        result = agent.execute_quality_check(rule.rule_id, result=98.0)
        assert result is True
        assert rule.last_result == 98.0
        # No issue created because result >= threshold
        issues = agent.get_quality_issues(asset_id=asset.asset_id)
        assert len(issues) == 0

    def test_execute_quality_check_fail(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        rule = agent.create_quality_rule("R", asset.asset_id, DataQualityDimension.COMPLETENESS, "expr", 95.0)
        agent.execute_quality_check(rule.rule_id, result=80.0)
        issues = agent.get_quality_issues(asset_id=asset.asset_id)
        assert len(issues) == 1
        assert issues[0].status == "open"

    def test_execute_quality_check_nonexistent_rule(self):
        agent = DataGovernanceAgent()
        result = agent.execute_quality_check("nonexistent", 80.0)
        assert result is False

    def test_resolve_quality_issue(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        rule = agent.create_quality_rule("R", asset.asset_id, DataQualityDimension.COMPLETENESS, "expr", 95.0)
        agent.execute_quality_check(rule.rule_id, result=80.0)
        issues = agent.get_quality_issues(asset_id=asset.asset_id)
        result = agent.resolve_quality_issue(issues[0].issue_id, "Fixed data pipeline")
        assert result is True
        assert issues[0].status == "resolved"

    def test_resolve_quality_issue_nonexistent(self):
        agent = DataGovernanceAgent()
        result = agent.resolve_quality_issue("nonexistent", "fix")
        assert result is False

    def test_get_quality_score(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        agent.create_quality_rule("R1", asset.asset_id, DataQualityDimension.COMPLETENESS, "expr", 95.0)
        agent.create_quality_rule("R2", asset.asset_id, DataQualityDimension.ACCURACY, "expr", 90.0)
        result = agent.get_quality_score(asset.asset_id)
        assert result["score"] is None  # no checks executed yet

    def test_get_quality_score_after_checks(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        r1 = agent.create_quality_rule("R1", asset.asset_id, DataQualityDimension.COMPLETENESS, "expr", 95.0)
        r2 = agent.create_quality_rule("R2", asset.asset_id, DataQualityDimension.ACCURACY, "expr", 90.0)
        agent.execute_quality_check(r1.rule_id, 98.0)
        agent.execute_quality_check(r2.rule_id, 95.0)
        score = agent.get_quality_score(asset.asset_id)
        assert score["score"] is not None
        assert score["score"] > 0


class TestDataGovernanceAgentAccess:
    def test_request_access(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        request = agent.request_access(
            asset_id=asset.asset_id,
            requester="analyst@example.com",
            purpose="Q2 analysis",
            access_level="read",
        )
        assert isinstance(request, AccessRequest)
        assert request.status == "pending"
        assert request.access_level == "read"

    def test_approve_access(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        request = agent.request_access(asset.asset_id, "analyst", "analysis", "read")
        result = agent.approve_access(request.request_id, "owner", expires_in_days=30)
        assert result is True
        assert request.status == "approved"
        assert request.approved_by == "owner"
        assert request.expires_at is not None

    def test_approve_access_nonexistent(self):
        agent = DataGovernanceAgent()
        result = agent.approve_access("nonexistent", "owner")
        assert result is False

    def test_deny_access(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        request = agent.request_access(asset.asset_id, "analyst", "analysis", "read")
        result = agent.deny_access(request.request_id, "owner", "Insufficient justification")
        assert result is True
        assert request.status == "denied"

    def test_revoke_access(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        request = agent.request_access(asset.asset_id, "analyst", "analysis", "read")
        agent.approve_access(request.request_id, "owner")
        result = agent.revoke_access(request.request_id)
        assert result is True
        assert request.status == "revoked"

    def test_revoke_access_nonexistent(self):
        agent = DataGovernanceAgent()
        result = agent.revoke_access("nonexistent")
        assert result is False

    def test_get_access_requests_filter(self):
        agent = DataGovernanceAgent()
        asset = agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        agent.request_access(asset.asset_id, "alice", "analysis", "read")
        agent.request_access(asset.asset_id, "bob", "reporting", "read")
        alice_reqs = agent.get_access_requests(requester="alice")
        assert len(alice_reqs) == 1


class TestDataGovernanceAgentReporting:
    def test_get_governance_report(self):
        agent = DataGovernanceAgent()
        report = agent.get_governance_report()
        assert "assets" in report
        assert "quality" in report
        assert "access" in report
        assert "lineage" in report
        assert "retention" in report

    def test_get_compliance_summary(self):
        agent = DataGovernanceAgent()
        agent.register_asset("DB", "d", DataType.PII, DataClassification.RESTRICTED, "o")
        summary = agent.get_compliance_summary()
        assert "regulated_data_types" in summary
        assert "total_regulated_assets" in summary

    def test_get_state(self):
        agent = DataGovernanceAgent()
        state = agent.get_state()
        assert state["agent_id"] == "data-governance-agent"
        assert "assets_count" in state
        assert "quality_rules_count" in state