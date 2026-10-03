"""Tests for the upgraded SalesAgent (CRM + pricing + proposals + forecasting).

Covers:
- Legacy compatibility: tool names, result shapes, loose BANT strings,
  payload-as-second-positional perform_task.
- Qualification scoring (BANT + ICP bonus, tiers A-D).
- Productized price book, quote math, discounts, opp binding.
- Proposal generation (measured proof points, quote-backed investment,
  opportunity_id alias).
- Pipeline report + forecast math, stage validation.
- Outreach drafts: draft-only, never sends.
- Persistence: real StateStore round trip, monotonic ids across restarts,
  in-memory mode without a store, mock-store tolerance.
"""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentic_ai.agents.base import Permission  # noqa: E402
from agentic_ai.agents.sales import (  # noqa: E402
    PRICING,
    VALID_STAGES,
    LeadStatus,
    SalesAgent,
)
from agentic_ai.infrastructure.state import StateStore  # noqa: E402

LEGACY_TOOLS = ["create_lead", "qualify_lead", "create_opportunity",
                "generate_proposal", "update_pipeline"]
NEW_TOOLS = ["price_book", "quote", "pipeline_report", "forecast",
             "draft_outreach", "get_lead"]


def make_agent(agent_id: str = "sales-test-1", state_store=None) -> SalesAgent:
    agent = SalesAgent(agent_id=agent_id, name="SalesAgent-test",
                       state_store=state_store)
    return agent


class TestInitialization:
    def test_defaults(self):
        agent = make_agent()
        assert agent.agent_type == "sales"
        assert agent.permission == Permission.STANDARD
        assert agent.state_store is None
        assert set(LEGACY_TOOLS + NEW_TOOLS).issubset(set(agent._tools.keys()))

    def test_mock_store_tolerated(self):
        agent = SalesAgent(agent_id="sales-mock-1", state_store=MagicMock())
        result = agent.create_lead(lead_name="John Doe", company="Acme Corp",
                                   email="john@acme.com")
        assert result["status"] == "created"


class TestLegacyCrm:
    def test_create_lead_result_shape(self):
        agent = make_agent()
        result = agent.create_lead(lead_name="John Doe", company="Acme Corp",
                                   email="john@acme.com")
        assert "error" not in result
        assert result["status"] == "created"
        assert "lead_id" in result
        assert result["lead"]["company"] == "Acme Corp"

    def test_create_lead_email_dedupe(self):
        agent = make_agent()
        first = agent.create_lead(name="Dana", email="dana@corp.com")
        second = agent.create_lead(name="Dana Again", email="dana@corp.com")
        assert first["status"] == "created"
        assert second["status"] == "exists"
        assert second["lead_id"] == first["lead_id"]

    def test_get_lead_by_id_and_email(self):
        agent = make_agent()
        created = agent.create_lead(name="Rory", company="Initech",
                                    email="rory@initech.com")
        by_id = agent.get_lead(lead_id=created["lead_id"])
        by_email = agent.get_lead(email="rory@initech.com")
        assert by_id["lead"]["name"] == "Rory"
        assert by_email["lead"]["lead_id"] == created["lead_id"]
        assert "error" in agent.get_lead(lead_id="LEAD-9999")

    def test_unknown_lead_error(self):
        agent = make_agent()
        result = agent.qualify_lead(lead_id="LEAD-9999", budget="$50k")
        assert "error" in result

    def test_create_opportunity_result_shape(self):
        agent = make_agent()
        lead = agent.create_lead(lead_name="Bob Wilson", company="Initech",
                                 email="bob@initech.com")
        result = agent.create_opportunity(lead_id=lead["lead_id"], value=25000)
        assert "error" not in result
        assert result["status"] == "created"
        assert result["opportunity"]["value"] == 25000
        assert result["opportunity"]["probability"] == pytest.approx(0.10)


class TestQualification:
    def test_bant_scoring_with_loose_strings(self):
        agent = make_agent()
        lead = agent.create_lead(name="Jane Smith", company="Globex",
                                 email="jane@globex.com", industry="finance")
        result = agent.qualify_lead(lead_id=lead["lead_id"], budget="$50k",
                                    authority="CTO", need="Security",
                                    timeline="Q2")
        assert result["qualified"] is True
        assert result["score"] >= 80.0
        assert result["tier"] == "A"
        assert result["breakdown"]["need"] == 25.0
        stored = agent.get_lead(lead_id=lead["lead_id"])
        assert stored["lead"]["status"] == LeadStatus.QUALIFIED
        assert stored["lead"]["tier"] == "A"

    def test_low_signal_lead_scores_low(self):
        agent = make_agent()
        lead = agent.create_lead(name="Ann", email="ann@shop.com")
        result = agent.qualify_lead(lead_id=lead["lead_id"], budget="",
                                    authority="", need="", timeline="")
        # empty BANT and no ICP signals -> score 0, tier D
        assert result["score"] == 0.0
        assert result["tier"] == "D"
        assert result["qualified"] is True  # recorded, but ranked D

    def test_explicit_score_override_wins(self):
        agent = make_agent()
        lead = agent.create_lead(name="Ori", email="ori@corp.com")
        result = agent.qualify_lead(lead_id=lead["lead_id"], score=70.0)
        assert result["score"] >= 70.0


class TestPricing:
    def test_price_book_has_services(self):
        agent = make_agent()
        assert set(PRICING.keys()) >= {"soc_monitoring", "compliance",
                                       "vciso", "platform_pilot"}
        result = agent.price_book()
        assert result["status"] == "ok"
        assert result["pricing"]["soc_monitoring"]["tiers"]["24x7"] \
            ["per_endpoint_monthly"] > 0

    def test_soc_quote_math(self):
        agent = make_agent()
        result = agent.quote(service="soc_monitoring",
                             tier="business_hours", endpoints=100, months=12)
        assert result["monthly_recurring"] == pytest.approx(2700.0)
        assert result["year1_total"] == pytest.approx(32400.0)
        assert len(result["lines"]) == 2
        assert result["lines"][0]["extended"] == pytest.approx(18000.0)
        assert result["lines"][1]["extended"] == pytest.approx(14400.0)

    def test_compliance_package_quote(self):
        agent = make_agent()
        result = agent.quote(service="compliance", package="stig_pipeline")
        assert result["monthly_recurring"] == pytest.approx(2500.0)
        assert result["one_time"] == pytest.approx(9500.0)
        assert result["year1_total"] == pytest.approx(39500.0)
        assert len(result["lines"]) == 2

    def test_discount_math(self):
        agent = make_agent()
        gross = agent.quote(service="soc_monitoring", tier="business_hours",
                            endpoints=100, months=12)
        discounted = agent.quote(service="soc_monitoring",
                                 tier="business_hours", endpoints=100,
                                 months=12, discount_pct=10.0)
        assert discounted["discount_amount"] == pytest.approx(
            gross["gross_total"] * 0.10)
        assert discounted["net_total_term"] == pytest.approx(
            gross["gross_total"] * 0.90)

    def test_vciso_and_pilot_quotes(self):
        agent = make_agent()
        vciso = agent.quote(service="vciso", tier="with_ir")
        assert vciso["monthly_recurring"] == pytest.approx(6500.0)
        pilot = agent.quote(service="platform_pilot")
        assert pilot["one_time"] == pytest.approx(15000.0)
        assert pilot["year1_total"] == pytest.approx(15000.0)

    def test_unknown_service_and_tier(self):
        agent = make_agent()
        assert "error" in agent.quote(service="magic_unicorn")
        assert "error" in agent.quote(service="soc_monitoring", tier="gold")
        assert "error" in agent.quote(service="compliance", package="iso27001")

    def test_quote_binds_to_opportunity(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="ACME deployment", value=50000.0)
        result = agent.quote(service="compliance", package="soc2_prep",
                             opp_id=opp["opp_id"])
        assert "quote_id" in result
        fetched = agent._find_opp(opp["opp_id"])
        assert fetched.quote_id == result["quote_id"]
        assert fetched.quote_snapshot["one_time"] == 12000.0


class TestProposals:
    def test_proposal_without_quote(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="Globex SOC support", value=80000.0)
        result = agent.generate_proposal(opp_id=opp["opp_id"])
        assert result["status"] == "generated"
        assert result["title"] == "Globex SOC support"
        proposal = result["proposal"]
        assert "## Investment" in proposal["markdown"]
        assert "Estimated engagement value" in proposal["markdown"]
        assert "Median alert decision" in proposal["markdown"]
        assert "super intelligence" in proposal["markdown"]  # honest scope note
        assert "Executive summary" in proposal["sections"]

    def test_proposal_with_bound_quote(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="ACME", value=40000.0)
        q = agent.quote(service="soc_monitoring", tier="24x7", endpoints=50,
                        opp_id=opp["opp_id"])
        result = agent.generate_proposal(opp_id=opp["opp_id"])
        md = result["proposal"]["markdown"]
        assert f"${q['monthly_recurring']:,.0f}" in md
        assert result["proposal"]["quote_id"] == q["quote_id"]

    def test_opportunity_id_alias(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="Alias test")
        result = agent.generate_proposal(opportunity_id=opp["opp_id"])
        assert result["status"] == "generated"
        assert "error" in agent.generate_proposal(opp_id="OPP-9999")


class TestPipelineForecast:
    def _seed(self, agent):
        agent.create_opportunity(title="one", value=50000.0)  # prospecting
        two = agent.create_opportunity(title="two", value=100000.0)
        agent.update_pipeline(opp_id=two["opp_id"], stage="proposal")
        three = agent.create_opportunity(title="three", value=20000.0)
        agent.update_pipeline(opp_id=three["opp_id"], stage="won")
        four = agent.create_opportunity(title="four", value=30000.0)
        agent.update_pipeline(opp_id=four["opp_id"], stage="lost")
        return {"one": "OPP-0001", "two": "OPP-0002",
                "three": "OPP-0003", "four": "OPP-0004"}

    def test_stage_validation(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="x")
        ok = agent.update_pipeline(opp_id=opp["opp_id"], stage="negotiation")
        assert ok["probability"] == pytest.approx(0.75)
        assert ok["stage"] == "negotiation"
        assert "error" in agent.update_pipeline(opp_id=opp["opp_id"],
                                                stage="limbo")
        assert "valid_stages" in agent.update_pipeline(
            opp_id=opp["opp_id"], stage="limbo")

    def test_stage_alias_normalization(self):
        agent = make_agent()
        opp = agent.create_opportunity(title="x", stage="qualification")
        assert opp["opportunity"]["stage"] == "qualified"
        assert agent.opportunities[0].probability == pytest.approx(0.30)

    def test_pipeline_report_math(self):
        agent = make_agent()
        agent.create_lead(name="Dana", email="dana@corp.com")
        agent.create_lead(name="Ed", email="ed@corp.com")
        agent.qualify_lead(lead_id="LEAD-0001", budget="$100k",
                           authority="CISO", need="compliance", timeline="30 days")
        self._seed(agent)
        agent.quote(service="soc_monitoring", tier="business_hours",
                    endpoints=100)
        agent.quote(service="compliance", package="stig_pipeline")
        report = agent.pipeline_report()
        assert report["stage_counts"]["proposal"] == 1
        assert report["stage_counts"]["won"] == 1
        assert report["total_pipeline"] == pytest.approx(200000.0)
        assert report["open_pipeline"] == pytest.approx(150000.0)
        assert report["weighted_pipeline"] == pytest.approx(75000.0)
        assert report["won_value"] == pytest.approx(20000.0)
        assert report["leads"]["total"] == 2
        assert report["leads"]["qualified_pct"] == 50.0
        assert report["quotes"]["total_mrr"] == pytest.approx(5200.0)
        assert report["quotes"]["total_year1"] == pytest.approx(71900.0)
        assert report["top_open"][0]["opp_id"] == "OPP-0002"

    def test_forecast_math(self):
        agent = make_agent()
        ids = self._seed(agent)
        agent.opportunities[1].close_date = datetime(2026, 11, 15)
        result = agent.forecast()
        by_period = {row["quarter"]: row for row in result["by_period"]}
        assert by_period["2026Q4"]["weighted"] == pytest.approx(50000.0)
        assert by_period["unscheduled"]["weighted"] == pytest.approx(5000.0)
        assert result["won_total"] == pytest.approx(20000.0)
        assert result["weighted_total"] == pytest.approx(55000.0)


class TestOutreach:
    def test_draft_only_and_personalized(self):
        agent = make_agent()
        lead = agent.create_lead(name="Pat", company="Northwind",
                                 email="pat@nw.com",
                                 compliance_drivers=["SOC 2"])
        touch1 = agent.draft_outreach(lead_id=lead["lead_id"], touch=1)
        touch2 = agent.draft_outreach(lead_id=lead["lead_id"], touch=2)
        touch3 = agent.draft_outreach(lead_id=lead["lead_id"], touch=3)
        for draft in (touch1, touch2, touch3):
            assert draft["requires_owner_send"] is True
            assert "error" not in draft
        assert "Northwind" in touch1["subject"]
        assert "SOC 2" in touch1["body"]
        assert "Median alert decision" in touch2["body"]
        assert "briefing" in touch3["subject"].lower()
        stored = agent.get_lead(email="pat@nw.com")
        assert stored["lead"]["touch_count"] == 3
        assert stored["lead"]["status"] in (LeadStatus.CONTACTED, LeadStatus.NEW)

    def test_touch_out_of_range_clamps(self):
        agent = make_agent()
        lead = agent.create_lead(name="Sol", email="sol@corp.com")
        result = agent.draft_outreach(lead_id=lead["lead_id"], touch=99)
        assert result["touch"] == 3

    def test_unknown_lead(self):
        agent = make_agent()
        assert "error" in agent.draft_outreach(lead_id="LEAD-9999")

    def test_agent_never_sends(self):
        """The agent exposes no send-email style tool; drafts require the owner."""
        agent = make_agent("sales-nosend-1")
        assert "send_email" not in agent._tools
        lead = agent.create_lead(name="NoSend", email="nsend@x.com",
                                 company="NoSend Corp")
        draft = agent.draft_outreach(lead_id=lead["lead_id"])
        assert draft["requires_owner_send"] is True



class TestPersistence:
    def test_state_store_round_trip(self, tmp_path):
        store_a = StateStore(db_path=str(tmp_path / "state.sqlite"))
        agent_a = make_agent("sales-persist-1", state_store=store_a)
        agent_a.create_lead(name="Dana", company="ACME", email="dana@acme.com")
        agent_a.create_opportunity(title="ACME rollout", value=50000.0)

        store_b = StateStore(db_path=str(tmp_path / "state.sqlite"))
        agent_b = make_agent("sales-persist-1", state_store=store_b)
        found = agent_b.get_lead(email="dana@acme.com")
        assert found["lead"]["company"] == "ACME"
        # id continuity across restart
        nxt = agent_b.create_lead(name="Eli", email="eli@acme.com")
        assert nxt["lead_id"] == "LEAD-0002"

    def test_monotonic_ids(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "m.sqlite"))
        agent = make_agent("sales-id-1", state_store=store)
        first = agent.create_lead(name="A", email="a@x.com")
        second = agent.create_lead(name="B", email="b@x.com")
        assert (first["lead_id"], second["lead_id"]) == ("LEAD-0001", "LEAD-0002")

    def test_in_memory_mode_is_fine(self, tmp_path):
        agent = make_agent("sales-bare-1")
        agent.create_lead(name="NoStore", email="ns@x.com")
        opp = agent.create_opportunity(title="no store")
        assert agent.get_lead(email="ns@x.com")["lead"]["name"] == "NoStore"
        assert agent._find_opp(opp["opp_id"]) is not None

    def test_corrupt_state_ignored(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "c.sqlite"))
        store.save_agent_state("sales-corrupt-1", "sales",
                               "not-a-dict-state")
        agent = make_agent("sales-corrupt-1", state_store=store)
        result = agent.create_lead(name="After", email="after@x.com")
        assert result["status"] == "created"
        assert result["lead_id"] == "LEAD-0001"


class TestDispatch:
    @pytest.mark.asyncio
    async def test_perform_task_payload_positional(self):
        agent = make_agent("sales-dispatch-1")
        result = await agent.perform_task(
            "create_lead",
            {"name": "Test User", "company": "Test Co", "email": "test@test.com"})
        assert result["status"] == "created"
        assert result["lead"]["name"] == "Test User"

    @pytest.mark.asyncio
    async def test_perform_task_unknown(self):
        agent = make_agent("sales-dispatch-2")
        result = await agent.perform_task("quantum_flip")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_perform_task_kwarg_form(self):
        agent = make_agent("sales-dispatch-3")
        result = await agent.perform_task("qualify_lead", lead_id="LEAD-0001")
        assert "error" in result  # lead does not exist -> handled, not raised