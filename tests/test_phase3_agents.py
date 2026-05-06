"""
Tests for Phase 3 Agents (Sales, Finance, SysAdmin)
====================================================

Unit tests for the specialized agent implementations.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSalesAgent:
    """Test the SalesAgent class."""
    
    @pytest.fixture
    def temp_crm(self, tmp_path):
        """Create a temporary CRM directory."""
        crm = tmp_path / "crm"
        crm.mkdir()
        return crm
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="Generated proposal")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        mock = MagicMock()
        return mock
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        mock = MagicMock()
        return mock
    
    def test_sales_agent_initialization(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test sales agent initializes correctly."""
        from agentic_ai.agents.sales import SalesAgent
        from agentic_ai.agents.base import Permission
        
        agent = SalesAgent(
            agent_id="sales-001",
            name="TestSales",
            crm_path=str(temp_crm),
        )
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "sales-001"
        assert agent.agent_type == "sales"
        assert agent.permission == Permission.STANDARD
    
    def test_sales_has_correct_tools(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test sales agent has expected tools."""
        from agentic_ai.agents.sales import SalesAgent
        
        agent = SalesAgent(crm_path=str(temp_crm))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        assert "create_lead" in tool_names
        assert "qualify_lead" in tool_names
        assert "create_opportunity" in tool_names
        assert "generate_proposal" in tool_names
        assert "update_pipeline" in tool_names
    
    @pytest.mark.asyncio
    async def test_create_lead_tool(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test creating a lead."""
        from agentic_ai.agents.sales import SalesAgent
        
        agent = SalesAgent(crm_path=str(temp_crm))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_lead", lead_name="John Doe", company="Acme Corp", email="john@acme.com")
        
        assert "error" not in result
        assert result["status"] == "created"
        assert "lead_id" in result
        assert result["lead"]["company"] == "Acme Corp"
    
    @pytest.mark.asyncio
    async def test_qualify_lead_tool(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test qualifying a lead."""
        from agentic_ai.agents.sales import SalesAgent
        
        agent = SalesAgent(crm_path=str(temp_crm))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create lead first
        create_result = await agent.call_tool("create_lead", lead_name="Jane Smith", company="Globex", email="jane@globex.com")
        lead_id = create_result["lead_id"]
        
        # Qualify it
        result = await agent.call_tool("qualify_lead", lead_id=lead_id, budget="$50k", authority="CTO", need="Security", timeline="Q2")
        
        assert "error" not in result
        assert result["qualified"]
    
    @pytest.mark.asyncio
    async def test_create_opportunity_tool(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test creating an opportunity."""
        from agentic_ai.agents.sales import SalesAgent
        
        agent = SalesAgent(crm_path=str(temp_crm))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create and qualify lead
        create_result = await agent.call_tool("create_lead", lead_name="Bob Wilson", company="Initech", email="bob@initech.com")
        lead_id = create_result["lead_id"]
        await agent.call_tool("qualify_lead", lead_id=lead_id, budget="Yes", authority="Yes", need="Yes", timeline="Yes")
        
        # Create opportunity
        result = await agent.call_tool("create_opportunity", lead_id=lead_id, value=25000)
        
        assert "error" not in result
        assert result["status"] == "created"
        assert result["opportunity"]["value"] == 25000
    
    @pytest.mark.asyncio
    async def test_perform_task_create_lead(self, temp_crm, mock_inference, mock_state_store, mock_bus):
        """Test perform_task for create_lead."""
        from agentic_ai.agents.sales import SalesAgent
        
        agent = SalesAgent(crm_path=str(temp_crm))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("create_lead", {"name": "Test User", "company": "Test Co", "email": "test@test.com"})
        
        assert result["status"] == "created"


class TestFinanceAgent:
    """Test the FinanceAgent class."""
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="Financial analysis")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        return MagicMock()
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        return MagicMock()
    
    def test_finance_agent_initialization(self, mock_inference, mock_state_store, mock_bus):
        """Test finance agent initializes correctly."""
        from agentic_ai.agents.finance import FinanceAgent
        from agentic_ai.agents.base import Permission
        
        agent = FinanceAgent(agent_id="finance-001", name="TestFinance")
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "finance-001"
        assert agent.agent_type == "finance"
        assert agent.permission == Permission.STANDARD
    
    def test_finance_has_correct_tools(self, mock_inference, mock_state_store, mock_bus):
        """Test finance agent has expected tools."""
        from agentic_ai.agents.finance import FinanceAgent
        
        agent = FinanceAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        assert "record_transaction" in tool_names
        assert "create_budget" in tool_names
        assert "analyze_spending" in tool_names
        assert "create_invoice" in tool_names
        assert "generate_report" in tool_names
    
    @pytest.mark.asyncio
    async def test_record_transaction_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test recording a transaction."""
        from agentic_ai.agents.finance import FinanceAgent
        
        agent = FinanceAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("record_transaction", type="income", amount=1000.0, category="Sales", description="Product sale")
        
        assert "error" not in result
        assert result["status"] == "recorded"
        assert "transaction_id" in result
    
    @pytest.mark.asyncio
    async def test_create_budget_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test creating a budget."""
        from agentic_ai.agents.finance import FinanceAgent
        from agentic_ai.agents.base import Permission
        
        agent = FinanceAgent(permission=Permission.ELEVATED)
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_budget", budget_name="Q1 Budget", categories={"Marketing": 5000, "Development": 10000})
        
        assert "error" not in result
        assert result["status"] == "created"
        assert result["budget"]["total"] == 15000
    
    @pytest.mark.asyncio
    async def test_analyze_spending_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test analyzing spending."""
        from agentic_ai.agents.finance import FinanceAgent
        
        agent = FinanceAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Record some transactions first
        await agent.call_tool("record_transaction", type="income", amount=5000, category="Sales", description="Revenue")
        await agent.call_tool("record_transaction", type="expense", amount=2000, category="Marketing", description="Ads")
        await agent.call_tool("record_transaction", type="expense", amount=1000, category="Development", description="Tools")
        
        result = await agent.call_tool("analyze_spending")
        
        assert "error" not in result
        assert result["total_income"] == 5000
        assert result["total_expense"] == 3000
        assert result["net"] == 2000
    
    @pytest.mark.asyncio
    async def test_create_invoice_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test creating an invoice."""
        from agentic_ai.agents.finance import FinanceAgent
        
        agent = FinanceAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_invoice", client="Acme Corp", items=[{"name": "Consulting", "quantity": 10, "price": 150}])
        
        assert "error" not in result
        assert result["status"] == "created"
        assert result["invoice"]["subtotal"] == 1500


class TestSysAdminAgent:
    """Test the SysAdminAgent class."""
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="System analysis")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        return MagicMock()
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        return MagicMock()
    
    def test_sysadmin_agent_initialization(self, mock_inference, mock_state_store, mock_bus):
        """Test sysadmin agent initializes correctly."""
        from agentic_ai.agents.sysadmin import SysAdminAgent
        from agentic_ai.agents.base import Permission
        
        agent = SysAdminAgent(agent_id="sys-001", name="TestSysAdmin")
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "sys-001"
        assert agent.agent_type == "sysadmin"
        assert agent.permission == Permission.ELEVATED
    
    def test_sysadmin_has_correct_tools(self, mock_inference, mock_state_store, mock_bus):
        """Test sysadmin agent has expected tools."""
        from agentic_ai.agents.sysadmin import SysAdminAgent
        
        agent = SysAdminAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        assert "check_system" in tool_names
        assert "analyze_logs" in tool_names
        assert "create_incident" in tool_names
        assert "run_command" in tool_names
        assert "check_service" in tool_names
    
    @pytest.mark.asyncio
    async def test_create_incident_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test creating an incident."""
        from agentic_ai.agents.sysadmin import SysAdminAgent
        
        agent = SysAdminAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_incident", title="Server Down", description="Web server not responding", severity="critical", affected_systems=["web-01"])
        
        assert "error" not in result
        assert result["status"] == "created"
        assert result["incident"]["title"] == "Server Down"
    
    @pytest.mark.asyncio
    async def test_check_system_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test system health check."""
        from agentic_ai.agents.sysadmin import SysAdminAgent
        
        agent = SysAdminAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("check_system", checks=["memory"])
        
        # Result may have error if not on Linux, but shouldn't crash
        assert "error" in result or "memory" in result
    
    @pytest.mark.asyncio
    async def test_run_command_tool(self, mock_inference, mock_state_store, mock_bus):
        """Test running a command."""
        from agentic_ai.agents.sysadmin import SysAdminAgent
        
        agent = SysAdminAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("run_command", command="echo hello", timeout=5)
        
        assert "error" not in result
        assert result["success"]
        assert "hello" in result["stdout"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])