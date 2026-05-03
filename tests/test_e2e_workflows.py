"""
End-to-End Workflow Tests - Phase 5
====================================

Integration tests that verify complete workflows across multiple agents.
These tests simulate real-world scenarios where agents collaborate.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio

sys.path.insert(0, str(Path(__file__).parent.parent))


def create_mock_environment(tmp_path):
    """Helper to create mocked environment."""
    redis_instance = MagicMock()
    redis_instance.hget.return_value = None  # Cache miss, falls back to SQLite
    
    httpx_instance = MagicMock()
    mock_response = MagicMock()
    mock_response.json.return_value = {"result": "success"}
    httpx_instance.post.return_value = mock_response
    
    return {
        'redis': redis_instance,
        'httpx': httpx_instance,
        'db_path': str(tmp_path / "test.db"),
    }


class TestCodeDevelopmentWorkflow:
    """E2E test: Feature request → Implementation → Testing → Review"""
    
    @pytest.mark.asyncio
    async def test_feature_development_workflow(self, tmp_path):
        """Test complete feature development: Lead → Developer → QA → Lead"""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.developer import DeveloperAgent
        from agentic_ai.agents.qa import QAAgent
        from agentic_ai.infrastructure.state import StateStore
        
        env = create_mock_environment(tmp_path)
        
        with patch('redis.Redis', return_value=env['redis']), \
             patch('httpx.Client', return_value=env['httpx']):
            
            # Initialize agents
            state_store = StateStore(db_path=env['db_path'])
            
            lead = LeadAgent(agent_id="lead-001", name="LeadAgent")
            lead.state_store = state_store
            
            developer = DeveloperAgent(agent_id="dev-001", name="DeveloperAgent")
            developer.state_store = state_store
            
            qa = QAAgent(agent_id="qa-001", name="QAAgent")
            qa.state_store = state_store
            
            # Step 1: Lead creates workflow for new feature using tool
            workflow_result = await lead.call_tool(
                "create_workflow",
                workflow_name="feature_payment_gateway",
                tasks=[
                    {"type": "implement", "description": "Stripe integration"},
                    {"type": "write_tests", "description": "Payment module tests"},
                    {"type": "run_tests", "description": "Execute payment tests"},
                    {"type": "review", "description": "Code review"},
                ]
            )
            
            assert workflow_result is not None
            assert "workflow_id" in workflow_result
            assert len(workflow_result.get("task_ids", [])) == 4
            
            # Step 2: Developer implements feature
            impl_result = await developer.perform_task(
                "implement",
                {"feature": "Stripe integration", "description": "Payment module"}
            )
            
            assert impl_result is not None
            
            # Step 3: Developer writes tests
            test_result = await developer.perform_task(
                "write_tests",
                {"module": "payment", "coverage_target": 80}
            )
            
            assert test_result is not None
            
            # Step 4: QA runs tests
            qa_result = await qa.perform_task(
                "run_tests",
                {"suite": "payment_tests"}
            )
            
            assert qa_result is not None
            
            # Step 5: Developer reviews code
            review_result = await developer.perform_task(
                "review",
                {"code": "payment module code", "path": "payment/"}
            )
            
            assert review_result is not None
    
    @pytest.mark.asyncio
    async def test_bug_fix_workflow(self, tmp_path):
        """Test bug fix: Issue reported → Developer fixes → QA validates"""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.developer import DeveloperAgent
        from agentic_ai.agents.qa import QAAgent
        from agentic_ai.infrastructure.state import StateStore
        
        env = create_mock_environment(tmp_path)
        
        with patch('redis.Redis', return_value=env['redis']), \
             patch('httpx.Client', return_value=env['httpx']):
            
            state_store = StateStore(db_path=env['db_path'])
            
            lead = LeadAgent(agent_id="lead-001", name="LeadAgent")
            lead.state_store = state_store
            
            developer = DeveloperAgent(agent_id="dev-001", name="DeveloperAgent")
            developer.state_store = state_store
            
            qa = QAAgent(agent_id="qa-001", name="QAAgent")
            qa.state_store = state_store
            
            # Create bug fix workflow
            workflow_result = await lead.call_tool(
                "create_workflow",
                workflow_name="bugfix_login_timeout",
                tasks=[
                    {"type": "fix_bug", "description": "Fix LOGIN-42"},
                    {"type": "validate", "description": "Validate fix"},
                ]
            )
            
            assert workflow_result is not None
            assert "workflow_id" in workflow_result
            assert len(workflow_result.get("task_ids", [])) == 2
            
            # Developer fixes bug
            fix_result = await developer.perform_task(
                "fix_bug",
                {"bug_id": "LOGIN-42", "description": "Session timeout too short"}
            )
            
            assert fix_result is not None
            
            # QA validates fix
            validation_result = await qa.perform_task(
                "validate",
                {"artifact": "login_fix"}
            )
            
            assert validation_result is not None


class TestBusinessOperationsWorkflow:
    """E2E test: Sales opportunity → Finance approval → System provisioning"""
    
    @pytest.mark.asyncio
    async def test_customer_onboarding_workflow(self, tmp_path):
        """Test customer onboarding: Sales → Finance → SysAdmin"""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.sales import SalesAgent
        from agentic_ai.agents.finance import FinanceAgent
        from agentic_ai.agents.sysadmin import SysAdminAgent
        from agentic_ai.infrastructure.state import StateStore
        
        env = create_mock_environment(tmp_path)
        
        with patch('redis.Redis', return_value=env['redis']), \
             patch('httpx.Client', return_value=env['httpx']):
            
            state_store = StateStore(db_path=env['db_path'])
            
            lead = LeadAgent(agent_id="lead-001", name="LeadAgent")
            lead.state_store = state_store
            
            sales = SalesAgent(agent_id="sales-001", name="SalesAgent")
            sales.state_store = state_store
            
            finance = FinanceAgent(agent_id="finance-001", name="FinanceAgent")
            finance.state_store = state_store
            
            sysadmin = SysAdminAgent(agent_id="sysadmin-001", name="SysAdminAgent")
            sysadmin.state_store = state_store
            
            # Create onboarding workflow
            workflow_result = await lead.call_tool(
                "create_workflow",
                workflow_name="onboard_acme_corp",
                tasks=[
                    {"type": "create_opportunity", "description": "Create ACME opportunity"},
                    {"type": "generate_proposal", "description": "Generate proposal"},
                    {"type": "create_invoice", "description": "Create invoice"},
                    {"type": "check_system", "description": "Check prod system"},
                ]
            )
            
            assert workflow_result is not None
            assert "workflow_id" in workflow_result
            
            # Sales creates opportunity
            opp_result = await sales.perform_task(
                "create_opportunity",
                {"lead_id": "acme_lead", "value": 50000}
            )
            
            assert opp_result is not None
            
            # Sales generates proposal
            proposal_result = await sales.perform_task(
                "generate_proposal",
                {"opportunity_id": "acme_opp"}
            )
            
            assert proposal_result is not None
            
            # Finance creates invoice
            invoice_result = await finance.perform_task(
                "create_invoice",
                {"client": "ACME Corp", "items": [{"description": "Services", "quantity": 1, "price": 50000}]}
            )
            
            assert invoice_result is not None
            
            # SysAdmin checks system health
            health_result = await sysadmin.perform_task(
                "check_system",
                {"host": "prod-01"}
            )
            
            assert health_result is not None


class TestIncidentResponseWorkflow:
    """E2E test: System alert → SysAdmin investigates → Finance tracks cost"""
    
    @pytest.mark.asyncio
    async def test_incident_response_workflow(self, tmp_path):
        """Test incident response: Detection → Investigation → Resolution → Cost tracking"""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.sysadmin import SysAdminAgent
        from agentic_ai.agents.finance import FinanceAgent
        from agentic_ai.infrastructure.state import StateStore
        
        env = create_mock_environment(tmp_path)
        
        with patch('redis.Redis', return_value=env['redis']), \
             patch('httpx.Client', return_value=env['httpx']):
            
            state_store = StateStore(db_path=env['db_path'])
            
            lead = LeadAgent(agent_id="lead-001", name="LeadAgent")
            lead.state_store = state_store
            
            sysadmin = SysAdminAgent(agent_id="sysadmin-001", name="SysAdminAgent")
            sysadmin.state_store = state_store
            
            finance = FinanceAgent(agent_id="finance-001", name="FinanceAgent")
            finance.state_store = state_store
            
            # Create incident workflow
            workflow_result = await lead.call_tool(
                "create_workflow",
                workflow_name="incident_db_outage",
                tasks=[
                    {"type": "create_incident", "description": "P1 database outage"},
                    {"type": "analyze_logs", "description": "Analyze DB logs"},
                    {"type": "run_command", "description": "Restart PostgreSQL"},
                    {"type": "record_transaction", "description": "Track incident cost"},
                ]
            )
            
            assert workflow_result is not None
            assert "workflow_id" in workflow_result
            
            # SysAdmin creates incident
            incident_result = await sysadmin.perform_task(
                "create_incident",
                {"title": "Database Outage", "severity": "critical", "description": "Database unresponsive"}
            )
            
            assert incident_result is not None
            
            # SysAdmin analyzes logs
            log_result = await sysadmin.perform_task(
                "analyze_logs",
                {"log_file": "/var/log/syslog", "lines": 100}
            )
            
            assert log_result is not None
            
            # Finance tracks incident cost
            cost_result = await finance.perform_task(
                "record_transaction",
                {"type": "expense", "amount": 500, "category": "operations", "description": "Incident response cost"}
            )
            
            assert cost_result is not None


class TestMultiAgentCollaboration:
    """Test agents collaborating on complex tasks"""
    
    @pytest.mark.asyncio
    async def test_cross_agent_task_routing(self, tmp_path):
        """Test Lead Agent correctly routes tasks to appropriate agents"""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.infrastructure.state import StateStore
        
        env = create_mock_environment(tmp_path)
        
        with patch('redis.Redis', return_value=env['redis']), \
             patch('httpx.Client', return_value=env['httpx']):
            
            state_store = StateStore(db_path=env['db_path'])
            
            lead = LeadAgent(agent_id="lead-001", name="LeadAgent")
            lead.state_store = state_store
            
            # Test task type to agent type mapping
            task_mappings = [
                ("implement", "developer"),
                ("review", "developer"),
                ("fix_bug", "developer"),
                ("write_tests", "developer"),
                ("generate_tests", "qa"),
                ("run_tests", "qa"),
                ("analyze_coverage", "qa"),
                ("find_bugs", "qa"),
                ("create_lead", "sales"),
                ("qualify_lead", "sales"),
                ("create_opportunity", "sales"),
                ("generate_proposal", "sales"),
                ("record_transaction", "finance"),
                ("create_budget", "finance"),
                ("analyze_spending", "finance"),
                ("generate_report", "finance"),
                ("check_system", "sysadmin"),
                ("analyze_logs", "sysadmin"),
                ("create_incident", "sysadmin"),
                ("run_command", "sysadmin"),
            ]
            
            for task_type, expected_agent in task_mappings:
                # Create task and verify routing
                result = await lead.call_tool(
                    "create_task",
                    task_type=task_type,
                    description=f"Test {task_type}"
                )
                
                assert result is not None
                assert "task_id" in result
                assert result["task"]["agent_type"] == expected_agent, \
                    f"Task {task_type} should route to {expected_agent}, got {result['task']['agent_type']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
