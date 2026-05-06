"""
Tests for Lead Agent (Orchestration)
====================================

Unit tests for the lead agent implementation.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLeadAgent:
    """Test the LeadAgent class."""
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="Analysis result")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        return MagicMock()
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        return MagicMock()
    
    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project directory."""
        project = tmp_path / "test_project"
        project.mkdir()
        return project
    
    def test_lead_agent_initialization(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test lead agent initializes correctly."""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.base import Permission
        
        agent = LeadAgent(
            agent_id="lead-001",
            name="TestLead",
            project_path=str(temp_project),
        )
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "lead-001"
        assert agent.agent_type == "lead"
        assert agent.permission == Permission.ELEVATED
    
    def test_lead_has_correct_tools(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test lead agent has expected tools."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        assert "create_workflow" in tool_names
        assert "create_task" in tool_names
        assert "route_task" in tool_names
        assert "execute_workflow" in tool_names
        assert "get_status" in tool_names
        assert "delegate_task" in tool_names
        assert "analyze_request" in tool_names
    
    def test_routing_rules(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test task routing rules."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Developer tasks
        assert agent._routing_rules.get("implement") == "developer"
        assert agent._routing_rules.get("review") == "developer"
        assert agent._routing_rules.get("fix_bug") == "developer"
        
        # QA tasks
        assert agent._routing_rules.get("generate_tests") == "qa"
        assert agent._routing_rules.get("run_tests") == "qa"
        assert agent._routing_rules.get("find_bugs") == "qa"
        
        # Sales tasks
        assert agent._routing_rules.get("create_lead") == "sales"
        assert agent._routing_rules.get("generate_proposal") == "sales"
        
        # Finance tasks
        assert agent._routing_rules.get("record_transaction") == "finance"
        assert agent._routing_rules.get("generate_report") == "finance"
        
        # SysAdmin tasks
        assert agent._routing_rules.get("check_system") == "sysadmin"
        assert agent._routing_rules.get("analyze_logs") == "sysadmin"
    
    @pytest.mark.asyncio
    async def test_create_task_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test creating a task."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_task", task_type="implement", description="Create hello world")
        
        assert "error" not in result
        assert result["status"] == "created"
        assert "task_id" in result
        assert result["task"]["type"] == "implement"
        assert result["task"]["agent_type"] == "developer"  # Auto-routed
    
    @pytest.mark.asyncio
    async def test_create_task_with_priority(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test creating a task with priority."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("create_task", task_type="check_system", description="Check server health", priority="high")
        
        assert "error" not in result
        assert result["task"]["priority"] == "high"
        assert result["task"]["agent_type"] == "sysadmin"
    
    @pytest.mark.asyncio
    async def test_create_workflow_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test creating a workflow."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tasks = [
            {"type": "implement", "description": "Create feature"},
            {"type": "generate_tests", "description": "Write tests", "dependencies": []},
        ]
        
        result = await agent.call_tool("create_workflow", workflow_name="Feature Workflow", tasks=tasks)
        
        assert "error" not in result
        assert result["status"] == "created"
        assert "workflow_id" in result
        assert len(result["task_ids"]) == 2
    
    @pytest.mark.asyncio
    async def test_get_status_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test getting status."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create some tasks first
        await agent.call_tool("create_task", task_type="implement", description="Task 1")
        await agent.call_tool("create_task", task_type="generate_tests", description="Task 2")
        
        result = await agent.call_tool("get_status")
        
        assert "error" not in result
        assert result["total_tasks"] == 2
        assert "tasks_by_status" in result
        assert "registered_agents" in result
    
    @pytest.mark.asyncio
    async def test_agent_registration(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test registering agents."""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.developer import DeveloperAgent
        
        lead = LeadAgent(project_path=str(temp_project))
        lead.inference = mock_inference
        lead.state_store = mock_state_store
        lead.bus = mock_bus
        
        # Create and register a developer agent
        dev = DeveloperAgent(agent_id="dev-001", project_path=str(temp_project))
        dev.inference = mock_inference
        dev.state_store = mock_state_store
        dev.bus = mock_bus
        
        agent_id = lead.register_agent(dev)
        
        assert agent_id == "dev-001"
        assert "dev-001" in lead._agents
        assert "dev-001" in lead._agent_pools["developer"]
    
    @pytest.mark.asyncio
    async def test_agent_creation(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test creating agents dynamically."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create different agent types
        dev = agent._create_agent("developer")
        assert dev is not None
        assert dev.agent_type == "developer"
        assert dev.agent_id in agent._agents
        
        qa = agent._create_agent("qa")
        assert qa is not None
        assert qa.agent_type == "qa"
        
        sales = agent._create_agent("sales")
        assert sales is not None
        assert sales.agent_type == "sales"
        
        finance = agent._create_agent("finance")
        assert finance is not None
        assert finance.agent_type == "finance"
        
        sysadmin = agent._create_agent("sysadmin")
        assert sysadmin is not None
        assert sysadmin.agent_type == "sysadmin"
    
    @pytest.mark.asyncio
    async def test_route_task_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test routing a task to an agent."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create a task
        create_result = await agent.call_tool("create_task", task_type="implement", description="Test task")
        task_id = create_result["task_id"]
        
        # Route it
        route_result = await agent.call_tool("route_task", task_id=task_id)
        
        assert "error" not in route_result
        assert route_result["status"] == "routed"
        assert route_result["task_id"] == task_id
        assert "agent_id" in route_result
    
    @pytest.mark.asyncio
    async def test_delegate_task_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test delegating a task to a specific agent."""
        from agentic_ai.agents.lead import LeadAgent
        from agentic_ai.agents.developer import DeveloperAgent
        
        lead = LeadAgent(project_path=str(temp_project))
        lead.inference = mock_inference
        lead.state_store = mock_state_store
        lead.bus = mock_bus
        
        # Create and register a developer agent
        dev = DeveloperAgent(agent_id="dev-001", project_path=str(temp_project))
        dev.inference = mock_inference
        dev.state_store = mock_state_store
        dev.bus = mock_bus
        lead.register_agent(dev)
        
        # Create a task
        create_result = await lead.call_tool("create_task", task_type="review", description="Review code", payload={"path": "main.py"})
        task_id = create_result["task_id"]
        
        # Delegate to specific agent
        result = await lead.call_tool("delegate_task", task_id=task_id, agent_id="dev-001")
        
        assert "error" not in result
        assert result["status"] == "completed"
    
    @pytest.mark.asyncio
    async def test_execute_workflow_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test executing a workflow."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Create a workflow
        tasks = [
            {"type": "review", "description": "Review code", "payload": {"path": "main.py"}},
        ]
        
        create_result = await agent.call_tool("create_workflow", workflow_name="Test Workflow", tasks=tasks)
        workflow_id = create_result["workflow_id"]
        
        # Execute it
        exec_result = await agent.call_tool("execute_workflow", workflow_id=workflow_id)
        
        assert "error" not in exec_result
        assert "workflow_id" in exec_result
        assert "status" in exec_result
        assert "results" in exec_result
    
    @pytest.mark.asyncio
    async def test_perform_task_create_workflow(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test perform_task for create_workflow."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("create_workflow", {
            "workflow_name": "Test",
            "tasks": [{"type": "implement", "description": "Test"}],
        })
        
        assert "workflow_id" in result
        assert "task_ids" in result
    
    @pytest.mark.asyncio
    async def test_perform_task_create_task(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test perform_task for create_task."""
        from agentic_ai.agents.lead import LeadAgent
        
        agent = LeadAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("create_task", {
            "task_type": "implement",
            "description": "Test task",
        })
        
        assert "task_id" in result
        assert result["task"]["agent_type"] == "developer"


class TestTaskDataClasses:
    """Test Task and Workflow dataclasses."""
    
    def test_task_creation(self):
        """Test Task creation."""
        from agentic_ai.agents.lead import Task, TaskPriority, TaskStatus
        
        task = Task(
            id="test-001",
            type="implement",
            description="Test task",
            agent_type="developer",
        )
        
        assert task.id == "test-001"
        assert task.type == "implement"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.MEDIUM
    
    def test_task_with_dependencies(self):
        """Test Task with dependencies."""
        from agentic_ai.agents.lead import Task
        
        task = Task(
            id="test-002",
            type="generate_tests",
            description="Test after implementation",
            agent_type="qa",
            dependencies=["test-001"],
        )
        
        assert "test-001" in task.dependencies
    
    def test_workflow_creation(self):
        """Test Workflow creation."""
        from agentic_ai.agents.lead import Workflow, WorkflowStatus
        
        workflow = Workflow(
            id="wf-001",
            name="Test Workflow",
            description="Test workflow",
            tasks=[],
        )
        
        assert workflow.id == "wf-001"
        assert workflow.status == WorkflowStatus.DRAFT


if __name__ == "__main__":
    pytest.main([__file__, "-v"])