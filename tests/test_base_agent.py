"""
Tests for BaseAgent
===================

Unit tests for the agent base class.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestBaseAgent:
    """Test the BaseAgent abstract class."""
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        async def _async_generate(prompt, context=None):
            return "Generated response"
        mock.generate = MagicMock(side_effect=lambda p, c=None: "Generated response")
        mock.generate_async = _async_generate
        mock.chat = MagicMock(return_value="Chat response")
        mock.list_models = MagicMock(return_value=[])
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        mock = MagicMock()
        mock.get_agent_state = MagicMock(return_value=None)
        mock.save_agent_state = MagicMock()
        return mock
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        mock = MagicMock()
        mock.connect = MagicMock()
        mock.disconnect = MagicMock()
        mock.subscribe_agent = MagicMock()
        mock.publish_status = MagicMock()
        return mock
    
    def test_agent_initialization(self, mock_inference, mock_state_store, mock_bus):
        """Test agent initializes with correct defaults."""
        # Create a concrete test agent
        from agentic_ai.agents.base import BaseAgent, Permission, AgentStatus
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {"status": "done"}
        
        agent = TestAgent(
            agent_id="test-001",
            name="TestAgent",
            permission=Permission.STANDARD,
        )
        
        # Override the mock components
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "test-001"
        assert agent.name == "TestAgent"
        assert agent.permission == Permission.STANDARD
        assert agent.status == AgentStatus.IDLE
        assert len(agent._tools) > 0  # Default tools registered
    
    def test_permission_levels(self, mock_inference, mock_state_store, mock_bus):
        """Test permission level checking."""
        from agentic_ai.agents.base import BaseAgent, Permission
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {}
        
        # READ_ONLY agent
        agent_readonly = TestAgent(permission=Permission.READ_ONLY)
        agent_readonly.inference = mock_inference
        agent_readonly.state_store = mock_state_store
        agent_readonly.bus = mock_bus
        
        assert agent_readonly.can_read("project-1") == True
        assert agent_readonly.can_write("project-1") == False
        assert agent_readonly.can_create_project() == False
        
        # ADMIN agent
        agent_admin = TestAgent(permission=Permission.ADMIN)
        agent_admin.inference = mock_inference
        agent_admin.state_store = mock_state_store
        agent_admin.bus = mock_bus
        
        assert agent_admin.can_read("project-1") == True
        assert agent_admin.can_write("project-1") == True
        assert agent_admin.can_create_project() == True
        assert agent_admin.can_manage_agents() == True
    
    def test_tool_registration(self, mock_inference, mock_state_store, mock_bus):
        """Test tool registration and calling."""
        from agentic_ai.agents.base import BaseAgent, Tool, Permission
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {}
        
        agent = TestAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Register a custom tool
        async def custom_tool(arg1: str) -> str:
            return f"Processed: {arg1}"
        
        agent.register_tool(Tool(
            name="custom_tool",
            description="A custom test tool",
            func=custom_tool,
            requires_permission=Permission.STANDARD,
        ))
        
        # Tool should be registered
        assert "custom_tool" in agent._tools
        assert len(agent._tools) == 4  # 3 default + 1 custom
    
    def test_memory_operations(self, mock_inference, mock_state_store, mock_bus):
        """Test agent memory."""
        from agentic_ai.agents.base import AgentMemory
        
        memory = AgentMemory(max_entries=5)
        
        # Add entries
        memory.add("user", "Hello")
        memory.add("assistant", "Hi there!")
        
        assert len(memory.entries) == 2
        
        # Get recent
        recent = memory.get_recent(1)
        assert len(recent) == 1
        assert recent[0]["role"] == "assistant"
        
        # Convert to messages
        messages = memory.to_messages()
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        
        # Clear
        memory.clear()
        assert len(memory.entries) == 0
    
    def test_transparency_log(self, mock_inference, mock_state_store, mock_bus):
        """Test transparency logging."""
        from agentic_ai.agents.base import BaseAgent, Permission
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {}
        
        agent = TestAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        # Log some events
        agent.log("event1", {"key": "value1"})
        agent.log("event2", {"key": "value2"})
        
        log = agent.get_transparency_log()
        assert len(log) == 2
        
        # Each log should have timestamp, agent_id, event, data
        for entry in log:
            assert "timestamp" in entry
            assert "agent_id" in entry
            assert "event" in entry
            assert "data" in entry
    
    @pytest.mark.asyncio
    async def test_think_method(self, mock_inference, mock_state_store, mock_bus):
        """Test LLM inference through think method."""
        from agentic_ai.agents.base import BaseAgent
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {}
        
        agent = TestAgent()
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        response = await agent.think("What is 2+2?")
        
        assert response == "Generated response"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])