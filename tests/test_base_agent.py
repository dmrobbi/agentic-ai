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
        mock.generate = AsyncMock(return_value="Generated response")
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
        assert agent_readonly.permission == Permission.READ_ONLY
        
        # STANDARD agent
        agent_standard = TestAgent(permission=Permission.STANDARD)
        assert agent_standard.permission == Permission.STANDARD
        
        # ADMIN agent
        agent_admin = TestAgent(permission=Permission.ADMIN)
        assert agent_admin.permission == Permission.ADMIN
    
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
        
        # Register a custom tool
        async def custom_tool(arg1: str) -> str:
            return f"Processed: {arg1}"
        
        agent._tools["custom_tool"] = Tool(
            name="custom_tool",
            description="A custom test tool",
            func=custom_tool,
        )
        
        # Tool should be registered
        assert "custom_tool" in agent._tools
    
    def test_memory_operations(self, mock_inference, mock_state_store, mock_bus):
        """Test agent memory."""
        from agentic_ai.agents.base import AgentMemory
        
        memory = AgentMemory(max_entries=5)
        
        # Store entries
        memory.store("user", "Hello")
        memory.store("assistant", "Hi there!")
        
        assert len(memory) == 2
        
        # Retrieve entries
        assert memory.retrieve("user") == "Hello"
        assert memory.retrieve("assistant") == "Hi there!"
        assert memory.retrieve("nonexistent") is None
        
        # Keys
        assert set(memory.keys()) == {"user", "assistant"}
        
        # Forget
        assert memory.forget("user") is True
        assert memory.retrieve("user") is None
        assert len(memory) == 1
        
        # Clear
        memory.clear()
        assert len(memory) == 0
    
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
        
        # Log some events
        agent.log("event1", {"key": "value1"})
        agent.log("event2", {"key": "value2"})
        
        log = agent._transparency_log
        assert len(log) == 2
        
        # Each log should have timestamp, agent_id, action, details
        for entry in log:
            assert "timestamp" in entry
            assert "agent_id" in entry
            assert "action" in entry
            assert "details" in entry
    
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
        
        agent = TestAgent(inference_engine=mock_inference)
        
        response = await agent.think("What is 2+2?")
        
        assert response == "Generated response"
        mock_inference.generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_think_method_no_engine(self):
        """Test think method fallback without inference engine."""
        from agentic_ai.agents.base import BaseAgent
        
        class TestAgent(BaseAgent):
            agent_type = "test"
            
            async def process_message(self, message):
                return None
            
            async def perform_task(self, task_type, payload):
                return {}
        
        agent = TestAgent()
        
        response = await agent.think("What is 2+2?")
        assert "What is 2+2?" in response


if __name__ == "__main__":
    pytest.main([__file__, "-v"])