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
        mock.publish = MagicMock()
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
            inference_engine=mock_inference,
            state_store=mock_state_store,
            message_bus=mock_bus,
        )
<<<<<<< HEAD

=======
        
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
        assert agent.agent_id == "test-001"
        assert agent.name == "TestAgent"
        assert agent.permission == Permission.STANDARD
        assert agent.status == AgentStatus.IDLE
        assert len(agent._tools) > 0  # Default tools registered

    def test_permission_levels(self, mock_inference, mock_state_store, mock_bus):
        """Test permission level checking."""
        from agentic_ai.agents.base import BaseAgent, Permission
<<<<<<< HEAD

        # Permission is stored as an enum — check that the value is correct
        agent_readonly = BaseAgent.__new__(BaseAgent)
        agent_readonly.permission = Permission.READ_ONLY

        # READ_ONLY can't write or create projects
        assert agent_readonly.permission == Permission.READ_ONLY
        assert agent_readonly.permission.value == "read_only"

        agent_admin = BaseAgent.__new__(BaseAgent)
        agent_admin.permission = Permission.ADMIN

        assert agent_admin.permission == Permission.ADMIN
        assert agent_admin.permission.value == "admin"

=======
        
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
    
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
    def test_tool_registration(self, mock_inference, mock_state_store, mock_bus):
        """Test tool registration and calling."""
        from agentic_ai.agents.base import BaseAgent, Tool

        class TestAgent(BaseAgent):
            agent_type = "test"

            async def process_message(self, message):
                return None

            async def perform_task(self, task_type, payload):
                return {}

        agent = TestAgent()
<<<<<<< HEAD
        agent.inference_engine = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus

        # Register a custom tool by adding to _tools dict
        initial_count = len(agent._tools)

        async def custom_tool(arg1: str) -> str:
            return f"Processed: {arg1}"

=======
        
        # Register a custom tool
        async def custom_tool(arg1: str) -> str:
            return f"Processed: {arg1}"
        
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
        agent._tools["custom_tool"] = Tool(
            name="custom_tool",
            description="A custom test tool",
            func=custom_tool,
        )
<<<<<<< HEAD

        # Tool should be registered
        assert "custom_tool" in agent._tools
        assert len(agent._tools) == initial_count + 1

    def test_memory_operations(self):
        """Test agent memory store/retrieve/forget."""
=======
        
        # Tool should be registered
        assert "custom_tool" in agent._tools
    
    def test_memory_operations(self, mock_inference, mock_state_store, mock_bus):
        """Test agent memory."""
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
        from agentic_ai.agents.base import AgentMemory

        memory = AgentMemory(max_entries=5)
<<<<<<< HEAD

        # Store entries
        memory.store("key1", "Hello")
        memory.store("key2", "Hi there!")

        assert len(memory) == 2

        # Retrieve
        assert memory.retrieve("key1") == "Hello"
        assert memory.retrieve("key2") == "Hi there!"
        assert memory.retrieve("nonexistent") is None

        # Keys
        assert "key1" in memory.keys()
        assert "key2" in memory.keys()

        # Forget
        assert memory.forget("key1") is True
        assert memory.retrieve("key1") is None
        assert len(memory) == 1

        # Clear
        memory.clear()
        assert len(memory) == 0

=======
        
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
    
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
    def test_transparency_log(self, mock_inference, mock_state_store, mock_bus):
        """Test transparency logging."""
        from agentic_ai.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_type = "test"

            async def process_message(self, message):
                return None

            async def perform_task(self, task_type, payload):
                return {}

        agent = TestAgent()
<<<<<<< HEAD
        agent.inference_engine = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus

        # Log some events
        agent.log("event1", {"key": "value1"})
        agent.log("event2", {"key": "value2"})

        log = agent._transparency_log
        assert len(log) == 2

=======
        
        # Log some events
        agent.log("event1", {"key": "value1"})
        agent.log("event2", {"key": "value2"})
        
        log = agent._transparency_log
        assert len(log) == 2
        
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
        # Each log should have timestamp, agent_id, action, details
        for entry in log:
            assert "timestamp" in entry
            assert "agent_id" in entry
            assert "action" in entry
            assert "details" in entry
<<<<<<< HEAD

=======
    
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
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
<<<<<<< HEAD

        agent = TestAgent(
            inference_engine=mock_inference,
            state_store=mock_state_store,
            message_bus=mock_bus,
        )

=======
        
        agent = TestAgent(inference_engine=mock_inference)
        
>>>>>>> d04964d (fix: align all tests with refactored agent APIs)
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

    @pytest.mark.asyncio
    async def test_think_method_no_inference(self):
        """Test think method falls back when no inference engine."""
        from agentic_ai.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_type = "test"

            async def process_message(self, message):
                return None

            async def perform_task(self, task_type, payload):
                return {}

        agent = TestAgent()
        response = await agent.think("What is 2+2?")

        # Fallback returns "Thought about: <prompt>"
        assert "Thought about" in response

    @pytest.mark.asyncio
    async def test_call_tool(self):
        """Test tool calling."""
        from agentic_ai.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_type = "test"

            async def process_message(self, message):
                return None

            async def perform_task(self, task_type, payload):
                return {}

        agent = TestAgent()
        result = await agent.call_tool("get_status")
        assert result["agent_type"] == "test"

        # Nonexistent tool
        result = await agent.call_tool("nonexistent")
        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])