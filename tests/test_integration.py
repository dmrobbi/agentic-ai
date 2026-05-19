"""
Integration Tests for Agentic AI
=================================

Tests that verify all components work together.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestIntegration:
    """Integration tests for the full agent stack."""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis."""
        with patch('redis.Redis') as mock:
            mock_instance = MagicMock()
            mock.return_value = mock_instance
            yield mock_instance
    
    @pytest.fixture
    def mock_httpx(self):
        """Mock httpx for inference."""
        with patch('httpx.Client') as mock:
            mock_instance = MagicMock()
            mock.return_value = mock_instance
            yield mock_instance
    
    def test_full_import_chain(self):
        """Test that all modules can be imported."""
        # Infrastructure
        from agentic_ai.infrastructure.inference import InferenceServer
        from agentic_ai.infrastructure.state import StateStore
        
        # Protocol
        from agentic_ai.protocol.acp import ACPMessage, ACPBus
        
        # Agents
        from agentic_ai.agents.base import BaseAgent
        
        # Verify classes exist
        assert InferenceServer is not None
        assert StateStore is not None
        assert ACPMessage is not None
        assert ACPBus is not None
        assert BaseAgent is not None
    
    def test_message_bus_workflow(self, mock_redis):
        """Test complete message workflow."""
        from agentic_ai.protocol.acp import ACPBus, ACPMessage, MessageType
        
        # Create two "agents" with message bus
        bus1 = ACPBus(agent_id="agent-001")
        bus1.redis = mock_redis
        
        bus2 = ACPBus(agent_id="agent-002")
        bus2.redis = mock_redis
        
        # Agent 1 sends task request
        msg = ACPMessage(
            type=MessageType.TASK_REQUEST,
            sender="agent-001",
            recipient="agent-002",
            subject="analyze_code",
            body={"file": "main.py"},
        )
        
        bus1.send(msg)
        
        # Verify publish was called
        assert mock_redis.publish.called
        assert mock_redis.lpush.called
    
    def test_agent_state_persistence(self, mock_redis, tmp_path):
        """Test agent state is persisted."""
        from agentic_ai.infrastructure.state import StateStore
        
        db_path = str(tmp_path / "test.db")
        
        # Mock Redis to return None (cache miss)
        mock_redis.hget.return_value = None
        
        with patch('redis.Redis', return_value=mock_redis):
            store = StateStore(db_path=db_path)
            
            # Save state
            state = {
                "name": "DeveloperAgent",
                "project": "agentic_ai",
                "tasks_completed": 5,
            }
            store.save_agent_state("dev-001", "developer", state)
            
            # Retrieve state (from SQLite since Redis cache miss)
            retrieved = store.get_agent_state("dev-001")
            assert retrieved == state
    
    def test_task_workflow(self, mock_redis, tmp_path):
        """Test task creation and retrieval."""
        from agentic_ai.infrastructure.state import StateStore
        
        db_path = str(tmp_path / "test.db")
        store = StateStore(db_path=db_path)
        store.redis_client = mock_redis
        
        # Create task
        store.create_task(
            task_id="task-001",
            task_type="code_review",
            agent_id="dev-001",
            priority=1,
            payload={"pr": 42},
        )
        
        # Get pending tasks
        tasks = store.get_pending_tasks("dev-001")
        assert len(tasks) == 1
        assert tasks[0]["task_type"] == "code_review"
        
        # Complete task
        store.update_task_status("task-001", "completed", {"approved": True})
        
        # Should have no pending tasks now
        tasks = store.get_pending_tasks("dev-001")
        assert len(tasks) == 0


class TestDeveloperAgent:
    """Test a concrete Developer agent implementation."""
    
    @pytest.fixture
    def mock_components(self, tmp_path):
        """Set up mocked components."""
        with patch('redis.Redis') as mock_redis, \
             patch('httpx.Client') as mock_httpx:
            
            redis_instance = MagicMock()
            mock_redis.return_value = redis_instance
            
            httpx_instance = MagicMock()
            mock_httpx.return_value = httpx_instance
            
            yield {
                'redis': redis_instance,
                'httpx': httpx_instance,
                'db_path': str(tmp_path / "test.db"),
            }
    
    @pytest.mark.asyncio
    async def test_developer_agent_responds_to_task(self, mock_components):
        """Test developer agent processes task requests."""
        from agentic_ai.agents.base import BaseAgent, Permission
        from agentic_ai.protocol.acp import ACPMessage, MessageType
        
        class DeveloperAgent(BaseAgent):
            agent_type = "developer"
            
            async def process_message(self, message):
                if message.type == MessageType.TASK_REQUEST:
                    return ACPMessage(
                        type=MessageType.TASK_ACCEPT,
                        sender=self.agent_id,
                        recipient=message.sender,
                        correlation_id=message.id,
                    )
                return None
            
            async def perform_task(self, task_type, payload):
                if task_type == "write_code":
                    return {"code": "print('Hello, World!')"}
                return {"status": "unknown_task"}
        
        # Mock state store with None return for get_agent_state
        mock_state_store = MagicMock()
        mock_state_store.get_agent_state.return_value = None
        
        agent = DeveloperAgent(
            agent_id="dev-001",
            name="DeveloperAgent",
            permission=Permission.STANDARD,
            state_store=mock_state_store,  # Pass mock directly
        )
        
        # Create task request message
        request = ACPMessage(
            type=MessageType.TASK_REQUEST,
            sender="lead-001",
            recipient="dev-001",
            subject="write_code",
            body={"language": "python"},
        )
        
        # Process message
        response = await agent.process_message(request)
        
        assert response is not None
        assert response.type == MessageType.TASK_ACCEPT
        assert response.recipient == "lead-001"
        
        # Perform task
        result = await agent.perform_task("write_code", {"language": "python"})
        assert "code" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])