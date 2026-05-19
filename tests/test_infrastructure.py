"""
Tests for Inference Server and State Store
===========================================
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestInferenceServer:
    """Test the InferenceServer class."""
    
    @pytest.fixture
    def mock_httpx(self):
        """Mock httpx client."""
        with patch('httpx.Client') as mock_client:
            yield mock_client
    
    def test_init_default_host(self):
        """Test default initialization."""
        from agentic_ai.infrastructure.inference import InferenceServer
        
        server = InferenceServer()
        assert server.base_url == "http://10.0.0.117:11434"
        assert server.timeout == 120.0
    
    def test_init_custom_host(self):
        """Test custom host initialization."""
        from agentic_ai.infrastructure.inference import InferenceServer
        
        server = InferenceServer(host="localhost", port=11435)
        assert server.base_url == "http://localhost:11435"
    
    def test_get_model_for_agent(self):
        """Test model selection for agent types."""
        from agentic_ai.infrastructure.inference import InferenceServer, ModelInfo
        
        server = InferenceServer()
        server._available_models = [
            ModelInfo(name="llama3.1:8b", size=4000000000, parameter_size="8B", quantization="Q4_0", family="llama"),
            ModelInfo(name="qwen3-coder:latest", size=5000000000, parameter_size="7B", quantization="Q4_0", family="qwen"),
        ]
        
        # Developer should get coder model
        model = server.get_model_for_agent("developer")
        assert model == "qwen3-coder:latest"
        
        # Unknown agent should get first available
        model = server.get_model_for_agent("unknown")
        assert model == "llama3.1:8b"
    
    def test_fallback_model(self):
        """Test fallback model selection."""
        from agentic_ai.infrastructure.inference import InferenceServer, ModelInfo
        
        server = InferenceServer()
        server._available_models = [
            ModelInfo(name="tinyllama:latest", size=600000000, parameter_size="1B", quantization="Q4_0", family="llama"),
        ]
        
        # Developer prefers qwen-coder, but should fall back to tinyllama
        model = server.get_model_for_agent("developer")
        assert model == "tinyllama:latest"


class TestStateStore:
    """Test the StateStore class."""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client."""
        with patch('redis.Redis') as mock:
            yield mock
    
    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temp database path."""
        return str(tmp_path / "test_state.db")
    
    def test_init_creates_tables(self, mock_redis, temp_db):
        """Test database initialization creates tables."""
        from agentic_ai.infrastructure.state import StateStore
        
        store = StateStore(db_path=temp_db)
        
        # Tables should exist
        import sqlite3
        conn = sqlite3.connect(store.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert "agent_state" in tables
        assert "tasks" in tables
        assert "project_memory" in tables
        
        conn.close()
    
    def test_save_and_get_agent_state(self, mock_redis, temp_db):
        """Test agent state persistence."""
        from agentic_ai.infrastructure.state import StateStore
        
        # Mock Redis to return None (cache miss)
        mock_redis_instance = MagicMock()
        mock_redis_instance.hget.return_value = None  # No cached state
        mock_redis.return_value = mock_redis_instance
        
        store = StateStore(db_path=temp_db)
        
        # Save state
        state = {"name": "test_agent", "status": "active", "count": 42}
        store.save_agent_state("agent-001", "developer", state)
        
        # Redis should have been called
        mock_redis_instance.hset.assert_called_once()
        
        # Reset mock for get (cache miss)
        mock_redis_instance.hget.return_value = None
        
        # Retrieve state (from SQLite since Redis returns None)
        retrieved = store.get_agent_state("agent-001")
        assert retrieved == state


class TestACPMessage:
    """Test ACPMessage."""
    
    def test_message_creation(self):
        """Test creating a message."""
        from agentic_ai.protocol.acp import ACPMessage, MessageType, Priority
        
        msg = ACPMessage(
            type=MessageType.TASK_REQUEST,
            priority=Priority.HIGH,
            sender="agent-001",
            recipient="agent-002",
            subject="Test task",
            body={"key": "value"},
        )
        
        assert msg.type == MessageType.TASK_REQUEST
        assert msg.priority == Priority.HIGH
        assert msg.sender == "agent-001"
        assert "id" in msg.to_dict()
    
    def test_message_serialization(self):
        """Test message JSON serialization."""
        from agentic_ai.protocol.acp import ACPMessage, MessageType
        
        msg = ACPMessage(
            type=MessageType.QUERY,
            sender="agent-001",
            subject="Test",
        )
        
        json_str = msg.to_json()
        data = json.loads(json_str)
        
        assert data["type"] == "query"
        assert data["sender"] == "agent-001"
        
        # Deserialize
        msg2 = ACPMessage.from_json(json_str)
        assert msg2.type == MessageType.QUERY
        assert msg2.sender == "agent-001"


class TestACPBus:
    """Test ACPBus."""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client."""
        with patch('redis.Redis') as mock:
            mock_instance = MagicMock()
            mock.return_value = mock_instance
            yield mock_instance
    
    def test_send_message(self, mock_redis):
        """Test sending a message."""
        from agentic_ai.protocol.acp import ACPBus, ACPMessage, MessageType
        
        bus = ACPBus(agent_id="agent-001")
        bus.redis = mock_redis
        
        msg = ACPMessage(
            type=MessageType.TASK_REQUEST,
            sender="agent-001",
            recipient="agent-002",
            subject="Do something",
        )
        
        bus.send(msg)
        
        # Should publish to recipient channel
        mock_redis.publish.assert_called()
        # Should store in pending queue
        mock_redis.lpush.assert_called()
    
    def test_broadcast_message(self, mock_redis):
        """Test broadcasting a message."""
        from agentic_ai.protocol.acp import ACPBus, ACPMessage, MessageType
        
        bus = ACPBus(agent_id="agent-001")
        bus.redis = mock_redis
        
        msg = ACPMessage(
            type=MessageType.BROADCAST,
            sender="agent-001",
            channel="status",
        )
        
        bus.broadcast(msg)
        
        mock_redis.publish.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])