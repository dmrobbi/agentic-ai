"""Tests for Agent Card — A2A-compatible agent metadata and capability discovery."""
import json
import pytest

from agentic_ai.protocol.agent_card import (
    AgentCard,
    AgentCapability,
    AgentCardFormat,
)
from agentic_ai.agents.base import BaseAgent, Permission


# ============================================
# AgentCapability tests
# ============================================

class TestAgentCapability:
    """Tests for AgentCapability dataclass."""

    def test_capability_creation_with_defaults(self):
        """AgentCapability can be created with just a name, defaults are empty."""
        cap = AgentCapability(name="search")
        assert cap.name == "search"
        assert cap.description == ""
        assert cap.input_schema == {}
        assert cap.output_schema == {}

    def test_capability_creation_full(self):
        """AgentCapability can be created with all fields."""
        cap = AgentCapability(
            name="search",
            description="Search the web",
            input_schema={"query": "string"},
            output_schema={"results": "list"},
        )
        assert cap.name == "search"
        assert cap.description == "Search the web"
        assert cap.input_schema == {"query": "string"}
        assert cap.output_schema == {"results": "list"}

    def test_capability_serialization_in_card(self):
        """AgentCapability serializes correctly within an AgentCard."""
        cap = AgentCapability(
            name="compute",
            description="Run computation",
            input_schema={"x": "int"},
            output_schema={"result": "int"},
        )
        card = AgentCard(
            name="mathbot",
            description="Math agent",
            capabilities=[cap],
        )
        d = card.to_dict()
        assert len(d["capabilities"]) == 1
        assert d["capabilities"][0]["name"] == "compute"
        assert d["capabilities"][0]["description"] == "Run computation"
        assert d["capabilities"][0]["input_schema"] == {"x": "int"}
        assert d["capabilities"][0]["output_schema"] == {"result": "int"}


# ============================================
# AgentCard creation tests
# ============================================

class TestAgentCardCreation:
    """Tests for AgentCard creation and defaults."""

    def test_card_creation_with_defaults(self):
        """AgentCard can be created with only required fields."""
        card = AgentCard(name="test", description="A test agent")
        assert card.name == "test"
        assert card.description == "A test agent"
        assert card.version == "1.0.0"
        assert card.provider == "agentic-ai"
        assert card.agent_type == ""
        assert card.agent_id == ""
        assert card.capabilities == []
        assert card.input_schema == {}
        assert card.output_schema == {}
        assert card.authentication == {}
        assert card.endpoints == []
        assert card.permissions == []
        assert card.metadata == {}

    def test_card_creation_with_capabilities(self):
        """AgentCard can be created with a list of capabilities."""
        caps = [
            AgentCapability(name="search", description="Search the web"),
            AgentCapability(name="compute", description="Run calculations"),
        ]
        card = AgentCard(
            name="multi-bot",
            description="Multi-purpose agent",
            capabilities=caps,
        )
        assert len(card.capabilities) == 2
        assert card.capabilities[0].name == "search"
        assert card.capabilities[1].name == "compute"

    def test_card_with_custom_metadata(self):
        """AgentCard stores custom metadata."""
        card = AgentCard(
            name="custom",
            description="Custom agent",
            metadata={"owner": "team-a", "env": "production"},
        )
        assert card.metadata["owner"] == "team-a"
        assert card.metadata["env"] == "production"

    def test_card_with_authentication(self):
        """AgentCard stores authentication dict."""
        card = AgentCard(
            name="auth-agent",
            description="Authenticated agent",
            authentication={"scheme": "bearer", "token_url": "https://example.com/token"},
        )
        assert card.authentication["scheme"] == "bearer"
        assert card.authentication["token_url"] == "https://example.com/token"

    def test_card_with_endpoints(self):
        """AgentCard stores endpoint list."""
        card = AgentCard(
            name="ep-agent",
            description="Agent with endpoints",
            endpoints=[
                {"url": "https://example.com/agent", "type": "jsonrpc"},
                {"url": "https://example.com/ws", "type": "websocket"},
            ],
        )
        assert len(card.endpoints) == 2
        assert card.endpoints[0]["type"] == "jsonrpc"

    def test_empty_capabilities_list(self):
        """AgentCard with empty capabilities list serializes correctly."""
        card = AgentCard(name="empty", description="No capabilities", capabilities=[])
        d = card.to_dict()
        assert d["capabilities"] == []


# ============================================
# Serialization tests
# ============================================

class TestAgentCardSerialization:
    """Tests for AgentCard serialization methods."""

    def test_to_dict(self):
        """to_dict returns a complete dictionary."""
        card = AgentCard(
            name="testbot",
            description="Test bot",
            version="2.0.0",
            agent_type="test",
            agent_id="test-001",
        )
        d = card.to_dict()
        assert d["name"] == "testbot"
        assert d["description"] == "Test bot"
        assert d["version"] == "2.0.0"
        assert d["provider"] == "agentic-ai"
        assert d["agent_type"] == "test"
        assert d["agent_id"] == "test-001"
        assert isinstance(d["capabilities"], list)

    def test_to_json(self):
        """to_json returns valid JSON string."""
        card = AgentCard(name="jsontest", description="JSON test")
        json_str = card.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "jsontest"
        assert parsed["description"] == "JSON test"

    def test_to_json_ld_has_context_and_type(self):
        """to_json_ld includes @context and @type for A2A spec."""
        card = AgentCard(
            name="ldtest",
            description="JSON-LD test",
            agent_id="ld-001",
        )
        json_ld = card.to_json_ld()
        parsed = json.loads(json_ld)
        assert parsed["@context"] == "https://schema.org/Agent"
        assert parsed["@type"] == "Agent"
        assert parsed["@id"] == "ld-001"

    def test_to_json_ld_uses_name_as_id_fallback(self):
        """to_json_ld uses name as @id when agent_id is not set."""
        card = AgentCard(name="fallback-id", description="No ID set")
        json_ld = card.to_json_ld()
        parsed = json.loads(json_ld)
        assert parsed["@id"] == "fallback-id"


# ============================================
# Deserialization tests
# ============================================

class TestAgentCardDeserialization:
    """Tests for AgentCard deserialization methods."""

    def test_from_dict(self):
        """from_dict creates AgentCard from a dictionary."""
        data = {
            "name": "dict-agent",
            "description": "Created from dict",
            "version": "3.0.0",
            "agent_type": "dict-type",
            "capabilities": [
                {"name": "cap1", "description": "First", "input_schema": {}, "output_schema": {}},
            ],
        }
        card = AgentCard.from_dict(data)
        assert card.name == "dict-agent"
        assert card.description == "Created from dict"
        assert card.version == "3.0.0"
        assert len(card.capabilities) == 1
        assert card.capabilities[0].name == "cap1"

    def test_from_json(self):
        """from_json creates AgentCard from a JSON string."""
        json_str = json.dumps({
            "name": "json-agent",
            "description": "Created from JSON",
            "version": "1.5.0",
        })
        card = AgentCard.from_json(json_str)
        assert card.name == "json-agent"
        assert card.description == "Created from JSON"
        assert card.version == "1.5.0"

    def test_round_trip_dict_to_card_and_back(self):
        """Round-trip: dict → AgentCard → dict → AgentCard preserves data."""
        original_data = {
            "name": "roundtrip",
            "description": "Round trip test",
            "version": "4.0.0",
            "provider": "test-provider",
            "agent_type": "test",
            "agent_id": "rt-001",
            "capabilities": [
                {"name": "cap_a", "description": "Cap A", "input_schema": {"x": "int"}, "output_schema": {"y": "int"}},
                {"name": "cap_b", "description": "Cap B", "input_schema": {}, "output_schema": {}},
            ],
            "input_schema": {"prompt": "string"},
            "output_schema": {"response": "string"},
            "authentication": {"scheme": "apikey"},
            "endpoints": [{"url": "https://example.com", "type": "jsonrpc"}],
            "permissions": ["read", "write"],
            "metadata": {"env": "test"},
        }
        card = AgentCard.from_dict(original_data.copy())
        result_dict = card.to_dict()
        card2 = AgentCard.from_dict(result_dict)
        result_dict2 = card2.to_dict()
        assert result_dict2["name"] == "roundtrip"
        assert result_dict2["description"] == "Round trip test"
        assert len(result_dict2["capabilities"]) == 2
        assert result_dict2["capabilities"][0]["name"] == "cap_a"


# ============================================
# BaseAgent.get_agent_card() tests
# ============================================

class TestBaseAgentGetAgentCard:
    """Tests for BaseAgent.get_agent_card() method."""

    def test_base_agent_card_returns_valid_card(self):
        """BaseAgent.get_agent_card() returns a valid AgentCard."""
        agent = BaseAgent(agent_id="test-123", name="TestAgent")
        card = agent.get_agent_card()
        assert isinstance(card, AgentCard)
        assert card.agent_type == "base"
        assert card.agent_id == "test-123"
        assert "base" in card.name

    def test_base_agent_card_has_tools_in_capabilities(self):
        """BaseAgent card lists registered tools as capabilities."""
        agent = BaseAgent()
        card = agent.get_agent_card()
        # Default tools: get_status, list_tools, send_message
        assert len(card.capabilities) >= 3
        cap_names = [c.name for c in card.capabilities]
        assert "get_status" in cap_names

    def test_base_agent_card_permissions(self):
        """BaseAgent card includes permission level."""
        agent = BaseAgent(permission=Permission.ADMIN)
        card = agent.get_agent_card()
        assert "admin" in card.permissions

    def test_base_agent_card_metadata_has_tools(self):
        """BaseAgent card metadata includes tool names."""
        agent = BaseAgent()
        card = agent.get_agent_card()
        assert "tools" in card.metadata
        assert isinstance(card.metadata["tools"], list)


# ============================================
# AgentCardFormat enum tests
# ============================================

class TestAgentCardFormat:
    """Tests for AgentCardFormat enum."""

    def test_format_values(self):
        """AgentCardFormat has expected values."""
        assert AgentCardFormat.JSON == "json"
        assert AgentCardFormat.JSON_LD == "json-ld"

    def test_format_is_string(self):
        """AgentCardFormat values are strings."""
        assert isinstance(AgentCardFormat.JSON.value, str)
        assert isinstance(AgentCardFormat.JSON_LD.value, str)