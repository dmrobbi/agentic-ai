"""
Tests for Lead Agent Conversation Orchestration
=================================================

Unit tests for the multi-agent orchestration patterns added to LeadAgent.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCancellationToken:
    """Test the CancellationToken dataclass."""

    def test_cancellation_token_creation(self):
        """Token starts as not cancelled."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        assert token.is_cancelled is False

    def test_cancellation_token_cancel(self):
        """Cancel sets is_cancelled to True."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        token.cancel()
        assert token.is_cancelled is True

    def test_cancellation_token_stays_cancelled(self):
        """Once cancelled, token stays cancelled."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        token.cancel()
        token.cancel()  # Double cancel
        assert token.is_cancelled is True

    def test_cancellation_token_default_field(self):
        """Token can be created with _cancelled field."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken(_cancelled=True)
        assert token.is_cancelled is True


class TestRoundRobin:
    """Test the round_robin orchestration method."""

    @pytest.fixture
    def lead(self, tmp_path):
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent(project_path=str(tmp_path))
        agent.inference = MagicMock()
        agent.state_store = MagicMock()
        agent.bus = MagicMock()
        return agent

    @pytest.mark.asyncio
    async def test_round_robin_basic(self, lead):
        """Test basic round robin with two agents and one round."""
        results = await lead.round_robin(
            agents=["agent-a", "agent-b"],
            prompt="Discuss security",
            rounds=1,
        )
        assert len(results) == 2
        assert results[0]["round"] == 1
        assert results[0]["agent_id"] == "agent-a"
        assert results[1]["agent_id"] == "agent-b"

    @pytest.mark.asyncio
    async def test_round_robin_multiple_rounds(self, lead):
        """Test round robin with multiple rounds."""
        results = await lead.round_robin(
            agents=["agent-a", "agent-b"],
            prompt="Start",
            rounds=3,
        )
        # 2 agents * 3 rounds = 6 entries
        assert len(results) == 6
        # Check round numbers
        assert results[0]["round"] == 1
        assert results[2]["round"] == 2
        assert results[4]["round"] == 3

    @pytest.mark.asyncio
    async def test_round_robin_prompt_evolution(self, lead):
        """Test that prompts evolve across agents in round robin."""
        results = await lead.round_robin(
            agents=["agent-a"],
            prompt="Initial prompt",
            rounds=2,
        )
        assert len(results) == 2
        # First agent gets the initial prompt
        assert results[0]["prompt"] == "Initial prompt"
        # Second round prompt should contain reference to first round
        assert "Round 1" in results[1]["prompt"]

    @pytest.mark.asyncio
    async def test_round_robin_cancellation(self, lead):
        """Test cancellation token stops round robin early."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        # Cancel after creating token
        token.cancel()
        results = await lead.round_robin(
            agents=["agent-a", "agent-b"],
            prompt="Test",
            rounds=3,
            cancellation_token=token,
        )
        # Should produce no results since cancelled before start
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_round_robin_mid_cancellation(self, lead):
        """Test cancellation token stops round robin mid-execution."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()

        # We'll cancel the token after the first result
        original_send = lead.send_message

        call_count = 0

        def cancelling_send(*args, **kwargs):
            nonlocal call_count, token
            call_count += 1
            if call_count >= 2:
                token.cancel()
            return original_send(*args, **kwargs)

        lead.send_message = cancelling_send

        results = await lead.round_robin(
            agents=["agent-a", "agent-b", "agent-c"],
            prompt="Test",
            rounds=2,
            cancellation_token=token,
        )
        # Should have at least 2 results before cancellation
        assert len(results) >= 2
        # Should have fewer than full 6 (3 agents * 2 rounds)
        assert len(results) < 6

    @pytest.mark.asyncio
    async def test_round_robin_sends_messages(self, lead):
        """Test that round robin sends messages to agents."""
        results = await lead.round_robin(
            agents=["agent-x"],
            prompt="Hello",
            rounds=1,
        )
        # Check that messages were recorded in history
        sent_messages = [h for h in lead._history if h["action"] == "send_message"]
        assert len(sent_messages) >= 1
        assert sent_messages[0]["to"] == "agent-x"


class TestSelector:
    """Test the selector orchestration method."""

    @pytest.fixture
    def lead(self, tmp_path):
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent(project_path=str(tmp_path))
        agent.inference = MagicMock()
        agent.state_store = MagicMock()
        agent.bus = MagicMock()
        return agent

    @pytest.mark.asyncio
    async def test_selector_custom_fn(self, lead):
        """Test selector with custom selector function."""
        def pick_first(agents, prompt):
            return agents[0]

        result = await lead.selector(
            agents=["agent-a", "agent-b"],
            prompt="Do something",
            selector_fn=pick_first,
        )
        assert result["selected_agent"] == "agent-a"
        assert result["prompt"] == "Do something"

    @pytest.mark.asyncio
    async def test_selector_custom_fn_picks_last(self, lead):
        """Test selector with custom fn that picks last agent."""
        def pick_last(agents, prompt):
            return agents[-1]

        result = await lead.selector(
            agents=["agent-a", "agent-b", "agent-c"],
            prompt="Task",
            selector_fn=pick_last,
        )
        assert result["selected_agent"] == "agent-c"

    @pytest.mark.asyncio
    async def test_selector_default_security(self, lead):
        """Test default selector with security keyword."""
        result = await lead.selector(
            agents=["security-agent", "compliance-agent"],
            prompt="Check for security vulnerabilities",
        )
        assert result["selected_agent"] == "security-agent"

    @pytest.mark.asyncio
    async def test_selector_default_compliance(self, lead):
        """Test default selector with compliance keyword."""
        result = await lead.selector(
            agents=["security-agent", "compliance-agent"],
            prompt="Review compliance regulations",
        )
        assert result["selected_agent"] == "compliance-agent"

    @pytest.mark.asyncio
    async def test_selector_default_risk(self, lead):
        """Test default selector with risk keyword."""
        result = await lead.selector(
            agents=["security-agent", "risk-agent"],
            prompt="Conduct risk assessment",
        )
        assert result["selected_agent"] == "risk-agent"

    @pytest.mark.asyncio
    async def test_selector_default_privacy(self, lead):
        """Test default selector with privacy keyword."""
        result = await lead.selector(
            agents=["privacy-agent", "security-agent"],
            prompt="Review privacy and data protection policies",
        )
        assert result["selected_agent"] == "privacy-agent"

    @pytest.mark.asyncio
    async def test_selector_default_legal(self, lead):
        """Test default selector with legal keyword."""
        result = await lead.selector(
            agents=["legal-agent", "security-agent"],
            prompt="Review legal contract",
        )
        assert result["selected_agent"] == "legal-agent"

    @pytest.mark.asyncio
    async def test_selector_default_fallback(self, lead):
        """Test default selector falls back to first agent."""
        result = await lead.selector(
            agents=["agent-a", "agent-b"],
            prompt="Generic task with no keywords",
        )
        assert result["selected_agent"] == "agent-a"

    @pytest.mark.asyncio
    async def test_selector_cancelled(self, lead):
        """Test selector with cancelled token."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        token.cancel()
        result = await lead.selector(
            agents=["agent-a"],
            prompt="Task",
            cancellation_token=token,
        )
        assert "error" in result
        assert result["error"] == "cancelled"


class TestBroadcastAndCollect:
    """Test the broadcast_and_collect orchestration method."""

    @pytest.fixture
    def lead(self, tmp_path):
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent(project_path=str(tmp_path))
        agent.inference = MagicMock()
        agent.state_store = MagicMock()
        agent.bus = MagicMock()
        return agent

    @pytest.mark.asyncio
    async def test_broadcast_basic(self, lead):
        """Test basic broadcast to agents."""
        result = await lead.broadcast_and_collect(
            agents=["agent-a", "agent-b", "agent-c"],
            prompt="Broadcast message",
        )
        assert result["agent_count"] == 3
        assert result["response_count"] == 3
        assert result["prompt"] == "Broadcast message"

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all(self, lead):
        """Test that broadcast sends messages to all agents."""
        await lead.broadcast_and_collect(
            agents=["agent-x", "agent-y"],
            prompt="Alert",
        )
        # Check history for broadcast messages
        broadcast_msgs = [h for h in lead._history if h["action"] == "send_message" and "Alert" in str(h.get("content", ""))]
        assert len(broadcast_msgs) >= 2

    @pytest.mark.asyncio
    async def test_broadcast_cancellation(self, lead):
        """Test broadcast stops on cancellation."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        token.cancel()
        result = await lead.broadcast_and_collect(
            agents=["agent-a", "agent-b"],
            prompt="Test",
            cancellation_token=token,
        )
        # No responses since cancelled before start
        assert result["response_count"] == 0


class TestDecomposeAndParallel:
    """Test the decompose_and_parallel orchestration method."""

    @pytest.fixture
    def lead(self, tmp_path):
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent(project_path=str(tmp_path))
        agent.inference = MagicMock()
        agent.state_store = MagicMock()
        agent.bus = MagicMock()
        return agent

    @pytest.mark.asyncio
    async def test_decompose_three_agents(self, lead):
        """Test decomposition with three agents."""
        result = await lead.decompose_and_parallel(
            task="Implement authentication",
            agents=["agent-a", "agent-b", "agent-c"],
        )
        assert len(result["subtasks"]) == 3
        assert result["task"] == "Implement authentication"
        assert len(result["results"]) == 3
        assert "merged" in result

    @pytest.mark.asyncio
    async def test_decompose_with_merge_fn(self, lead):
        """Test decompose with custom merge function."""
        def custom_merge(results):
            return f"Custom merged {len(results)} agents"

        result = await lead.decompose_and_parallel(
            task="Test task",
            agents=["agent-a", "agent-b"],
            merge_fn=custom_merge,
        )
        assert "Custom merged 2 agents" in result["merged"]

    @pytest.mark.asyncio
    async def test_decompose_default_merge(self, lead):
        """Test decompose with default merge concatenates responses."""
        result = await lead.decompose_and_parallel(
            task="Test task",
            agents=["agent-a"],
        )
        # Default merge should contain agent references
        assert "agent-a" in result["merged"]

    @pytest.mark.asyncio
    async def test_decompose_cancellation(self, lead):
        """Test decompose stops on cancellation."""
        from agentic_ai.agents.lead import CancellationToken
        token = CancellationToken()
        token.cancel()
        result = await lead.decompose_and_parallel(
            task="Test",
            agents=["agent-a", "agent-b"],
            cancellation_token=token,
        )
        # No results since cancelled before start
        assert len(result["results"]) == 0


class TestDecomposeTask:
    """Test the _decompose_task helper."""

    def test_decompose_task_count(self):
        """Test that decompose generates correct number of subtasks."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        subtasks = agent._decompose_task("Implement auth", 3)
        assert len(subtasks) == 3

    def test_decompose_task_five(self):
        """Test decompose with five agents."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        subtasks = agent._decompose_task("Big project", 5)
        assert len(subtasks) == 5

    def test_decompose_task_content(self):
        """Test decompose subtasks contain original task."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        subtasks = agent._decompose_task("Audit system", 3)
        for subtask in subtasks:
            assert "Audit system" in subtask


class TestDefaultSelector:
    """Test the _default_selector helper."""

    def test_default_selector_security(self):
        """Test keyword matching for security."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent._default_selector(
            ["security-agent", "finance-agent"],
            "Check for security vulnerabilities"
        )
        assert result == "security-agent"

    def test_default_selector_compliance(self):
        """Test keyword matching for compliance."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent._default_selector(
            ["security-agent", "compliance-team"],
            "Review compliance policy"
        )
        assert result == "compliance-team"

    def test_default_selector_fallback(self):
        """Test fallback to first agent."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent._default_selector(
            ["agent-x", "agent-y"],
            "Something random"
        )
        assert result == "agent-x"

    def test_default_selector_empty_agents(self):
        """Test with empty agent list."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent._default_selector([], "Any prompt")
        assert result == ""


class TestDefaultMerge:
    """Test the _default_merge helper."""

    def test_default_merge_concatenates(self):
        """Test that default merge concatenates responses."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        results = {
            "agent-a": {"subtask": "t1", "response": "Response A"},
            "agent-b": {"subtask": "t2", "response": "Response B"},
        }
        merged = agent._default_merge(results)
        assert "Agent agent-a: Response A" in merged
        assert "Agent agent-b: Response B" in merged

    def test_default_merge_empty(self):
        """Test merge with empty results."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        merged = agent._default_merge({})
        assert merged == ""

    def test_default_merge_missing_response(self):
        """Test merge when response key is missing."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        results = {
            "agent-a": {"subtask": "t1"},  # no "response" key
        }
        merged = agent._default_merge(results)
        assert "agent-a" in merged


class TestRequestApproval:
    """Test the request_approval method."""

    @pytest.mark.asyncio
    async def test_request_approval_pending(self):
        """Test approval request returns pending status."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = await agent.request_approval("agent-a", "delete_records")
        assert result["agent_id"] == "agent-a"
        assert result["action"] == "delete_records"
        assert result["status"] == "pending_approval"
        assert result["approved"] is None

    @pytest.mark.asyncio
    async def test_request_approval_with_context(self):
        """Test approval request includes context."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        ctx = {"risk": "high", "records": 100}
        result = await agent.request_approval(
            "agent-b", "delete_records", context=ctx
        )
        assert result["context"]["risk"] == "high"
        assert result["context"]["records"] == 100

    @pytest.mark.asyncio
    async def test_request_approval_default_context(self):
        """Test approval request defaults to empty context."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = await agent.request_approval("agent-a", "action")
        assert result["context"] == {}


class TestSpawnConversation:
    """Test the spawn_conversation method."""

    def test_spawn_conversation_structure(self):
        """Test conversation has required fields."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent.spawn_conversation(
            ["agent-a", "agent-b"], "Security review"
        )
        assert "conversation_id" in result
        assert result["topic"] == "Security review"
        assert result["agents"] == ["agent-a", "agent-b"]
        assert result["status"] == "active"

    def test_spawn_conversation_with_context(self):
        """Test conversation includes context."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        ctx = {"priority": "high"}
        result = agent.spawn_conversation(
            ["agent-x"], "Audit", context=ctx
        )
        assert result["context"]["priority"] == "high"

    def test_spawn_conversation_default_context(self):
        """Test conversation defaults to empty context."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent.spawn_conversation(["agent-a"], "Discussion")
        assert result["context"] == {}

    def test_spawn_conversation_has_timestamp(self):
        """Test conversation includes created_at timestamp."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result = agent.spawn_conversation(["agent-a"], "Topic")
        assert "created_at" in result
        # Should be ISO format
        assert "T" in result["created_at"] or "-" in result["created_at"]

    def test_spawn_conversation_unique_ids(self):
        """Test each conversation gets a unique ID."""
        from agentic_ai.agents.lead import LeadAgent
        agent = LeadAgent()
        result1 = agent.spawn_conversation(["agent-a"], "Topic 1")
        result2 = agent.spawn_conversation(["agent-a"], "Topic 2")
        assert result1["conversation_id"] != result2["conversation_id"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])