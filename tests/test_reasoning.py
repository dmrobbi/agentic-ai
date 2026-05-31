"""
Tests for ReAct reasoning loop and self-reflection.
===================================================

Unit tests for agentic_ai.agents.reasoning and BaseAgent.reason/reflect.
"""

import pytest
import sys
import json
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
from agentic_ai.agents.reasoning import (
    ReasoningStatus,
    ReActStep,
    ReActTrace,
    ReflectionResult,
    ReActLoop,
)
from agentic_ai.agents.base import BaseAgent

sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================
# ReActStep tests
# ============================================================


class TestReActStep:
    """Tests for ReActStep dataclass."""

    def test_create_basic_step(self):
        step = ReActStep(step_number=1, thought="I need to search")
        assert step.step_number == 1
        assert step.thought == "I need to search"
        assert step.action is None
        assert step.action_input is None
        assert step.observation is None
        assert step.status == ReasoningStatus.THINKING

    def test_create_step_with_action(self):
        step = ReActStep(
            step_number=2,
            thought="Let me look it up",
            action="search",
            action_input={"query": "test"},
            status=ReasoningStatus.ACTING,
        )
        assert step.action == "search"
        assert step.action_input == {"query": "test"}
        assert step.status == ReasoningStatus.ACTING

    def test_create_step_with_observation(self):
        step = ReActStep(
            step_number=3,
            thought="Got results",
            action="search",
            observation="Result found",
            status=ReasoningStatus.OBSERVING,
        )
        assert step.observation == "Result found"
        assert step.status == ReasoningStatus.OBSERVING

    def test_create_finished_step(self):
        step = ReActStep(
            step_number=4,
            thought="I have the answer",
            action="FINISH",
            action_input={"final_answer": "42"},
            status=ReasoningStatus.FINISHED,
        )
        assert step.action == "FINISH"
        assert step.status == ReasoningStatus.FINISHED

    def test_create_failed_step(self):
        step = ReActStep(
            step_number=5,
            thought="",
            status=ReasoningStatus.FAILED,
        )
        assert step.status == ReasoningStatus.FAILED


# ============================================================
# ReActTrace tests
# ============================================================


class TestReActTrace:
    """Tests for ReActTrace dataclass."""

    def test_create_empty_trace(self):
        trace = ReActTrace()
        assert trace.steps == []
        assert trace.final_answer is None
        assert trace.status == ReasoningStatus.THINKING
        assert trace.iterations_used == 0

    def test_add_step(self):
        trace = ReActTrace()
        step1 = ReActStep(step_number=1, thought="Think 1")
        trace.add_step(step1)
        assert len(trace.steps) == 1
        assert trace.iterations_used == 1

        step2 = ReActStep(step_number=2, thought="Think 2")
        trace.add_step(step2)
        assert len(trace.steps) == 2
        assert trace.iterations_used == 2

    def test_to_dict_empty(self):
        trace = ReActTrace()
        d = trace.to_dict()
        assert d["steps"] == []
        assert d["final_answer"] is None
        assert d["status"] == "thinking"
        assert d["iterations_used"] == 0

    def test_to_dict_with_steps(self):
        trace = ReActTrace()
        step = ReActStep(
            step_number=1,
            thought="I need info",
            action="search",
            action_input={"query": "python"},
            observation="Found docs",
            status=ReasoningStatus.OBSERVING,
        )
        trace.add_step(step)
        trace.final_answer = "Python is great"
        trace.status = ReasoningStatus.FINISHED

        d = trace.to_dict()
        assert len(d["steps"]) == 1
        s = d["steps"][0]
        assert s["step_number"] == 1
        assert s["thought"] == "I need info"
        assert s["action"] == "search"
        assert s["action_input"] == {"query": "python"}
        assert s["observation"] == "Found docs"
        assert s["status"] == "observing"
        assert d["final_answer"] == "Python is great"
        assert d["status"] == "finished"
        assert d["iterations_used"] == 1

    def test_to_dict_multiple_steps(self):
        trace = ReActTrace()
        for i in range(3):
            trace.add_step(ReActStep(step_number=i + 1, thought=f"Step {i+1}"))
        d = trace.to_dict()
        assert len(d["steps"]) == 3
        assert d["iterations_used"] == 3


# ============================================================
# ReflectionResult tests
# ============================================================


class TestReflectionResult:
    """Tests for ReflectionResult dataclass."""

    def test_create_basic(self):
        result = ReflectionResult(score=0.8, critique="Could be more concise")
        assert result.score == 0.8
        assert result.critique == "Could be more concise"
        assert result.improved_response is None

    def test_create_with_improved(self):
        result = ReflectionResult(
            score=0.5, critique="Too vague", improved_response="A better response"
        )
        assert result.improved_response == "A better response"

    def test_to_dict(self):
        result = ReflectionResult(score=0.9, critique="Good", improved_response="Better")
        d = result.to_dict()
        assert d["score"] == 0.9
        assert d["critique"] == "Good"
        assert d["improved_response"] == "Better"

    def test_to_dict_no_improvement(self):
        result = ReflectionResult(score=0.95, critique="Excellent")
        d = result.to_dict()
        assert d["improved_response"] is None


# ============================================================
# ReActLoop.parse_step tests
# ============================================================


class TestReActLoopParseStep:
    """Tests for ReActLoop.parse_step()."""

    def test_parse_thought_and_action(self):
        loop = ReActLoop()
        text = "Thought: I should search for info\nAction: search\nAction Input: {\"query\": \"test\"}"
        step = loop.parse_step(text, 1)
        assert step.step_number == 1
        assert step.thought == "I should search for info"
        assert step.action == "search"
        assert step.action_input == {"query": "test"}
        assert step.status == ReasoningStatus.ACTING

    def test_parse_thought_only(self):
        loop = ReActLoop()
        text = "Thought: Let me think about this"
        step = loop.parse_step(text, 2)
        assert step.thought == "Let me think about this"
        assert step.action is None
        assert step.status == ReasoningStatus.THINKING

    def test_parse_finish_keyword(self):
        loop = ReActLoop()
        text = "Thought: I have the answer\nFINISH: The answer is 42"
        step = loop.parse_step(text, 3)
        assert step.action == "FINISH"
        assert step.action_input == {"final_answer": "The answer is 42"}
        assert step.status == ReasoningStatus.FINISHED

    def test_parse_finish_with_colon(self):
        loop = ReActLoop()
        text = "FINISH: Final result here"
        step = loop.parse_step(text, 1)
        assert step.action == "FINISH"
        assert step.action_input == {"final_answer": "Final result here"}
        assert step.status == ReasoningStatus.FINISHED

    def test_parse_malformed_action_input(self):
        loop = ReActLoop()
        text = "Thought: Try something\nAction: lookup\nAction Input: not valid json"
        step = loop.parse_step(text, 1)
        assert step.action == "lookup"
        assert step.action_input == {"raw": "not valid json"}
        assert step.status == ReasoningStatus.ACTING

    def test_parse_empty_text(self):
        loop = ReActLoop()
        step = loop.parse_step("", 1)
        assert step.status == ReasoningStatus.FAILED
        assert step.thought == ""

    def test_parse_observation(self):
        loop = ReActLoop()
        text = "Thought: Got results\nObservation: Search returned 3 items"
        step = loop.parse_step(text, 1)
        assert step.observation == "Search returned 3 items"

    def test_parse_custom_finish_keyword(self):
        loop = ReActLoop(finish_keyword="DONE")
        text = "Thought: All done\nDONE: The result"
        step = loop.parse_step(text, 1)
        assert step.action == "DONE"
        assert step.action_input == {"final_answer": "The result"}
        assert step.status == ReasoningStatus.FINISHED

    def test_parse_multiline_with_whitespace(self):
        loop = ReActLoop()
        text = """  Thought:   Need to check  
  Action:   verify  
  Action Input:   {"x": 1}  """
        step = loop.parse_step(text, 1)
        assert step.thought == "Need to check"
        assert step.action == "verify"
        assert step.action_input == {"x": 1}


# ============================================================
# ReActLoop.is_finished tests
# ============================================================


class TestReActLoopIsFinished:
    """Tests for ReActLoop.is_finished()."""

    def test_finished_action(self):
        loop = ReActLoop()
        step = ReActStep(step_number=1, thought="Done", action="FINISH", status=ReasoningStatus.FINISHED)
        assert loop.is_finished(step) is True

    def test_not_finished_action(self):
        loop = ReActLoop()
        step = ReActStep(step_number=1, thought="Working", action="search", status=ReasoningStatus.ACTING)
        assert loop.is_finished(step) is False

    def test_finished_by_status(self):
        loop = ReActLoop()
        step = ReActStep(step_number=1, thought="Done", action="FINISH", status=ReasoningStatus.FINISHED)
        assert loop.is_finished(step) is True

    def test_not_finished_thinking(self):
        loop = ReActLoop()
        step = ReActStep(step_number=1, thought="Hmm", status=ReasoningStatus.THINKING)
        assert loop.is_finished(step) is False

    def test_custom_finish_keyword(self):
        loop = ReActLoop(finish_keyword="DONE")
        step = ReActStep(step_number=1, thought="Done", action="DONE", status=ReasoningStatus.FINISHED)
        assert loop.is_finished(step) is True


# ============================================================
# ReActLoop.format_prompt tests
# ============================================================


class TestReActLoopFormatPrompt:
    """Tests for ReActLoop.format_prompt()."""

    def test_format_prompt_empty_trace(self):
        loop = ReActLoop()
        trace = ReActTrace()
        prompt = loop.format_prompt("Solve this problem", trace)
        assert "Solve this problem" in prompt
        assert "Thought: <your reasoning>" in prompt
        assert "FINISH:" in prompt
        assert "Now continue with the next step:" in prompt

    def test_format_prompt_with_trace(self):
        loop = ReActLoop()
        trace = ReActTrace()
        step = ReActStep(
            step_number=1,
            thought="I should search",
            action="search",
            action_input={"query": "test"},
            observation="Found results",
        )
        trace.add_step(step)

        prompt = loop.format_prompt("Find the answer", trace)
        assert "Previous steps:" in prompt
        assert "I should search" in prompt
        assert "Action: search" in prompt
        assert "Found results" in prompt

    def test_format_prompt_with_context(self):
        loop = ReActLoop()
        trace = ReActTrace()
        prompt = loop.format_prompt("Help me", trace, context={"user": "test"})
        assert "Help me" in prompt
        assert "Thought: <your reasoning>" in prompt

    def test_format_prompt_finish_step_not_included(self):
        loop = ReActLoop()
        trace = ReActTrace()
        step = ReActStep(
            step_number=1,
            thought="Done thinking",
            action="FINISH",
            action_input={"final_answer": "42"},
        )
        trace.add_step(step)
        prompt = loop.format_prompt("What is the answer?", trace)
        # FINISH step's action should not be printed (skipped by `!= self.finish_keyword` check)
        assert "Thought: Done thinking" in prompt


# ============================================================
# BaseAgent.reason tests (mocked)
# ============================================================


def _make_test_agent(inference_generate_fn=None):
    """Helper: create a concrete BaseAgent subclass with mocked inference."""
    class TestAgent(BaseAgent):
        agent_type = "test"

        async def process_message(self, message):
            return None

        async def perform_task(self, task_type, payload=None):
            return {"status": "done"}

    agent = TestAgent()

    mock_inference = MagicMock()
    if inference_generate_fn:
        mock_inference.generate = inference_generate_fn
    else:
        # Default: return a generic response
        mock_inference.generate = MagicMock(return_value="Thought: Thinking...")

    agent.inference_engine = mock_inference
    return agent


class TestBaseAgentReason:
    """Tests for BaseAgent.reason() method."""

    @pytest.mark.asyncio
    async def test_reason_single_finish(self):
        """Agent reasons one step and finishes immediately."""
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Thought: I know the answer\nFINISH: The answer is 42"
            )
        )
        result = await agent.reason("What is the meaning of life?")
        assert result["status"] == "finished"
        assert result["final_answer"] == "The answer is 42"
        assert result["iterations_used"] == 1

    @pytest.mark.asyncio
    async def test_reason_with_tool_call(self):
        """Agent reasons, calls a tool, observes, then finishes."""
        agent = _make_test_agent()

        # Register a tool the agent can call
        from agentic_ai.agents.base import Tool
        agent.register_tool(Tool(
            name="calculator",
            description="Does math",
            func=lambda **kwargs: {"result": 42},
        ))

        # First call: think+act, second call: observe+finish
        call_count = [0]
        def generate_side_effect(prompt, context=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return 'Thought: Let me calculate\nAction: calculator\nAction Input: {"expr": "6*7"}'
            else:
                return "Thought: Got it\nFINISH: 42"

        agent.inference_engine.generate = MagicMock(side_effect=generate_side_effect)

        result = await agent.reason("What is 6*7?")
        assert result["status"] == "finished"
        assert result["final_answer"] == "42"
        assert result["iterations_used"] == 2

    @pytest.mark.asyncio
    async def test_reason_max_iterations(self):
        """Agent hits max iterations without finishing."""
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Thought: Still thinking about it"
            )
        )
        result = await agent.reason("Hard question", max_iterations=3)
        assert result["status"] == "failed"
        assert result["iterations_used"] == 3

    @pytest.mark.asyncio
    async def test_reason_tool_error(self):
        """Agent calls a nonexistent tool, gets error observation."""
        agent = _make_test_agent()
        call_count = [0]
        def generate_side_effect(prompt, context=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return 'Thought: Try a tool\nAction: nonexistent_tool\nAction Input: {}'
            else:
                return "Thought: Tool failed, let me finish\nFINISH: I cannot complete this"

        agent.inference_engine.generate = MagicMock(side_effect=generate_side_effect)
        result = await agent.reason("Do something")
        assert result["status"] == "finished"
        # The observation for nonexistent tool should be recorded
        assert len(result["steps"]) == 2


class TestBaseAgentReflect:
    """Tests for BaseAgent.reflect() method."""

    @pytest.mark.asyncio
    async def test_reflect_parses_score(self):
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Score: 0.8\nCritique: Could be more detailed\nImproved: A more detailed response"
            )
        )
        result = await agent.reflect("Some response")
        assert result["score"] == 0.8
        assert result["critique"] == "Could be more detailed"
        assert result["improved_response"] == "A more detailed response"

    @pytest.mark.asyncio
    async def test_reflect_no_improvement(self):
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Score: 0.95\nCritique: Excellent\nImproved: N/A"
            )
        )
        result = await agent.reflect("Perfect response")
        assert result["score"] == 0.95
        assert result["improved_response"] is None

    @pytest.mark.asyncio
    async def test_reflect_malformed_score(self):
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Score: not a number\nCritique: Okay"
            )
        )
        result = await agent.reflect("Some response")
        # Default score should be 0.5 when parsing fails
        assert result["score"] == 0.5
        assert result["critique"] == "Okay"

    @pytest.mark.asyncio
    async def test_reflect_with_context(self):
        agent = _make_test_agent(
            inference_generate_fn=MagicMock(
                return_value="Score: 0.7\nCritique: Needs context awareness"
            )
        )
        result = await agent.reflect("Some response", context={"task": "analysis"})
        assert result["score"] == 0.7
        assert result["critique"] == "Needs context awareness"