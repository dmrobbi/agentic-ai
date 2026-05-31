"""ReAct reasoning loop for agent decision-making."""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum


class ReasoningStatus(str, Enum):
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    FINISHED = "finished"
    FAILED = "failed"


@dataclass
class ReActStep:
    """A single step in the ReAct reasoning loop."""
    step_number: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None
    observation: Optional[str] = None
    status: ReasoningStatus = ReasoningStatus.THINKING


@dataclass
class ReActTrace:
    """Complete trace of a ReAct reasoning session."""
    steps: List[ReActStep] = field(default_factory=list)
    final_answer: Optional[str] = None
    status: ReasoningStatus = ReasoningStatus.THINKING
    iterations_used: int = 0

    def add_step(self, step: ReActStep) -> None:
        self.steps.append(step)
        self.iterations_used = len(self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [
                {
                    "step_number": s.step_number,
                    "thought": s.thought,
                    "action": s.action,
                    "action_input": s.action_input,
                    "observation": s.observation,
                    "status": s.status.value,
                }
                for s in self.steps
            ],
            "final_answer": self.final_answer,
            "status": self.status.value,
            "iterations_used": self.iterations_used,
        }


@dataclass
class ReflectionResult:
    """Result of self-reflection on a response."""
    score: float
    critique: str
    improved_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "critique": self.critique,
            "improved_response": self.improved_response,
        }


class ReActLoop:
    """ReAct (Reason+Act) reasoning loop.

    Implements the ReAct pattern from Yao et al., 2023:
    interleaved reasoning and action steps with observation feedback.
    """

    def __init__(self, max_iterations: int = 5, finish_keyword: str = "FINISH"):
        self.max_iterations = max_iterations
        self.finish_keyword = finish_keyword

    def parse_step(self, text: str, step_number: int) -> ReActStep:
        """Parse a ReAct step from LLM text output.

        Expected format:
        Thought: <reasoning>
        Action: <tool_name>
        Action Input: <json_args>

        Or:
        Thought: <reasoning>
        FINISH: <final_answer>
        """
        thought = ""
        action = None
        action_input = None
        observation = None

        lines = text.strip().split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("Thought:"):
                thought = line[len("Thought:"):].strip()
            elif line.startswith("Action:"):
                action = line[len("Action:"):].strip()
            elif line.startswith("Action Input:"):
                import json
                try:
                    action_input = json.loads(line[len("Action Input:"):].strip())
                except (json.JSONDecodeError, TypeError):
                    action_input = {"raw": line[len("Action Input:"):].strip()}
            elif line.startswith(self.finish_keyword + ":") or line.startswith(self.finish_keyword):
                # This is the final answer
                final_text = line[len(self.finish_keyword):].strip().lstrip(":").strip()
                return ReActStep(
                    step_number=step_number,
                    thought=thought or final_text,
                    action=self.finish_keyword,
                    action_input={"final_answer": final_text},
                    status=ReasoningStatus.FINISHED,
                )
            elif line.startswith("Observation:"):
                observation = line[len("Observation:"):].strip()

        if action:
            status = ReasoningStatus.ACTING
        elif thought:
            status = ReasoningStatus.THINKING
        else:
            status = ReasoningStatus.FAILED

        return ReActStep(
            step_number=step_number,
            thought=thought,
            action=action,
            action_input=action_input,
            observation=observation,
            status=status,
        )

    def is_finished(self, step: ReActStep) -> bool:
        """Check if the step indicates the loop should finish."""
        return step.action == self.finish_keyword or step.status == ReasoningStatus.FINISHED

    def format_prompt(self, prompt: str, trace: ReActTrace, context: Dict[str, Any] = None) -> str:
        """Format a prompt with ReAct context for the next iteration."""
        parts = [prompt, "", "Follow this format exactly:"]
        parts.append("Thought: <your reasoning>")
        parts.append("Action: <tool_name>  OR  FINISH: <your final answer>")
        parts.append("Action Input: <json arguments for the action>")
        parts.append("")

        if trace.steps:
            parts.append("Previous steps:")
            for step in trace.steps:
                parts.append(f"Thought: {step.thought}")
                if step.action and step.action != self.finish_keyword:
                    parts.append(f"Action: {step.action}")
                    if step.action_input:
                        import json
                        parts.append(f"Action Input: {json.dumps(step.action_input)}")
                if step.observation:
                    parts.append(f"Observation: {step.observation}")
            parts.append("")

        parts.append("Now continue with the next step:")
        return "\n".join(parts)