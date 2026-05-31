"""
Base agent classes and shared types for the agentic-ai framework.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable, Tuple
from collections import OrderedDict
import logging
import asyncio
import secrets
from agentic_ai.infrastructure.utils import utcnow
from agentic_ai.agents.reasoning import ReActLoop, ReActTrace, ReasoningStatus, ReflectionResult
from agentic_ai.agents.memory import TieredMemory
from agentic_ai.guardrails import PIIFilter, ContentPolicyFilter, ToolAllowlist, MaxLengthGuardrail
from agentic_ai.observability.tracing import trace_agent_method
from agentic_ai.protocol.agent_card import AgentCard, AgentCapability


logger = logging.getLogger(__name__)


class Permission(Enum):
    """Agent permission levels."""
    READ_ONLY = "read_only"
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"
    SUPERUSER = "superuser"


class AgentStatus(Enum):
    """Agent status."""
    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    ERROR = "error"
    OFFLINE = "offline"


@dataclass
class AgentMessage:
    """Message passed between agents."""
    sender: str
    recipient: str
    content: str
    msg_type: str = "info"
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Tool:
    """A tool that an agent can use."""
    name: str
    description: str = ""
    func: Callable = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    requires_permission: Permission = Permission.STANDARD

    def __call__(self, **kwargs):
        if self.func:
            return self.func(**kwargs)
        return {"error": f"Tool '{self.name}' has no function"}


class AgentMemory:
    """Backward-compatible memory wrapper around TieredMemory.
    
    Preserves the original AgentMemory interface while delegating
    storage to the new TieredMemory system.
    """

    def __init__(self, max_entries: int = 100):
        self.max_entries = max_entries
        self._tiered = TieredMemory(max_working=max_entries)
        self._entries: OrderedDict = OrderedDict()

    def add(self, role: str, content: str) -> None:
        """Add a conversation entry (role, content)."""
        self._tiered.add_working(role, content)
        # Also store in entries for retrieval
        self.store(role, content)

    def store(self, key: str, value: Any) -> None:
        """Store a value in memory."""
        if key in self._entries:
            del self._entries[key]
        self._entries[key] = {"value": value, "timestamp": datetime.now()}
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve a value from memory."""
        if key in self._entries:
            entry = self._entries[key]
            self._entries.move_to_end(key)
            return entry["value"]
        return None

    def forget(self, key: str) -> bool:
        """Remove a value from memory."""
        if key in self._entries:
            del self._entries[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all memory."""
        self._entries.clear()
        self._tiered.clear_working()

    def keys(self) -> List[str]:
        """List all keys."""
        return list(self._entries.keys())

    @property
    def entries(self) -> OrderedDict:
        """Access to entries dict."""
        return self._entries

    def get_recent(self, count: int = 1) -> List[Dict[str, str]]:
        """Get recent conversation entries."""
        working = self._tiered.working
        return working[-count:]

    def to_messages(self) -> List[Dict[str, str]]:
        """Convert conversation to message list."""
        return self._tiered.to_messages()

    def __len__(self):
        return len(self._entries)


class BaseAgent:
    """Base class for all agents in the framework."""

    agent_type: str = "base"
    permission: Permission = Permission.STANDARD

    def __init__(self, agent_id: str = None, name: str = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 permission: Permission = None, knowledge=None):
        self.agent_id = agent_id or f"{self.agent_type}-{id(self):08x}"
        self.name = name or self.agent_type
        self.inference_engine = inference_engine
        self.state_store = state_store
        self.bus = message_bus
        self.status = AgentStatus.IDLE
        if permission is not None:
            self.permission = permission
        self._tools: Dict[str, Any] = {}
        self._history: List[Dict[str, Any]] = []
        self._memory = AgentMemory()
        self._transparency_log: List[Dict[str, Any]] = []
        self.guardrails: List = []  # Configurable guardrail pipeline
        self.knowledge = knowledge  # Optional AgentKnowledge instance

        # Register default tools
        self._register_default_tools()

    # ============================================
    # Permission helpers
    # ============================================

    def can_read(self, resource: str = "") -> bool:
        """Check if agent has read permission."""
        return self.permission.value in (
            Permission.READ_ONLY.value,
            Permission.STANDARD.value,
            Permission.ELEVATED.value,
            Permission.ADMIN.value,
            Permission.SUPERUSER.value,
        )

    def can_write(self, resource: str = "") -> bool:
        """Check if agent has write permission."""
        return self.permission.value not in (Permission.READ_ONLY.value,)

    def can_create_project(self) -> bool:
        """Check if agent can create projects."""
        return self.permission.value in (
            Permission.ADMIN.value,
            Permission.SUPERUSER.value,
        )

    def can_manage_agents(self) -> bool:
        """Check if agent can manage other agents."""
        return self.permission.value in (
            Permission.ADMIN.value,
            Permission.SUPERUSER.value,
        )

    def register_tool(self, tool: Tool) -> None:
        """Register a tool with the agent."""
        self._tools[tool.name] = tool

    def get_transparency_log(self) -> List[Dict[str, Any]]:
        """Get the transparency log entries."""
        return list(self._transparency_log)

    def _register_default_tools(self):
        """Register default tools available to all agents."""
        self._tools["get_status"] = self.get_status
        self._tools["list_tools"] = lambda: {"tools": list(self._tools.keys())}
        self._tools["send_message"] = self.send_message

    def _generate_id(self, prefix: str) -> str:
        """Generate a unique ID with the given prefix."""
        timestamp = utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = secrets.token_hex(4)
        return f"{prefix}-{timestamp}-{random_suffix}"

    @staticmethod
    def generate_id(prefix: str) -> str:
        """Generate a unique ID with the given prefix (static version)."""
        timestamp = utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = secrets.token_hex(4)
        return f"{prefix}-{timestamp}-{random_suffix}"

    @property
    def tools(self):
        return self._tools

    @tools.setter
    def tools(self, value):
        """Allow setting tools (e.g., from subclasses like KaliAgent)."""
        if isinstance(value, dict):
            self._tools = value
        elif isinstance(value, list):
            self._tools = {t.name if hasattr(t, 'name') else str(t): t for t in value}
        else:
            self._tools = value

    @property
    def memory(self):
        return self._memory

    @property
    def inference(self):
        """Alias for inference_engine."""
        return self.inference_engine

    @inference.setter
    def inference(self, value):
        """Alias for inference_engine."""
        self.inference_engine = value

    def log(self, action: str, details: Dict[str, Any] = None):
        """Log an action for transparency."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id,
            "event": action,
            "action": action,
            "data": details or {},
            "details": details or {},
        }
        self._transparency_log.append(entry)
        logger.info(f"Agent {self.agent_id}: {action} - {details}")

    def input_guardrail(self, prompt: str) -> Tuple[str, bool]:
        """Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe)."""
        sanitized = prompt
        is_safe = True
        for guardrail in self.guardrails:
            if hasattr(guardrail, 'check'):
                if isinstance(guardrail, (PIIFilter, ContentPolicyFilter, MaxLengthGuardrail)):
                    result = guardrail.check(sanitized)
                    sanitized = result.sanitized
                    if not result.is_safe:
                        is_safe = False
                        logger.warning(f"Input guardrail blocked: {result.reason}")
                        break
        return sanitized, is_safe

    def output_guardrail(self, response: str) -> Tuple[str, bool]:
        """Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe)."""
        sanitized = response
        is_safe = True
        for guardrail in self.guardrails:
            if hasattr(guardrail, 'check'):
                if isinstance(guardrail, (PIIFilter, ContentPolicyFilter, MaxLengthGuardrail)):
                    result = guardrail.check(sanitized)
                    sanitized = result.sanitized
                    if not result.is_safe:
                        is_safe = False
                        logger.warning(f"Output guardrail blocked: {result.reason}")
                        break
        return sanitized, is_safe

    def tool_guardrail(self, tool_name: str, kwargs: dict) -> bool:
        """Check if tool call is permitted. Returns is_allowed."""
        for guardrail in self.guardrails:
            if isinstance(guardrail, ToolAllowlist):
                result = guardrail.check(tool_name, kwargs)
                if not result.is_safe:
                    logger.warning(f"Tool guardrail blocked: {result.reason}")
                    return False
        return True

    @trace_agent_method("think")
    async def think(self, prompt: str, context: Dict[str, Any] = None, response_model=None) -> str:
        """Use LLM inference to reason about something. Optionally validate against a Pydantic model."""
        # Input guardrail
        sanitized, is_safe = self.input_guardrail(prompt)
        if not is_safe:
            return f"Error: Input blocked by guardrail"

        if self.inference_engine:
            try:
                gen = self.inference_engine.generate
                if asyncio.iscoroutinefunction(gen):
                    result = await gen(sanitized, context or {})
                else:
                    result = gen(sanitized, context or {})
            except Exception as e:
                logger.error(f"Inference failed: {e}")
                return f"Error: {e}"
        else:
            result = "Generated response"

        # Output guardrail
        result, is_safe = self.output_guardrail(result)
        if not is_safe:
            return f"Error: Output blocked by guardrail"
        # If response_model requested, try to parse and serialize
        if response_model and result:
            try:
                import json
                parsed = response_model(**json.loads(result))
                return parsed.model_dump_json()
            except (json.JSONDecodeError, ValueError, TypeError):
                pass  # Return raw result if parsing fails
        return result

    @trace_agent_method("call_tool")
    async def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Call a tool by name with keyword arguments."""
        # Tool guardrail
        if not self.tool_guardrail(tool_name, kwargs):
            return {"error": f"Tool '{tool_name}' blocked by guardrail"}

        if tool_name not in self._tools:
            return {"error": f"Tool '{tool_name}' not found", "available_tools": list(self._tools.keys())}
        try:
            tool = self._tools[tool_name]
            if isinstance(tool, Tool):
                result = tool(**kwargs)
            elif callable(tool):
                result = tool(**kwargs)
            else:
                result = tool
            if result is None:
                result = {"status": "ok"}
            elif isinstance(result, dict):
                pass
            else:
                result = {"status": "ok", "result": result}
            return result
        except Exception as e:
            logger.error(f"Tool '{tool_name}' failed: {e}")
            return {"error": str(e), "tool": tool_name}

    @trace_agent_method("send_message")
    def send_message(self, recipient: str = "", content: str = "", msg_type: str = "info", **kwargs):
        """Send a message to another agent."""
        # Output guardrail — log warning but still send
        sanitized, is_safe = self.output_guardrail(content)
        if not is_safe:
            logger.warning(f"Output guardrail warning on send_message: content flagged but still sent")

        if self.bus:
            msg = AgentMessage(
                sender=self.agent_id,
                recipient=recipient,
                content=sanitized,
                msg_type=msg_type,
            )
            self.bus.publish(msg)
        self._history.append({"action": "send_message", "to": recipient, "content": sanitized})

    def receive_message(self, message: AgentMessage):
        """Receive a message from another agent."""
        self._history.append({"action": "receive_message", "from": message.sender, "content": message.content})

    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "name": self.name,
            "status": self.status.value,
            "permission": self.permission.value,
            "tools": list(self._tools.keys()),
        }

    async def process_message(self, message):
        """Process an incoming message. Override in subclasses."""
        return None

    async def reason(self, prompt: str, context: Dict[str, Any] = None,
                     max_iterations: int = 5) -> Dict[str, Any]:
        """Iterative ReAct reasoning loop: think→act→observe."""
        loop = ReActLoop(max_iterations=max_iterations)
        trace = ReActTrace()

        current_prompt = prompt
        for i in range(max_iterations):
            # Think
            thought_text = await self.think(
                loop.format_prompt(current_prompt, trace, context),
                context or {}
            )

            # Parse step
            step = loop.parse_step(thought_text, i + 1)
            trace.add_step(step)

            # Check if finished
            if loop.is_finished(step):
                trace.final_answer = step.action_input.get("final_answer", step.thought) if step.action_input else step.thought
                trace.status = ReasoningStatus.FINISHED
                break

            # Act — execute tool if specified
            if step.action and step.action != loop.finish_keyword:
                try:
                    result = await self.call_tool(step.action, **(step.action_input or {}))
                    observation = str(result)
                except Exception as e:
                    observation = f"Error executing {step.action}: {e}"

                step.observation = observation
                step.status = ReasoningStatus.OBSERVING
        else:
            # Max iterations reached
            trace.status = ReasoningStatus.FAILED
            trace.final_answer = trace.steps[-1].thought if trace.steps else "Max iterations reached"

        return trace.to_dict()

    async def reflect(self, response: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Self-critique: evaluate response quality and suggest improvements."""
        reflection_prompt = f"""Evaluate the following response on a scale of 0.0 to 1.0.
Provide a score, critique, and improved version if applicable.

Response to evaluate:
{response}

Context: {context or {}}

Format your response as:
Score: <float between 0.0 and 1.0>
Critique: <what could be improved>
Improved: <better version of the response, or "N/A" if good enough>"""

        result = await self.think(reflection_prompt, context or {})

        # Parse reflection
        score = 0.5
        critique = ""
        improved = None

        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("Score:"):
                try:
                    score = float(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("Critique:"):
                critique = line.split(":", 1)[1].strip()
            elif line.startswith("Improved:"):
                improved = line.split(":", 1)[1].strip()
                if improved == "N/A":
                    improved = None

        return ReflectionResult(score=score, critique=critique, improved_response=improved).to_dict()

    def get_agent_card(self) -> AgentCard:
        """Generate an A2A-compatible agent card describing this agent."""
        capabilities = []
        for tool_name, tool in self._tools.items():
            if callable(tool):
                # Extract tool info
                cap = AgentCapability(
                    name=tool_name,
                    description=getattr(tool, '__doc__', '') or '',
                    input_schema=getattr(tool, 'input_schema', {}),
                    output_schema=getattr(tool, 'output_schema', {}),
                )
                capabilities.append(cap)
        
        return AgentCard(
            name=f"{self.agent_type}_agent",
            description=f"{self.agent_type} agent with {len(self._tools)} tools",
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            capabilities=capabilities,
            permissions=[self.permission.value] if hasattr(self.permission, 'value') else [str(self.permission)],
            metadata={"tools": list(self._tools.keys())},
        )

    @trace_agent_method("perform_task")
    async def perform_task(self, task_type: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform a task. Override in subclasses."""
        return {"status": "done", "task_type": task_type}