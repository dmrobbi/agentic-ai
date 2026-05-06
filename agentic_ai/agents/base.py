"""
Base agent classes and shared types for the agentic-ai framework.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
from collections import OrderedDict
import logging

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

    def __call__(self, **kwargs):
        if self.func:
            return self.func(**kwargs)
        return {"error": f"Tool '{self.name}' has no function"}


class AgentMemory:
    """Agent memory store with limited capacity."""

    def __init__(self, max_entries: int = 100):
        self.max_entries = max_entries
        self._entries: OrderedDict = OrderedDict()

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

    def keys(self) -> List[str]:
        """List all keys."""
        return list(self._entries.keys())

    def __len__(self):
        return len(self._entries)


class BaseAgent:
    """Base class for all agents in the framework."""

    agent_type: str = "base"
    permission: Permission = Permission.STANDARD

    def __init__(self, agent_id: str = None, name: str = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 permission: Permission = None):
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

        # Register default tools
        self._register_default_tools()

    def _register_default_tools(self):
        """Register default tools available to all agents."""
        self._tools["get_status"] = self.get_status
        self._tools["list_tools"] = lambda: {"tools": list(self._tools.keys())}
        self._tools["send_message"] = self.send_message

    @property
    def tools(self):
        return list(self._tools.keys())

    @property
    def memory(self):
        return self._memory

    def log(self, action: str, details: Dict[str, Any] = None):
        """Log an action for transparency."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id,
            "action": action,
            "details": details or {},
        }
        self._transparency_log.append(entry)
        logger.info(f"Agent {self.agent_id}: {action} - {details}")

    async def think(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Use LLM inference to reason about something."""
        if self.inference_engine:
            try:
                result = await self.inference_engine.generate(prompt, context or {})
                return result
            except Exception as e:
                logger.error(f"Inference failed: {e}")
                return f"Error: {e}"
        return f"Thought about: {prompt}"

    async def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Call a tool by name with keyword arguments."""
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

    def send_message(self, recipient: str = "", content: str = "", msg_type: str = "info", **kwargs):
        """Send a message to another agent."""
        if self.bus:
            msg = AgentMessage(
                sender=self.agent_id,
                recipient=recipient,
                content=content,
                msg_type=msg_type,
            )
            self.bus.publish(msg)
        self._history.append({"action": "send_message", "to": recipient, "content": content})

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

    async def perform_task(self, task_type: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform a task. Override in subclasses."""
        return {"status": "done", "task_type": task_type}