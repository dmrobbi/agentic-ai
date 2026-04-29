"""
Base agent classes and shared types for the agentic-ai framework.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class Permission(Enum):
    """Agent permission levels."""
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

    @property
    def tools(self):
        return list(self._tools.keys())

    async def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Call a tool by name with keyword arguments."""
        if tool_name not in self._tools:
            return {"error": f"Tool '{tool_name}' not found", "available_tools": list(self._tools.keys())}
        try:
            tool = self._tools[tool_name]
            if callable(tool):
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

    def send_message(self, recipient: str, content: str, msg_type: str = "info"):
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