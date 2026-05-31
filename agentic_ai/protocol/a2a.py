"""
A2A (Agent-to-Agent) Protocol
===================================

A2A-compatible message types for inter-agent task communication,
with bidirectional conversion to/from ACP messages.
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field
import uuid
import json
from agentic_ai.infrastructure.utils import utcnow

if TYPE_CHECKING:
    from agentic_ai.protocol.acp import ACPMessage


@dataclass
class A2ATaskMessage:
    """A2A-compatible task message."""

    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_card: Optional[Dict[str, Any]] = None  # AgentCard dict
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # maps to TaskStatus
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "agent_card": self.agent_card,
            "payload": self.payload,
            "status": self.status,
            "artifacts": self.artifacts,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_acp(cls, acp_message: "ACPMessage") -> "A2ATaskMessage":
        """Convert from ACP message to A2A format.

        Maps ACPMessage fields to A2A payload:
        - subject → payload["subject"]
        - body → payload["content"]
        - message_type → payload["message_type"]
        - created_at → A2A created_at
        """
        return cls(
            task_id=acp_message.message_id,
            payload={
                "subject": acp_message.subject,
                "content": acp_message.body,
                "message_type": acp_message.message_type.value
                if hasattr(acp_message.message_type, "value")
                else str(acp_message.message_type),
            },
            status="pending",
            artifacts=[],
            created_at=acp_message.created_at or utcnow().isoformat(),
        )

    def to_acp(self) -> "ACPMessage":
        """Convert from A2A format back to ACP message.

        Maps A2A payload fields to ACPMessage:
        - payload["content"] → body
        - payload["subject"] → subject
        - payload["message_type"] → message_type
        - task_id → message_id
        - created_at → created_at
        """
        from agentic_ai.protocol.acp import ACPMessage, MessageType

        body = self.payload.get("content", {})
        subject = self.payload.get("subject", "")
        msg_type_str = self.payload.get("message_type", "request")
        try:
            msg_type = MessageType(msg_type_str)
        except ValueError:
            msg_type = MessageType.REQUEST
        # Both `type` and `message_type` must be set because ACPMessage.__post_init__
        # syncs them: if they differ, `type` overwrites `message_type`.
        return ACPMessage(
            message_id=self.task_id,
            sender="a2a",
            recipient="",
            subject=subject,
            body=body if isinstance(body, dict) else {"_raw": body},
            type=msg_type,
            message_type=msg_type,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "A2ATaskMessage":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_json(cls, json_str: str) -> "A2ATaskMessage":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))