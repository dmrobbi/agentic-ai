"""Agent Card — A2A-compatible agent metadata and capability discovery."""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum
import json


class AgentCardFormat(str, Enum):
    JSON = "json"
    JSON_LD = "json-ld"


@dataclass
class AgentCapability:
    """A single agent capability."""
    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentCard:
    """A2A-compatible agent card describing an agent's identity and capabilities.
    
    Follows the Agent-to-Agent (A2A) protocol specification for agent discovery.
    """
    name: str
    description: str
    version: str = "1.0.0"
    provider: str = "agentic-ai"
    agent_type: str = ""
    agent_id: str = ""
    
    capabilities: List[AgentCapability] = field(default_factory=list)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    
    authentication: Dict[str, Any] = field(default_factory=dict)
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "provider": self.provider,
            "agent_type": self.agent_type,
            "agent_id": self.agent_id,
            "capabilities": [
                {
                    "name": c.name,
                    "description": c.description,
                    "input_schema": c.input_schema,
                    "output_schema": c.output_schema,
                }
                for c in self.capabilities
            ],
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "authentication": self.authentication,
            "endpoints": self.endpoints,
            "permissions": self.permissions,
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_json_ld(self) -> str:
        """Serialize to JSON-LD format for A2A spec compliance."""
        data = self.to_dict()
        data["@context"] = "https://schema.org/Agent"
        data["@type"] = "Agent"
        data["@id"] = self.agent_id or self.name
        return json.dumps(data, indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCard":
        """Deserialize from dictionary."""
        capabilities = [
            AgentCapability(**c) if isinstance(c, dict) else c
            for c in data.pop("capabilities", [])
        ]
        return cls(capabilities=capabilities, **data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "AgentCard":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))