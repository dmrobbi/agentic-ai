"""Inference server for agent communication and model serving."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class InferenceStatus(Enum):
    IDLE = "idle"
    LOADING = "loading"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"


@dataclass
class InferenceConfig:
    model_name: str = "default"
    max_tokens: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    batch_size: int = 1


@dataclass
class ModelInfo:
    """Information about an available model."""
    name: str
    size: int = 0
    parameter_size: str = ""
    quantization: str = ""
    family: str = ""
    capabilities: List[str] = field(default_factory=list)


# Agent type to model family mapping
AGENT_MODEL_PREFERENCES = {
    "developer": ["qwen", "coder", "code"],
    "qa": ["qwen", "coder"],
    "lead": ["llama", "qwen"],
    "sales": ["llama"],
    "finance": ["llama"],
    "sysadmin": ["llama"],
}


class InferenceServer:
    """Manages inference requests for agents."""

    def __init__(self, host: str = "10.0.0.117", port: int = 11434,
                 timeout: float = 120.0, config: InferenceConfig = None):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self.config = config or InferenceConfig()
        self.status = InferenceStatus.IDLE
        self._models: Dict[str, Dict] = {}
        self._available_models: List[ModelInfo] = []
        self._request_history: List[Dict[str, Any]] = []
        self._client = None

    def load_model(self, model_name: str = "", config: Dict[str, Any] = None) -> Dict[str, Any]:
        model = model_name or self.config.model_name
        self.status = InferenceStatus.LOADING
        self._models[model] = {
            "name": model,
            "loaded_at": datetime.now(timezone.utc).isoformat(),
            "config": config or {},
            "status": "ready",
        }
        self.status = InferenceStatus.READY
        return {"status": "loaded", "model": model}

    def get_model_for_agent(self, agent_type: str) -> Optional[str]:
        """Select best model for an agent type based on preferences."""
        preferences = AGENT_MODEL_PREFERENCES.get(agent_type, [])
        if not self._available_models:
            return None
        for pref in preferences:
            for model in self._available_models:
                if pref in model.name.lower() or pref in model.family.lower():
                    return model.name
        return self._available_models[0].name if self._available_models else None

    def generate(self, prompt: str = "", model: str = "", max_tokens: int = 0,
                 temperature: float = 0.0, **kwargs) -> Dict[str, Any]:
        model = model or self.config.model_name
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature
        self._request_history.append({
            "prompt": prompt[:100],
            "model": model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {
            "status": "completed",
            "model": model,
            "response": f"Generated response for: {prompt[:50]}...",
            "tokens_used": min(max_tokens, len(prompt.split()) * 2),
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "base_url": self.base_url,
            "models_loaded": list(self._models.keys()),
            "available_models": [m.name for m in self._available_models],
            "total_requests": len(self._request_history),
        }

    def unload_model(self, model_name: str = "") -> Dict[str, Any]:
        model = model_name or self.config.model_name
        if model in self._models:
            del self._models[model]
            return {"status": "unloaded", "model": model}
        return {"status": "not_found", "model": model}


# Global inference server instance
_inference_server: Optional[InferenceServer] = None


def get_inference_server(config: InferenceConfig = None) -> InferenceServer:
    """Get or create the global inference server instance."""
    global _inference_server
    if _inference_server is None:
        _inference_server = InferenceServer(config=config)
    return _inference_server