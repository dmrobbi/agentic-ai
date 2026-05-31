"""Inference server for agent communication and model serving."""
from agentic_ai.infrastructure.utils import utcnow

import os
from dataclasses import dataclass, field
from datetime import datetime
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
    default_model: str = "ollama/llama3"
    model_map: Dict[str, str] = field(default_factory=dict)
    max_tokens: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    batch_size: int = 1
    api_base: str = ""
    api_key: str = ""


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
                 timeout: float = 120.0, config: InferenceConfig = None,
                 stub: bool = False):
        self.stub = stub
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
        self._api_base = os.environ.get("LLM_API_BASE", self.base_url)
        self._api_key = os.environ.get("LLM_API_KEY", "")
        self._default_model = os.environ.get("LLM_DEFAULT_MODEL", self.config.default_model)
        self._model_map: Dict[str, str] = dict(self.config.model_map)

    def load_model(self, model_name: str = "", config: Dict[str, Any] = None) -> Dict[str, Any]:
        model = model_name or self.config.model_name
        self.status = InferenceStatus.LOADING
        self._models[model] = {
            "name": model,
            "loaded_at": utcnow().isoformat(),
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
        model = model or self._default_model
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature
        self._request_history.append({
            "prompt": prompt[:100],
            "model": model,
            "timestamp": utcnow().isoformat(),
        })
        if self.stub:
            return {
                "status": "completed",
                "model": model,
                "response": f"Generated response for: {prompt[:50]}...",
                "tokens_used": min(max_tokens, len(prompt.split()) * 2),
            }
        try:
            import litellm
            response = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                api_base=self._api_base,
                api_key=self._api_key or None,
                timeout=self.timeout,
            )
            return {
                "status": "completed",
                "model": model,
                "response": response.choices[0].message.content,
                "tokens_used": response.usage.total_tokens if response.usage else 0,
            }
        except Exception as e:
            logger.error(f"Inference error: {e}")
            return {"status": "error", "model": model, "response": str(e), "tokens_used": 0}

    def chat(self, messages: List[Dict[str, str]], model: str = "", max_tokens: int = 0,
             temperature: float = 0.0, **kwargs) -> Dict[str, Any]:
        """Chat-style completion with message list."""
        model = model or self._default_model
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature
        if self.stub:
            return {
                "status": "completed",
                "model": model,
                "response": f"Chat response for: {messages[-1]['content'][:50]}...",
                "tokens_used": 10,
            }
        try:
            import litellm
            response = litellm.completion(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                api_base=self._api_base,
                api_key=self._api_key or None,
                timeout=self.timeout,
            )
            return {
                "status": "completed",
                "model": model,
                "response": response.choices[0].message.content,
                "tokens_used": response.usage.total_tokens if response.usage else 0,
            }
        except Exception as e:
            logger.error(f"Chat inference error: {e}")
            return {"status": "error", "model": model, "response": str(e), "tokens_used": 0}

    async def generate_stream(self, prompt: str = "", model: str = "", max_tokens: int = 0,
                               temperature: float = 0.0):
        """Streaming completion — yields tokens."""
        model = model or self._default_model
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature
        if self.stub:
            yield {"token": f"Generated response for: {prompt[:50]}...", "done": True}
            return
        try:
            import litellm
            response = await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                api_base=self._api_base,
                api_key=self._api_key or None,
                stream=True,
                timeout=self.timeout,
            )
            async for chunk in response:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    yield {"token": delta, "done": False}
            yield {"token": "", "done": True}
        except Exception as e:
            yield {"token": f"Error: {e}", "done": True}

    def list_models(self) -> List[ModelInfo]:
        """List available models."""
        if self.stub:
            return [ModelInfo(name="stub-model")]
        try:
            import litellm
            import requests
            resp = requests.get(f"{self._api_base}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = []
                for m in resp.json().get("models", []):
                    models.append(ModelInfo(
                        name=m.get("name", ""),
                        size=m.get("size", 0),
                        parameter_size=m.get("details", {}).get("parameter_size", ""),
                        quantization=m.get("details", {}).get("quantization_level", ""),
                        family=m.get("details", {}).get("family", ""),
                    ))
                return models
        except Exception as e:
            logger.warning(f"Could not list models: {e}")
        return []

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