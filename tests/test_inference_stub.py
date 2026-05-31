"""Tests for InferenceServer stub mode and configuration."""
import os
import pytest

from agentic_ai.infrastructure.inference import InferenceServer, InferenceConfig


class TestStubModeGenerate:
    """Stub mode generate returns expected format."""

    def test_stub_generate_returns_completed_status(self):
        server = InferenceServer(stub=True)
        result = server.generate("test prompt")
        assert result["status"] == "completed"

    def test_stub_generate_returns_model(self):
        server = InferenceServer(stub=True)
        result = server.generate("test prompt", model="custom-model")
        assert result["model"] == "custom-model"

    def test_stub_generate_returns_default_model_when_none_specified(self):
        server = InferenceServer(stub=True)
        result = server.generate("test prompt")
        assert result["model"] == "ollama/llama3"

    def test_stub_generate_returns_stub_response(self):
        server = InferenceServer(stub=True)
        result = server.generate("hello world")
        assert "Generated response for:" in result["response"]
        assert "hello world" in result["response"]

    def test_stub_generate_truncates_long_prompt(self):
        server = InferenceServer(stub=True)
        long_prompt = "x" * 200
        result = server.generate(long_prompt)
        # Stub response shows first 50 chars
        assert result["response"].startswith("Generated response for:")

    def test_stub_generate_tokens_used(self):
        server = InferenceServer(stub=True)
        result = server.generate("hello world")
        assert result["tokens_used"] > 0
        assert isinstance(result["tokens_used"], int)

    def test_stub_generate_records_request_history(self):
        server = InferenceServer(stub=True)
        server.generate("test prompt")
        assert len(server._request_history) == 1
        assert server._request_history[0]["prompt"] == "test prompt"


class TestStubModeChat:
    """Stub mode chat returns expected format."""

    def test_stub_chat_returns_completed_status(self):
        server = InferenceServer(stub=True)
        messages = [{"role": "user", "content": "hello"}]
        result = server.chat(messages)
        assert result["status"] == "completed"

    def test_stub_chat_returns_model(self):
        server = InferenceServer(stub=True)
        messages = [{"role": "user", "content": "hello"}]
        result = server.chat(messages, model="custom-model")
        assert result["model"] == "custom-model"

    def test_stub_chat_returns_stub_response(self):
        server = InferenceServer(stub=True)
        messages = [{"role": "user", "content": "hello there"}]
        result = server.chat(messages)
        assert "Chat response for:" in result["response"]
        assert "hello there" in result["response"]

    def test_stub_chat_tokens_used(self):
        server = InferenceServer(stub=True)
        messages = [{"role": "user", "content": "hello"}]
        result = server.chat(messages)
        assert result["tokens_used"] == 10

    def test_stub_chat_with_multiple_messages_uses_last(self):
        server = InferenceServer(stub=True)
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "what is 2+2"},
        ]
        result = server.chat(messages)
        assert "what is 2+2" in result["response"]


class TestStubModeGenerateStream:
    """Stub mode generate_stream yields tokens."""

    @pytest.mark.asyncio
    async def test_stub_generate_stream_yields_tokens(self):
        server = InferenceServer(stub=True)
        tokens = []
        async for chunk in server.generate_stream("test prompt"):
            tokens.append(chunk)
        assert len(tokens) >= 1
        assert tokens[0]["token"] == "Generated response for: test prompt..."
        assert tokens[0]["done"] is True

    @pytest.mark.asyncio
    async def test_stub_generate_stream_single_chunk(self):
        server = InferenceServer(stub=True)
        chunks = []
        async for chunk in server.generate_stream("hello"):
            chunks.append(chunk)
        # Stub mode should yield exactly one chunk with done=True
        assert len(chunks) == 1
        assert chunks[0]["done"] is True


class TestDefaultModelFromEnvVars:
    """Default model from env vars."""

    def test_default_model_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_DEFAULT_MODEL", "ollama/mistral")
        server = InferenceServer(stub=True)
        assert server._default_model == "ollama/mistral"

    def test_default_model_fallback_when_no_env(self, monkeypatch):
        monkeypatch.delenv("LLM_DEFAULT_MODEL", raising=False)
        server = InferenceServer(stub=True)
        assert server._default_model == "ollama/llama3"

    def test_default_model_used_in_generate(self, monkeypatch):
        monkeypatch.setenv("LLM_DEFAULT_MODEL", "ollama/codellama")
        server = InferenceServer(stub=True)
        result = server.generate("test")
        assert result["model"] == "ollama/codellama"


class TestApiBaseFromEnvVars:
    """API base from env vars."""

    def test_api_base_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_API_BASE", "http://custom-host:8080")
        server = InferenceServer(stub=True)
        assert server._api_base == "http://custom-host:8080"

    def test_api_base_fallback_to_base_url(self, monkeypatch):
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        server = InferenceServer(host="10.0.0.117", port=11434, stub=True)
        assert server._api_base == "http://10.0.0.117:11434"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")
        server = InferenceServer(stub=True)
        assert server._api_key == "sk-test-key"

    def test_api_key_defaults_empty(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        server = InferenceServer(stub=True)
        assert server._api_key == ""


class TestConfigDefaults:
    """Config defaults."""

    def test_inference_config_default_model(self):
        config = InferenceConfig()
        assert config.default_model == "ollama/llama3"

    def test_inference_config_max_tokens(self):
        config = InferenceConfig()
        assert config.max_tokens == 2048

    def test_inference_config_temperature(self):
        config = InferenceConfig()
        assert config.temperature == 0.7

    def test_inference_config_top_p(self):
        config = InferenceConfig()
        assert config.top_p == 0.9

    def test_inference_config_batch_size(self):
        config = InferenceConfig()
        assert config.batch_size == 1

    def test_inference_config_model_map_default(self):
        config = InferenceConfig()
        assert config.model_map == {}

    def test_inference_config_model_map_custom(self):
        config = InferenceConfig(model_map={"developer": "ollama/codellama"})
        assert config.model_map == {"developer": "ollama/codellama"}

    def test_inference_config_api_base_default(self):
        config = InferenceConfig()
        assert config.api_base == ""

    def test_inference_config_api_key_default(self):
        config = InferenceConfig()
        assert config.api_key == ""

    def test_inference_config_custom_values(self):
        config = InferenceConfig(
            default_model="ollama/mistral",
            max_tokens=4096,
            temperature=0.5,
            api_base="http://localhost:8080",
            api_key="sk-test",
        )
        assert config.default_model == "ollama/mistral"
        assert config.max_tokens == 4096
        assert config.temperature == 0.5
        assert config.api_base == "http://localhost:8080"
        assert config.api_key == "sk-test"


class TestListModelsStub:
    """Stub mode list_models."""

    def test_stub_list_models_returns_stub_model(self):
        server = InferenceServer(stub=True)
        models = server.list_models()
        assert len(models) == 1
        assert models[0].name == "stub-model"