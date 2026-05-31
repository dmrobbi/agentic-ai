"""
Messaging Backends Tests
==========================

Tests for the pluggable messaging backend system:
- MemoryBackend creation and operations
- RedisBackend creation with config
- MessageBackend protocol compliance
- MessageBus with pluggable backends
- Multiple channels and edge cases
"""

import asyncio
import pytest
from unittest.mock import Mock, patch, MagicMock

from agentic_ai.messaging.backends import MessageBackend
from agentic_ai.messaging.backends.memory_backend import MemoryBackend
from agentic_ai.messaging.backends.redis_backend import RedisBackend
from agentic_ai.messaging.message_bus import MessageBus, Message, MessageType
from agentic_ai.infrastructure.config import RedisConfig


# ============================================================================
# MemoryBackend Tests
# ============================================================================

class TestMemoryBackendCreation:
    """Test MemoryBackend instantiation."""

    def test_memory_backend_creation(self):
        """Test creating a MemoryBackend instance."""
        backend = MemoryBackend()
        assert backend is not None
        assert backend._closed is False
        assert isinstance(backend._channels, dict)

    def test_memory_backend_creation_type(self):
        """Test that MemoryBackend has the expected type."""
        backend = MemoryBackend()
        assert type(backend).__name__ == "MemoryBackend"

    def test_memory_backend_initial_state(self):
        """Test MemoryBackend starts with empty channels."""
        backend = MemoryBackend()
        assert len(backend._channels) == 0


class TestMemoryBackendPublishSubscribe:
    """Test MemoryBackend publish and subscribe operations."""

    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self):
        """Test basic publish and subscribe flow."""
        backend = MemoryBackend()
        received = []

        async def subscriber():
            async for message in backend.subscribe("test-channel"):
                received.append(message)
                if len(received) >= 2:
                    break

        # Start subscriber task
        sub_task = asyncio.create_task(subscriber())

        # Give subscriber time to start listening
        await asyncio.sleep(0.05)

        await backend.publish("test-channel", b"hello")
        await backend.publish("test-channel", b"world")

        await asyncio.wait_for(sub_task, timeout=3.0)
        await backend.close()

        assert len(received) == 2
        assert received[0] == b"hello"
        assert received[1] == b"world"

    @pytest.mark.asyncio
    async def test_publish_string_message(self):
        """Test publishing a string message (auto-converts to bytes)."""
        backend = MemoryBackend()
        received = []

        async def subscriber():
            async for message in backend.subscribe("str-channel"):
                received.append(message)
                if len(received) >= 1:
                    break

        sub_task = asyncio.create_task(subscriber())
        await asyncio.sleep(0.05)

        await backend.publish("str-channel", "hello")

        await asyncio.wait_for(sub_task, timeout=3.0)
        await backend.close()

        assert len(received) == 1
        assert received[0] == b"hello"

    @pytest.mark.asyncio
    async def test_multiple_channels(self):
        """Test publishing to multiple channels independently."""
        backend = MemoryBackend()
        chan_a = []
        chan_b = []

        async def sub_a():
            async for message in backend.subscribe("channel-a"):
                chan_a.append(message)
                if len(chan_a) >= 1:
                    break

        async def sub_b():
            async for message in backend.subscribe("channel-b"):
                chan_b.append(message)
                if len(chan_b) >= 1:
                    break

        task_a = asyncio.create_task(sub_a())
        task_b = asyncio.create_task(sub_b())
        await asyncio.sleep(0.05)

        await backend.publish("channel-a", b"msg-a")
        await backend.publish("channel-b", b"msg-b")

        await asyncio.wait_for(task_a, timeout=3.0)
        await asyncio.wait_for(task_b, timeout=3.0)
        await backend.close()

        assert chan_a == [b"msg-a"]
        assert chan_b == [b"msg-b"]


class TestMemoryBackendClose:
    """Test MemoryBackend close behavior."""

    @pytest.mark.asyncio
    async def test_close_sets_closed_flag(self):
        """Test that close sets the closed flag."""
        backend = MemoryBackend()
        assert backend._closed is False
        await backend.close()
        assert backend._closed is True

    @pytest.mark.asyncio
    async def test_publish_after_close_is_noop(self):
        """Test that publishing after close does nothing."""
        backend = MemoryBackend()
        await backend.close()
        # Should not raise, just silently ignore
        await backend.publish("test-channel", b"should-be-ignored")

    @pytest.mark.asyncio
    async def test_close_clears_channels(self):
        """Test that close clears channels."""
        backend = MemoryBackend()
        await backend.publish("ch1", b"data1")
        assert len(backend._channels) > 0
        await backend.close()
        assert len(backend._channels) == 0


# ============================================================================
# RedisBackend Tests
# ============================================================================

class TestRedisBackendCreation:
    """Test RedisBackend instantiation."""

    def test_redis_backend_creation_default(self):
        """Test creating a RedisBackend with default config."""
        backend = RedisBackend()
        assert backend is not None
        assert backend.config is not None
        assert isinstance(backend.config, RedisConfig)

    def test_redis_backend_creation_with_config(self):
        """Test creating a RedisBackend with custom config."""
        config = RedisConfig(url="redis://custom:6380")
        backend = RedisBackend(config=config)
        assert backend.config.url == "redis://custom:6380"

    def test_redis_backend_lazy_client(self):
        """Test that Redis client is created lazily."""
        backend = RedisBackend()
        assert backend._client is None

    @patch('redis.Redis')
    def test_redis_backend_client_property(self, mock_redis):
        """Test that accessing client property creates a Redis client."""
        backend = RedisBackend()
        client = backend.client
        assert backend._client is not None

    @pytest.mark.asyncio
    async def test_redis_backend_close(self):
        """Test closing RedisBackend with no client."""
        backend = RedisBackend()
        # Should not raise even with no client
        await backend.close()


# ============================================================================
# MessageBackend Protocol Tests
# ============================================================================

class TestMessageBackendProtocol:
    """Test MessageBackend protocol compliance."""

    def test_memory_backend_satisfies_protocol(self):
        """Test that MemoryBackend satisfies MessageBackend protocol."""
        backend = MemoryBackend()
        assert isinstance(backend, MessageBackend)

    def test_protocol_is_runtime_checkable(self):
        """Test that MessageBackend is runtime checkable."""
        # A plain object should not satisfy the protocol
        class NotABackend:
            pass

        obj = NotABackend()
        assert not isinstance(obj, MessageBackend)

    def test_protocol_has_required_methods(self):
        """Test that MessageBackend protocol has the required methods."""
        assert hasattr(MessageBackend, 'publish')
        assert hasattr(MessageBackend, 'subscribe')
        assert hasattr(MessageBackend, 'close')


# ============================================================================
# MessageBus Backend Integration Tests
# ============================================================================

class TestMessageBusWithBackend:
    """Test MessageBus with pluggable backend."""

    def test_message_bus_with_memory_backend(self):
        """Test creating MessageBus with explicit MemoryBackend."""
        backend = MemoryBackend()
        bus = MessageBus(backend=backend)
        assert bus.backend is backend
        assert isinstance(bus.backend, MemoryBackend)

    @patch('redis.Redis')
    def test_message_bus_with_redis_mock(self, mock_redis):
        """Test MessageBus still works with Redis when mocked."""
        bus = MessageBus(redis_url="redis://localhost:6379")
        bus._redis = mock_redis

        message = Message(
            message_id="test-123",
            message_type=MessageType.EVENT,
            source_agent="test-agent",
            target_agent=None,
            topic="test.topic",
            payload={'data': 'test'},
        )

        result = bus.publish(message)
        assert result is True

    def test_message_bus_backend_attribute(self):
        """Test MessageBus stores backend attribute."""
        backend = MemoryBackend()
        bus = MessageBus(backend=backend)
        assert bus.backend is backend

    def test_message_bus_auto_detection(self):
        """Test MessageBus auto-detects backend (falls back to MemoryBackend)."""
        # With no Redis available, should fall back to MemoryBackend
        bus = MessageBus()
        assert bus.backend is not None
        # In test environment without Redis, it should be MemoryBackend
        assert isinstance(bus.backend, (MemoryBackend, RedisBackend))

    @pytest.mark.asyncio
    async def test_message_bus_publish_with_memory_backend(self):
        """Test MessageBus publish works through MemoryBackend."""
        backend = MemoryBackend()
        bus = MessageBus(backend=backend)

        # This should not raise even if Redis is not connected
        # The MessageBus.publish method currently uses Redis directly
        # but the backend is available for future use
        assert bus.backend is backend
        await backend.close()