"""
Message Bus - Redis Pub/Sub Implementation
===========================================

Provides asynchronous message passing between agents using Redis pub/sub.
"""

import json
import ast
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar
from contextlib import contextmanager

import redis
from agentic_ai.infrastructure.utils import utcnow

logger = logging.getLogger(__name__)

def _safe_loads(data):
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        try:
            return ast.literal_eval(data)
        except (ValueError, SyntaxError):
            return {}

T = TypeVar('T')


class MessageType(Enum):
    """Message types for agent communication."""
    REQUEST = "request"
    RESPONSE = "response"
    EVENT = "event"
    COMMAND = "command"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class Message:
    """Message structure for agent communication."""
    message_id: str
    message_type: MessageType
    source_agent: str
    target_agent: Optional[str]
    topic: str
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=utcnow)
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    ttl_seconds: int = 3600
    priority: int = 5  # 1-10, 10 is highest

    def to_json(self) -> str:
        """Serialize message to JSON."""
        data = asdict(self)
        data['message_type'] = self.message_type.value
        data['timestamp'] = self.timestamp.isoformat()
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> 'Message':
        """Deserialize message from JSON."""
        data = _safe_loads(json_str)
        data['message_type'] = MessageType(data['message_type'])
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class MessageBus:
    """
    Redis-based message bus for agent communication.

    Supports:
    - Publish/subscribe messaging
    - Request/response pattern
    - Priority queues
    - Message TTL
    - Dead letter queue for failed messages
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        channel_prefix: str = "agentic_ai",
        dead_letter_queue: str = "dlq",
        backend=None,
        client: Optional["redis.Redis"] = None,
    ):
        """
        Initialize message bus.

        Args:
            redis_url: Redis connection URL
            channel_prefix: Prefix for all channels
            dead_letter_queue: Queue for failed messages
            backend: Optional pluggable messaging backend. If provided,
                overrides Redis. If None, tries Redis then falls back to
                MemoryBackend.
            client: Optional pre-built Redis client (e.g. a shared test
                server). When given, redis_url is ignored and connect()
                uses this client; disconnect() will not close it.
        """
        self.redis_url = redis_url
        self.channel_prefix = channel_prefix
        self.dead_letter_queue = dead_letter_queue
        self._external_client = client
        self._redis: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None
        self._subscribers: Dict[str, List[Callable]] = {}
        self._running = False
        self._pump_thread: Optional[threading.Thread] = None
        self._pump_lock = threading.Lock()
        self.backend = backend
        if backend is None:
            try:
                from agentic_ai.messaging.backends.redis_backend import RedisBackend
                self.backend = RedisBackend()
            except Exception:
                from agentic_ai.messaging.backends.memory_backend import MemoryBackend
                self.backend = MemoryBackend()
                logger.info("Redis unavailable, using in-memory messaging backend")

    def connect(self) -> None:
        """Connect to Redis (or adopt an injected client, e.g. for tests)."""
        if self._external_client is not None:
            self._redis = self._external_client
        else:
            self._redis = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
        self._pubsub = self._redis.pubsub()  # type: ignore[union-attr]
        logger.info(f"Connected to Redis: {self.redis_url}")

    def disconnect(self) -> None:
        """Disconnect from Redis and stop the subscriber pump."""
        self._running = False
        if self._pump_thread is not None and self._pump_thread.is_alive():
            self._pump_thread.join(timeout=2)
        self._pump_thread = None
        if self._pubsub:
            self._pubsub.close()
        # Only close clients we created; injected clients (tests) stay open.
        if self._redis is not None and self._external_client is None:
            self._redis.close()  # type: ignore[union-attr]
        logger.info("Disconnected from Redis")

    def _get_channel(self, topic: str) -> str:
        """Get full channel name with prefix."""
        return f"{self.channel_prefix}:{topic}"

    def publish(self, message: Message) -> bool:
        """
        Publish message to topic.

        Args:
            message: Message to publish

        Returns:
            True if published successfully
        """
        if not self._redis:
            self.connect()

        try:
            channel = self._get_channel(message.topic)
            self._redis.publish(channel, message.to_json())  # type: ignore[union-attr]
            logger.debug(f"Published message {message.message_id} to {channel}")
            return True
        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            self._send_to_dlq(message, str(e))
            return False

    def subscribe(self, topic: str, callback: Callable[[Message], None]) -> None:
        """
        Subscribe to topic with callback.

        Args:
            topic: Topic to subscribe to
            callback: Function to call on message received
        """
        channel = self._get_channel(topic)

        if topic not in self._subscribers:
            self._subscribers[topic] = []
            if self._pubsub is None:
                self.connect()
            assert self._pubsub is not None
            # Subscribe by channel NAME only: redis-py's PubSub.subscribe()
            # treats positional arguments as channel names, and handlers must
            # be passed as **kwargs if at all. We dispatch ourselves in the
            # pump loop instead of relying on redis-py's handler protocol.
            self._pubsub.subscribe(channel)
            self._start_pump()

        self._subscribers[topic].append(callback)
        logger.info(f"Subscribed to {channel}")

    def _start_pump(self) -> None:
        """Ensure the background pump thread that receives messages is running."""
        with self._pump_lock:
            if self._pump_thread is not None and self._pump_thread.is_alive():
                return
            self._running = True
            self._pump_thread = threading.Thread(
                target=self._pump_loop,
                name=f"agentic-ai-msgbus-{self.channel_prefix}",
                daemon=True,
            )
            self._pump_thread.start()

    @staticmethod
    def _get_pubsub_message(pubsub: "redis.client.PubSub"):
        """Fetch the next pubsub message, tolerating kwarg differences
        between redis-py versions and fakeredis (timeout vs select_timeout)."""
        try:
            return pubsub.get_message(timeout=0.5, ignore_subscribe_messages=True)
        except TypeError:
            # redis-py < 8 named the wait argument select_timeout
            return pubsub.get_message(select_timeout=0.5, ignore_subscribe_messages=True)  # type: ignore[call-arg]

    def _pump_loop(self) -> None:
        """Poll the pubsub connection and dispatch incoming messages."""
        pubsub = self._pubsub
        while self._running and pubsub is not None:
            try:
                message = self._get_pubsub_message(pubsub)
            except Exception:
                if not self._running:
                    break
                time.sleep(0.1)
                continue
            if message is None:
                # get_message already waited ~0.5s; poll again immediately
                continue
            if not isinstance(message, dict):
                # Junk response (e.g. a mocked pubsub in tests): sleep so a
                # fake get_message that never blocks cannot hot-spin this loop.
                time.sleep(0.1)
                continue
            if message.get('type') != 'message':
                continue
            self._on_message(message)

    def unsubscribe(self, topic: str, callback: Optional[Callable] = None) -> None:
        """
        Unsubscribe from topic.

        Args:
            topic: Topic to unsubscribe from
            callback: Specific callback to remove (or all if None)
        """
        if topic in self._subscribers:
            if callback:
                self._subscribers[topic].remove(callback)
            else:
                channel = self._get_channel(topic)
                if self._pubsub:
                    self._pubsub.unsubscribe(channel)
                del self._subscribers[topic]
            logger.info(f"Unsubscribed from {topic}")

    def _on_message(self, message: dict) -> None:
        """Handle incoming pubsub message."""
        if message.get('type') != 'message':
            return

        try:
            data = message.get('data')
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='replace')
            if not isinstance(data, str):
                logger.error("Pubsub message without string payload")
                return
            channel_name = message.get('channel', '')
            if isinstance(channel_name, bytes):
                channel_name = channel_name.decode('utf-8', errors='replace')
            msg = Message.from_json(data)
            topic = channel_name.replace(f"{self.channel_prefix}:", "")

            if topic in self._subscribers:
                for callback in self._subscribers[topic]:
                    try:
                        callback(msg)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                        self._send_to_dlq(msg, str(e))
        except Exception as e:
            logger.error(f"Failed to process message: {e}")

    def request(self, message: Message, timeout_seconds: int = 30) -> Optional[Message]:
        """
        Send request and wait for response.

        Args:
            message: Request message
            timeout_seconds: Response timeout

        Returns:
            Response message or None if timeout
        """
        if not self._redis:
            self.connect()

        reply_topic = f"reply.{uuid.uuid4().hex[:8]}"
        message.reply_to = reply_topic

        # Subscribe to reply channel
        reply_channel = self._get_channel(reply_topic)
        pubsub = self._redis.pubsub()  # type: ignore[union-attr]
        pubsub.subscribe(reply_channel)

        try:
            # Publish request
            self.publish(message)

            # Wait for response
            import time
            start_time = time.time()

            while time.time() - start_time < timeout_seconds:
                response = pubsub.get_message(timeout=1.0)
                if response and response['type'] == 'message':
                    return Message.from_json(response['data'])

            logger.warning(f"Request timeout for {message.message_id}")
            return None
        finally:
            pubsub.unsubscribe(reply_channel)
            pubsub.close()

    def respond(self, original_message: Message, response_payload: Dict[str, Any]) -> bool:
        """
        Send response to original request.

        Args:
            original_message: Original request message
            response_payload: Response data

        Returns:
            True if response sent successfully
        """
        if not original_message.reply_to:
            logger.error("Cannot respond: no reply_to channel")
            return False

        response = Message(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            source_agent=original_message.target_agent or "unknown",
            target_agent=original_message.source_agent,
            topic=original_message.reply_to,
            payload=response_payload,
            correlation_id=original_message.message_id,
        )

        return self.publish(response)

    def _send_to_dlq(self, message: Message, error: str) -> None:
        """Send failed message to dead letter queue."""
        if not self._redis:
            return

        dlq_message = {
            'original_message': message.to_json(),
            'error': error,
            'timestamp': utcnow().isoformat(),
        }

        try:
            self._redis.lpush(self.dead_letter_queue, json.dumps(dlq_message))  # type: ignore[union-attr]
            self._redis.ltrim(self.dead_letter_queue, 0, 999)  # Keep last 1000  # type: ignore[union-attr]
            logger.warning(f"Message {message.message_id} sent to DLQ: {error}")
        except Exception as e:
            logger.error(f"Failed to send to DLQ: {e}")

    def get_dlq_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get messages from dead letter queue."""
        if not self._redis:
            return []

        messages = self._redis.lrange(self.dead_letter_queue, 0, limit - 1)  # type: ignore[union-attr]
        return [_safe_loads(m) for m in messages]  # type: ignore[union-attr]

    def retry_dlq_message(self, message_index: int) -> bool:
        """Retry message from dead letter queue."""
        if not self._redis:
            return False

        messages = self._redis.lrange(self.dead_letter_queue, message_index, message_index)  # type: ignore[union-attr]
        if not messages:
            return False

        try:
            dlq_message = _safe_loads(messages[0])  # type: ignore[index]
            original_message = Message.from_json(dlq_message['original_message'])

            # Republish original message
            if self.publish(original_message):
                self._redis.lrem(self.dead_letter_queue, message_index + 1, messages[0])  # type: ignore[union-attr,arg-type,index]
                return True
        except Exception as e:
            logger.error(f"Failed to retry DLQ message: {e}")

        return False

    def clear_dlq(self) -> int:
        """Clear dead letter queue. Returns count of cleared messages."""
        if not self._redis:
            return 0

        count = self._redis.llen(self.dead_letter_queue)  # type: ignore[union-attr]
        self._redis.delete(self.dead_letter_queue)  # type: ignore[union-attr]
        logger.info(f"Cleared {count} messages from DLQ")
        return count  # type: ignore[no-any-return,return-value]

    @contextmanager
    def connection(self):
        """Context manager for connection."""
        self.connect()
        try:
            yield self
        finally:
            self.disconnect()


# Convenience functions for simple usage

_default_bus: Optional[MessageBus] = None


def get_message_bus(redis_url: str = "redis://localhost:6379") -> MessageBus:
    """Get or create default message bus."""
    global _default_bus
    if _default_bus is None:
        _default_bus = MessageBus(redis_url=redis_url)
    return _default_bus


def publish_message(
    topic: str,
    payload: Dict[str, Any],
    source_agent: str,
    message_type: MessageType = MessageType.EVENT,
    target_agent: Optional[str] = None,
) -> bool:
    """Publish message using default bus."""
    bus = get_message_bus()
    message = Message(
        message_id=str(uuid.uuid4()),
        message_type=message_type,
        source_agent=source_agent,
        target_agent=target_agent,
        topic=topic,
        payload=payload,
    )
    return bus.publish(message)


def subscribe_to_topic(topic: str, callback: Callable[[Message], None]) -> None:
    """Subscribe to topic using default bus."""
    bus = get_message_bus()
    bus.subscribe(topic, callback)
