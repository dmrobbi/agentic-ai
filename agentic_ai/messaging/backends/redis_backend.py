"""Redis-based messaging backend."""
import logging
from typing import Optional, AsyncIterator

from agentic_ai.infrastructure.config import RedisConfig

logger = logging.getLogger(__name__)


class RedisBackend:
    """Redis messaging backend using the existing Redis infrastructure."""

    def __init__(self, config: Optional[RedisConfig] = None):
        self.config = config or RedisConfig()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = self.config.create_client()
        return self._client

    async def publish(self, channel: str, message: bytes) -> None:
        try:
            self.client.publish(channel, message if isinstance(message, str) else message.decode())
        except Exception as e:
            logger.error(f"Redis publish error: {e}")

    async def subscribe(self, channel: str) -> AsyncIterator[bytes]:
        try:
            pubsub = self.client.pubsub()
            pubsub.subscribe(channel)
            for message in pubsub.listen():
                if message["type"] == "message":
                    data = message.get("data", b"")
                    yield data if isinstance(data, bytes) else data.encode()
        except Exception as e:
            logger.error(f"Redis subscribe error: {e}")

    async def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass