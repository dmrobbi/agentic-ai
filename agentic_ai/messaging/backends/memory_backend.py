"""In-memory messaging backend for testing."""
import asyncio
import logging
from collections import defaultdict
from typing import AsyncIterator

from agentic_ai.messaging.backends import MessageBackend

logger = logging.getLogger(__name__)


class MemoryBackend:
    """In-process messaging backend for testing and development.

    No external dependencies required. Messages are stored in memory
    and delivered via asyncio queues.
    """

    def __init__(self):
        self._channels: dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        self._closed = False

    async def publish(self, channel: str, message: bytes) -> None:
        if self._closed:
            return
        if isinstance(message, str):
            message = message.encode()
        await self._channels[channel].put(message)

    async def subscribe(self, channel: str) -> AsyncIterator[bytes]:
        while not self._closed:
            try:
                message = await asyncio.wait_for(
                    self._channels[channel].get(), timeout=1.0
                )
                yield message
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Memory subscribe error: {e}")
                break

    async def close(self) -> None:
        self._closed = True
        self._channels.clear()