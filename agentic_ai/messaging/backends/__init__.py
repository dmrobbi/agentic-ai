"""Pluggable messaging backends."""
from typing import Protocol, AsyncIterator, runtime_checkable


@runtime_checkable
class MessageBackend(Protocol):
    """Protocol for messaging backends."""

    async def publish(self, channel: str, message: bytes) -> None:
        """Publish a message to a channel."""
        ...

    async def subscribe(self, channel: str) -> AsyncIterator[bytes]:
        """Subscribe to messages on a channel."""
        ...

    async def close(self) -> None:
        """Close the backend connection."""
        ...