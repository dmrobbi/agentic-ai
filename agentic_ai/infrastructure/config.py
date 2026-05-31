"""Infrastructure configuration from environment variables."""
import os
from dataclasses import dataclass, field


@dataclass
class RedisConfig:
    """Redis connection configuration from environment."""

    url: str = field(default_factory=lambda: os.environ.get("REDIS_URL", "redis://localhost:6379"))
    password: str = field(default_factory=lambda: os.environ.get("REDIS_PASSWORD", ""))
    tls: bool = field(default_factory=lambda: os.environ.get("REDIS_TLS", "").lower() in ("1", "true", "yes"))

    def get_client_kwargs(self) -> dict:
        """Get kwargs for redis.Redis.from_url()."""
        kwargs = {"decode_responses": True}
        if self.tls:
            kwargs["ssl"] = True
        return kwargs

    def create_client(self):
        """Create a Redis client from this config."""
        import redis
        return redis.Redis.from_url(self.url, **self.get_client_kwargs())