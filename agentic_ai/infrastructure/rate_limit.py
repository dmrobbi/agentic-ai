"""Rate limiting for agent actions using token bucket algorithm."""
import time
import threading
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """Token bucket rate limiter.
    
    Allows bursts up to capacity, then enforces a steady rate.
    """
    rate: float  # tokens per second
    capacity: int  # max burst size
    _tokens: float = 0.0
    _last_refill: float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        self._tokens = float(self.capacity)
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self.capacity),
            self._tokens + elapsed * self.rate
        )
        self._last_refill = now
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed, False if rate limited."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
    
    def wait(self, tokens: int = 1) -> float:
        """Calculate how long to wait before tokens are available.
        
        Returns wait time in seconds (0 if tokens available now).
        Does NOT actually wait — just returns the time.
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                return 0.0
            needed = tokens - self._tokens
            return needed / self.rate


class RateLimiter:
    """Per-agent, per-action rate limiting.
    
    Uses token buckets for each (agent_id, action) pair.
    """
    
    def __init__(self, default_rate: float = 10.0, default_capacity: int = 20):
        """Initialize rate limiter.
        
        Args:
            default_rate: Default tokens per second (10/s = 600/min)
            default_capacity: Default burst capacity
        """
        self.default_rate = default_rate
        self.default_capacity = default_capacity
        self._buckets: Dict[str, TokenBucket] = {}
        self._custom_rates: Dict[str, Tuple[float, int]] = {}  # key -> (rate, capacity)
        self._lock = threading.Lock()
    
    def _get_bucket(self, agent_id: str, action: str) -> TokenBucket:
        """Get or create a token bucket for the given agent+action."""
        key = f"{agent_id}:{action}"
        with self._lock:
            if key not in self._buckets:
                rate, capacity = self._custom_rates.get(key, (self.default_rate, self.default_capacity))
                self._buckets[key] = TokenBucket(rate=rate, capacity=capacity)
            return self._buckets[key]
    
    def set_rate(self, agent_id: str, action: str, rate: float, capacity: Optional[int] = None) -> None:
        """Set a custom rate for a specific agent+action pair."""
        key = f"{agent_id}:{action}"
        capacity = capacity or self.default_capacity
        self._custom_rates[key] = (rate, capacity)
        # Recreate bucket with new rate
        with self._lock:
            self._buckets[key] = TokenBucket(rate=rate, capacity=capacity)
    
    def check(self, agent_id: str, action: str) -> bool:
        """Check if an action is allowed (non-consuming).
        
        Returns True if the action would be allowed, False if rate-limited.
        Does NOT consume a token.
        """
        bucket = self._get_bucket(agent_id, action)
        # Check without consuming
        with bucket._lock:
            bucket._refill()
            return bucket._tokens >= 1
    
    def acquire(self, agent_id: str, action: str) -> bool:
        """Try to acquire a token for an action.
        
        Returns True if allowed (token consumed), False if rate-limited.
        """
        bucket = self._get_bucket(agent_id, action)
        allowed = bucket.consume(1)
        if not allowed:
            logger.warning(f"Rate limit exceeded: {agent_id}:{action}")
        return allowed
    
    def reset(self, agent_id: Optional[str] = None, action: Optional[str] = None) -> None:
        """Reset rate limits.
        
        If agent_id is None, reset all.
        If action is None, reset all actions for the agent.
        """
        with self._lock:
            if agent_id is None:
                self._buckets.clear()
            elif action is None:
                # Reset all actions for this agent
                keys_to_remove = [k for k in self._buckets if k.startswith(f"{agent_id}:")]
                for k in keys_to_remove:
                    del self._buckets[k]
            else:
                key = f"{agent_id}:{action}"
                if key in self._buckets:
                    del self._buckets[key]