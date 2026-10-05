"""Tests for rate limiting — token bucket and per-agent rate limiter."""
import time
import threading
import pytest
from agentic_ai.infrastructure.rate_limit import TokenBucket, RateLimiter
from agentic_ai.agents.base import BaseAgent, Permission


# ============================================================
# TokenBucket tests
# ============================================================

class TestTokenBucket:
    """TokenBucket unit tests."""

    def test_creation_default_full(self):
        """New bucket starts with tokens equal to capacity."""
        bucket = TokenBucket(rate=10.0, capacity=20)
        assert bucket._tokens == 20.0

    def test_creation_custom_rate_capacity(self):
        """Bucket stores rate and capacity correctly."""
        bucket = TokenBucket(rate=5.0, capacity=50)
        assert bucket.rate == 5.0
        assert bucket.capacity == 50
        assert bucket._tokens == 50.0

    def test_consume_single_token(self):
        """Consuming one token succeeds and decrements count."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        assert bucket.consume(1) is True
        assert bucket._tokens == 4.0

    def test_consume_multiple_tokens(self):
        """Consuming multiple tokens at once."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        assert bucket.consume(3) is True
        assert bucket._tokens == 7.0

    def test_consume_exceeds_capacity_returns_false(self):
        """Consuming more tokens than available returns False."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        assert bucket.consume(6) is False
        # Tokens unchanged after failed consume
        assert bucket._tokens == 5.0

    def test_consume_all_tokens(self):
        """Consuming exactly all tokens succeeds."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        assert bucket.consume(5) is True
        assert bucket._tokens == 0.0

    def test_consume_after_drain_fails(self):
        """After draining all tokens, further consumes fail."""
        bucket = TokenBucket(rate=10.0, capacity=3)
        assert bucket.consume(3) is True
        assert bucket.consume(1) is False

    def test_refill_over_time(self):
        """Tokens refill based on elapsed time at the configured rate."""
        bucket = TokenBucket(rate=1000.0, capacity=10)  # 1000 tokens/s
        # Drain all tokens
        bucket.consume(10)
        assert bucket._tokens == 0.0
        # Wait a short time
        time.sleep(0.01)  # 10ms → should refill ~10 tokens
        # consume should work again
        assert bucket.consume(1) is True

    def test_refill_capped_at_capacity(self):
        """Tokens never exceed capacity even after long idle."""
        bucket = TokenBucket(rate=1000.0, capacity=5)
        time.sleep(0.01)  # Would refill ~10 tokens if uncapped
        assert bucket.consume(5) is True  # Only 5 available (capacity)
        assert bucket.consume(1) is False  # No extras beyond capacity

    def test_wait_returns_zero_when_tokens_available(self):
        """wait() returns 0 when tokens are immediately available."""
        bucket = TokenBucket(rate=10.0, capacity=20)
        assert bucket.wait(1) == 0.0

    def test_wait_returns_nonzero_when_depleted(self):
        """wait() returns > 0 when tokens are depleted."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        bucket.consume(5)
        wait_time = bucket.wait(1)
        assert wait_time > 0
        # Should be approximately 1/10 = 0.1 seconds
        assert 0.05 < wait_time < 0.2

    def test_wait_does_not_consume(self):
        """Calling wait() does not consume tokens."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        bucket.wait(1)
        assert bucket._tokens == 5.0

    def test_thread_safety_consume(self):
        """Concurrent consume calls don't exceed capacity."""
        # Use a very slow refill rate so tokens don't refill during the test
        bucket = TokenBucket(rate=0.01, capacity=100)
        successes = []
        lock = threading.Lock()

        def consume_one():
            result = bucket.consume(1)
            with lock:
                successes.append(result)

        threads = [threading.Thread(target=consume_one) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At most 100 should succeed (capacity), rest should fail
        total_success = successes.count(True)
        total_fail = successes.count(False)
        assert total_success <= 100
        assert total_success + total_fail == 200


# ============================================================
# RateLimiter tests
# ============================================================

class TestRateLimiter:
    """RateLimiter unit tests."""

    def test_creation_with_defaults(self):
        """RateLimiter stores defaults."""
        limiter = RateLimiter()
        assert limiter.default_rate == 10.0
        assert limiter.default_capacity == 20

    def test_creation_with_custom_defaults(self):
        """RateLimiter accepts custom defaults."""
        limiter = RateLimiter(default_rate=5.0, default_capacity=10)
        assert limiter.default_rate == 5.0
        assert limiter.default_capacity == 10

    def test_acquire_allows_under_rate(self):
        """Acquire succeeds for calls within burst capacity."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=20)
        for i in range(20):
            assert limiter.acquire("agent1", "action1") is True

    def test_acquire_blocks_over_rate(self):
        """Acquire fails after burst capacity is exhausted (100 calls, first 20 succeed)."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=20)
        results = [limiter.acquire("agent1", "action1") for _ in range(100)]
        assert results[:20].count(True) == 20
        assert results[20:].count(True) == 0  # All subsequent should fail

    def test_acquire_different_agents_independent(self):
        """Different agents have independent buckets."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=5)
        for _ in range(5):
            assert limiter.acquire("agent1", "action1") is True
        assert limiter.acquire("agent1", "action1") is False  # agent1 exhausted
        assert limiter.acquire("agent2", "action1") is True  # agent2 still has tokens

    def test_acquire_different_actions_independent(self):
        """Different actions for same agent have independent buckets."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=5)
        for _ in range(5):
            assert limiter.acquire("agent1", "action1") is True
        assert limiter.acquire("agent1", "action1") is False  # action1 exhausted
        assert limiter.acquire("agent1", "action2") is True  # different action

    def test_check_non_consuming(self):
        """check() returns True without consuming a token."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=5)
        assert limiter.check("agent1", "action1") is True
        # Still has full capacity since check doesn't consume
        for _ in range(5):
            assert limiter.acquire("agent1", "action1") is True

    def test_check_returns_false_when_depleted(self):
        """check() returns False when no tokens available."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=3)
        for _ in range(3):
            limiter.acquire("agent1", "action1")
        assert limiter.check("agent1", "action1") is False

    def test_set_rate_custom(self):
        """set_rate creates a custom bucket with specified rate."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=20)
        limiter.set_rate("agent1", "action1", rate=1.0, capacity=5)
        # Only 5 tokens available (custom capacity)
        for _ in range(5):
            assert limiter.acquire("agent1", "action1") is True
        assert limiter.acquire("agent1", "action1") is False

    def test_set_rate_does_not_affect_other_agents(self):
        """set_rate for one agent doesn't change defaults for others."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=20)
        limiter.set_rate("agent1", "action1", rate=1.0, capacity=5)
        # agent2 still uses default capacity
        for _ in range(20):
            assert limiter.acquire("agent2", "action1") is True

    def test_reset_all(self):
        """reset() with no args clears all buckets."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=3)
        for _ in range(3):
            limiter.acquire("agent1", "action1")
            limiter.acquire("agent2", "action1")
        assert limiter.acquire("agent1", "action1") is False
        assert limiter.acquire("agent2", "action1") is False
        limiter.reset()
        assert limiter.acquire("agent1", "action1") is True
        assert limiter.acquire("agent2", "action1") is True

    def test_reset_agent(self):
        """reset(agent_id) clears all actions for that agent."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=3)
        for _ in range(3):
            limiter.acquire("agent1", "action1")
        assert limiter.acquire("agent1", "action1") is False
        limiter.reset(agent_id="agent1")
        assert limiter.acquire("agent1", "action1") is True

    def test_reset_specific_action(self):
        """reset(agent_id, action) clears only that action's bucket."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=3)
        for _ in range(3):
            limiter.acquire("agent1", "action1")
            limiter.acquire("agent1", "action2")
        limiter.reset(agent_id="agent1", action="action1")
        assert limiter.acquire("agent1", "action1") is True  # Reset
        assert limiter.acquire("agent1", "action2") is False  # Not reset

    def test_wait_returns_zero_when_available(self):
        """RateLimiter wait returns 0 when tokens available."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=20)
        assert limiter._get_bucket("agent1", "action1").wait(1) == 0.0


# ============================================================
# BaseAgent integration tests
# ============================================================

class TestBaseAgentRateLimiting:
    """Test that BaseAgent respects rate limiting when configured."""

    def test_no_rate_limiter_backward_compat(self):
        """BaseAgent without rate_limiter works normally (no limiting)."""
        agent = BaseAgent(agent_id="test-agent")
        # Should be able to call tools freely without rate limiting
        result = asyncio_run(agent.call_tool("get_status"))
        assert "error" not in result or "rate_limited" not in result

    def test_with_rate_limiter_tools_limited(self):
        """BaseAgent with rate_limiter limits tool calls."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=3)
        agent = BaseAgent(agent_id="test-agent", rate_limiter=limiter)
        # First 3 calls should succeed
        results = [asyncio_run(agent.call_tool("get_status")) for _ in range(5)]
        rate_limited_count = sum(1 for r in results if r.get("rate_limited") is True)
        assert rate_limited_count == 2  # 4th and 5th should be rate limited

    def test_with_rate_limiter_send_message_drops(self):
        """BaseAgent with rate_limiter drops messages over rate."""
        limiter = RateLimiter(default_rate=10.0, default_capacity=2)
        agent = BaseAgent(agent_id="test-agent", rate_limiter=limiter)
        # First 2 should work
        agent.send_message(recipient="other", content="msg1")
        agent.send_message(recipient="other", content="msg2")
        # 3rd should be dropped (returns None)
        result = agent.send_message(recipient="other", content="msg3")
        assert result is None

    def test_without_rate_limiter_send_message_normal(self):
        """BaseAgent without rate_limiter sends all messages."""
        agent = BaseAgent(agent_id="test-agent")
        agent.send_message(recipient="other", content="msg1")
        agent.send_message(recipient="other", content="msg2")
        agent.send_message(recipient="other", content="msg3")
        # All messages should be in history
        send_msgs = [h for h in agent._history if h["action"] == "send_message"]
        assert len(send_msgs) == 3


def asyncio_run(coro):
    """Helper to run async code in tests."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)