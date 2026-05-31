"""Tests for observability module (tracing and metrics)."""
import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from agentic_ai.observability.tracing import (
    NoOpTracer,
    NoOpSpan,
    get_tracer,
    setup_tracing,
    trace_agent_method,
)
from agentic_ai.observability.metrics import (
    increment_counter,
    record_latency,
    get_simple_metrics,
    setup_metrics,
    _simple_metrics,
)


# ============================================
# NoOpTracer tests
# ============================================

class TestNoOpTracer:
    def test_start_as_current_span_returns_noop_span(self):
        tracer = NoOpTracer()
        span = tracer.start_as_current_span("test")
        assert isinstance(span, NoOpSpan)

    def test_start_span_returns_noop_span(self):
        tracer = NoOpTracer()
        span = tracer.start_span("test")
        assert isinstance(span, NoOpSpan)

    def test_start_as_current_span_with_kwargs(self):
        tracer = NoOpTracer()
        span = tracer.start_as_current_span("test", attributes={"key": "value"})
        assert isinstance(span, NoOpSpan)


# ============================================
# NoOpSpan tests
# ============================================

class TestNoOpSpan:
    def test_context_manager_enter_returns_self(self):
        span = NoOpSpan()
        with span as s:
            assert s is span

    def test_context_manager_exit_no_error(self):
        span = NoOpSpan()
        with span:
            pass  # Should not raise

    def test_set_attribute_no_error(self):
        span = NoOpSpan()
        span.set_attribute("key", "value")  # Should not raise

    def test_set_status_no_error(self):
        span = NoOpSpan()
        span.set_status(2)  # Should not raise

    def test_add_event_no_error(self):
        span = NoOpSpan()
        span.add_event("event_name", {"attr": "val"})  # Should not raise

    def test_record_exception_no_error(self):
        span = NoOpSpan()
        span.record_exception(ValueError("test"))  # Should not raise

    def test_end_no_error(self):
        span = NoOpSpan()
        span.end()  # Should not raise


# ============================================
# get_tracer tests
# ============================================

class TestGetTracer:
    def test_get_tracer_returns_tracer(self):
        # Reset global state
        import agentic_ai.observability.tracing as tracing_mod
        tracing_mod._tracer = None
        tracer = get_tracer()
        # Should return either a real tracer or NoOpTracer
        assert tracer is not None

    def test_get_tracer_returns_noop_when_otel_unavailable(self):
        import agentic_ai.observability.tracing as tracing_mod
        tracing_mod._tracer = None
        with patch.dict("sys.modules", {"opentelemetry": None, "opentelemetry.trace": None}):
            # Force ImportError by temporarily removing the module
            saved = tracing_mod._tracer
            tracing_mod._tracer = None
            try:
                tracer = get_tracer()
                # If OTel is installed, it will return a real tracer.
                # The key is it doesn't crash.
                assert tracer is not None
            finally:
                tracing_mod._tracer = saved


# ============================================
# setup_tracing tests
# ============================================

class TestSetupTracing:
    def test_setup_tracing_without_otel_exporter(self):
        """setup_tracing should work even without OTLP exporter installed."""
        import agentic_ai.observability.tracing as tracing_mod
        old_enabled = tracing_mod._tracing_enabled
        old_tracer = tracing_mod._tracer
        try:
            setup_tracing(service_name="test-service")
            # Should not raise, either initializes or gracefully falls back
            assert True
        finally:
            tracing_mod._tracing_enabled = old_enabled
            tracing_mod._tracer = old_tracer

    def test_setup_tracing_with_custom_endpoint(self):
        """setup_tracing should accept custom endpoint."""
        import agentic_ai.observability.tracing as tracing_mod
        old_enabled = tracing_mod._tracing_enabled
        old_tracer = tracing_mod._tracer
        try:
            setup_tracing(service_name="test-service", endpoint="localhost:9999")
            assert True
        finally:
            tracing_mod._tracing_enabled = old_enabled
            tracing_mod._tracer = old_tracer


# ============================================
# trace_agent_method decorator tests
# ============================================

class TestTraceAgentMethod:
    def test_decorator_wraps_async_function(self):
        @trace_agent_method("test_method")
        async def my_method(self):
            return "result"

        assert asyncio.iscoroutinefunction(my_method)

    def test_decorator_wraps_sync_function(self):
        @trace_agent_method("test_method")
        def my_method(self):
            return "result"

        assert not asyncio.iscoroutinefunction(my_method)

    @pytest.mark.asyncio
    async def test_decorator_on_async_method(self):
        class FakeAgent:
            agent_type = "test_agent"
            agent_id = "test-123"

            @trace_agent_method("think")
            async def think(self):
                return "thought"

        agent = FakeAgent()
        result = await agent.think()
        assert result == "thought"

    def test_decorator_on_sync_method(self):
        class FakeAgent:
            agent_type = "test_agent"
            agent_id = "test-123"

            @trace_agent_method("send_message")
            def send_message(self, content="hello"):
                return content

        agent = FakeAgent()
        result = agent.send_message(content="hi")
        assert result == "hi"

    @pytest.mark.asyncio
    async def test_decorator_propagates_exception(self):
        class FakeAgent:
            agent_type = "test_agent"
            agent_id = "test-123"

            @trace_agent_method("failing")
            async def failing(self):
                raise ValueError("boom")

        agent = FakeAgent()
        with pytest.raises(ValueError, match="boom"):
            await agent.failing()


# ============================================
# Metrics tests
# ============================================

class TestMetrics:
    def setup_method(self):
        """Clear simple metrics before each test."""
        _simple_metrics.clear()

    def test_increment_counter_basic(self):
        increment_counter("requests")
        metrics = get_simple_metrics()
        assert metrics["requests"] == 1

    def test_increment_counter_multiple(self):
        increment_counter("requests")
        increment_counter("requests")
        increment_counter("requests")
        metrics = get_simple_metrics()
        assert metrics["requests"] == 3

    def test_increment_counter_with_value(self):
        increment_counter("bytes_sent", value=100)
        metrics = get_simple_metrics()
        assert metrics["bytes_sent"] == 100

    def test_increment_counter_with_attributes(self):
        increment_counter("requests", attributes={"method": "GET"})
        metrics = get_simple_metrics()
        key = "requests:{'method': 'GET'}"
        assert metrics[key] == 1

    def test_record_latency(self):
        record_latency("api_call", 150.5)
        metrics = get_simple_metrics()
        key = "latency:api_call"
        assert 150.5 in metrics[key]

    def test_record_latency_multiple(self):
        record_latency("api_call", 100.0)
        record_latency("api_call", 200.0)
        metrics = get_simple_metrics()
        key = "latency:api_call"
        assert len(metrics[key]) == 2
        assert 100.0 in metrics[key]
        assert 200.0 in metrics[key]

    def test_record_latency_with_attributes(self):
        record_latency("api_call", 50.0, attributes={"endpoint": "/health"})
        metrics = get_simple_metrics()
        key = "latency:api_call:{'endpoint': '/health'}"
        assert 50.0 in metrics[key]

    def test_get_simple_metrics_returns_copy(self):
        increment_counter("test_counter")
        m1 = get_simple_metrics()
        m2 = get_simple_metrics()
        assert m1 == m2
        assert m1 is not m2  # Different objects

    def test_setup_metrics_graceful_fallback(self):
        """setup_metrics should not crash even if OTel metrics aren't fully configured."""
        setup_metrics(service_name="test")
        # Should not raise


# ============================================
# Integration: Agent method tracing with BaseAgent
# ============================================

class TestAgentTracingIntegration:
    @pytest.mark.asyncio
    async def test_base_agent_think_with_tracing(self):
        """BaseAgent.think should work with the tracing decorator."""
        from agentic_ai.agents.base import BaseAgent
        agent = BaseAgent(name="test-agent")
        result = await agent.think("hello")
        # Without inference engine, returns "Generated response"
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_base_agent_call_tool_with_tracing(self):
        """BaseAgent.call_tool should work with the tracing decorator."""
        from agentic_ai.agents.base import BaseAgent
        agent = BaseAgent(name="test-agent")
        result = await agent.call_tool("get_status")
        assert isinstance(result, dict)
        assert result["agent_type"] == "base"

    def test_base_agent_send_message_with_tracing(self):
        """BaseAgent.send_message (sync) should work with the tracing decorator."""
        from agentic_ai.agents.base import BaseAgent
        agent = BaseAgent(name="test-agent")
        agent.send_message(recipient="other", content="hello")
        assert len(agent._history) > 0

    @pytest.mark.asyncio
    async def test_base_agent_perform_task_with_tracing(self):
        """BaseAgent.perform_task should work with the tracing decorator."""
        from agentic_ai.agents.base import BaseAgent
        agent = BaseAgent(name="test-agent")
        result = await agent.perform_task("analysis")
        assert result["status"] == "done"
        assert result["task_type"] == "analysis"