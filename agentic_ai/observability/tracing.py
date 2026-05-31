"""OpenTelemetry tracing for agent operations."""
import os
import logging
from functools import wraps
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy import — OTel is optional
_tracer = None
_tracing_enabled = False


def setup_tracing(service_name: str = "agentic-ai", endpoint: str = None):
    """Initialize OpenTelemetry tracing.

    Args:
        service_name: Service name for traces
        endpoint: OTLP endpoint (default: localhost:4317, or OTEL_EXPORTER_OTLP_ENDPOINT env var)
    """
    global _tracer, _tracing_enabled
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except ImportError:
            # No OTLP exporter installed, use console or in-memory
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter
            logger.info("OTLP exporter not available, using ConsoleSpanExporter")
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        _tracing_enabled = True
        logger.info(f"Tracing initialized: service={service_name}, endpoint={endpoint}")
    except ImportError:
        logger.warning("OpenTelemetry not installed, tracing disabled")
        _tracing_enabled = False


def get_tracer():
    """Get the configured tracer, or a no-op tracer."""
    global _tracer
    if _tracer is None:
        try:
            from opentelemetry import trace
            _tracer = trace.get_tracer("agentic-ai")
        except ImportError:
            return NoOpTracer()
    return _tracer


class NoOpTracer:
    """Fallback tracer when OTel is not available."""
    def start_as_current_span(self, name, **kwargs):
        return NoOpSpan()

    def start_span(self, name, **kwargs):
        return NoOpSpan()


class NoOpSpan:
    """Fallback span when OTel is not available."""
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key, value):
        pass

    def set_status(self, status):
        pass

    def add_event(self, name, attributes=None):
        pass

    def record_exception(self, exception):
        pass

    def end(self):
        pass


def trace_agent_method(method_name: str):
    """Decorator to add OTel span to agent methods."""
    def decorator(func):
        import asyncio
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                tracer = get_tracer()
                with tracer.start_as_current_span(f"{self.agent_type}.{method_name}") as span:
                    span.set_attribute("agent.id", self.agent_id)
                    span.set_attribute("agent.type", self.agent_type)
                    try:
                        result = await func(self, *args, **kwargs)
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        span.set_status(2)  # ERROR
                        raise
            return wrapper
        else:
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                tracer = get_tracer()
                with tracer.start_as_current_span(f"{self.agent_type}.{method_name}") as span:
                    span.set_attribute("agent.id", self.agent_id)
                    span.set_attribute("agent.type", self.agent_type)
                    try:
                        result = func(self, *args, **kwargs)
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        span.set_status(2)  # ERROR
                        raise
            return wrapper
    return decorator