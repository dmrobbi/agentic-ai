"""OpenTelemetry metrics for agent operations."""
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

_meter = None
_metrics_enabled = False

# Simple counter/metric store for when OTel is not available
_simple_metrics: Dict[str, Any] = {}


def setup_metrics(service_name: str = "agentic-ai", endpoint: str = None):
    """Initialize OpenTelemetry metrics."""
    global _meter, _metrics_enabled
    try:
        from opentelemetry import metrics
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": service_name})
        provider = MeterProvider(resource=resource)
        metrics.set_meter_provider(provider)
        _meter = metrics.get_meter(service_name)
        _metrics_enabled = True
    except ImportError:
        logger.warning("OpenTelemetry metrics not available, using simple counters")
        _metrics_enabled = False


def get_meter():
    """Get the configured meter."""
    return _meter


def increment_counter(name: str, value: int = 1, attributes: Dict[str, str] = None):
    """Increment a counter."""
    if _meter:
        try:
            counter = _meter.create_counter(name)
            counter.add(value, attributes or {})
        except (AttributeError, TypeError, ValueError):
            pass
    # Always track in simple metrics
    key = f"{name}:{attributes}" if attributes else name
    _simple_metrics[key] = _simple_metrics.get(key, 0) + value


def record_latency(name: str, duration_ms: float, attributes: Dict[str, str] = None):
    """Record a latency measurement."""
    if _meter:
        try:
            histogram = _meter.create_histogram(name)
            histogram.record(duration_ms, attributes or {})
        except (AttributeError, TypeError, ValueError):
            pass
    key = f"latency:{name}:{attributes}" if attributes else f"latency:{name}"
    _simple_metrics.setdefault(key, []).append(duration_ms)


def get_simple_metrics() -> Dict[str, Any]:
    """Get simple metrics (for testing/monitoring without OTel)."""
    return dict(_simple_metrics)