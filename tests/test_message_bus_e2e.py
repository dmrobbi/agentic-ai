"""End-to-end messaging tests: the real pub/sub receive path.

These cover the MessageBus receive path (subscribe -> background pump ->
dispatch) that the 2026-09-21 audit found non-functional: subscribe() passed
its handler as a channel name and no message pump existed, so subscribers
never received anything.

Strategy: run against a real Redis when one is reachable (REDIS_URL, default
localhost:6379 — CI provides a redis service); fall back to a shared fakeredis
server when only fakeredis is available; skip otherwise.
"""

import os
import socket
import time
import uuid

import pytest

from agentic_ai.messaging.message_bus import MessageBus, Message, MessageType


def _redis_reachable(url: str, timeout: float = 1.0) -> bool:
    """TCP-connect check for the host/port parsed from a redis:// URL."""
    host, port = "localhost", 6379
    if url.startswith("redis://"):
        rest = url[len("redis://"):].split("/", 1)[0]
        if ":" in rest:
            host, _, port = rest.partition(":")
            port = int(port)
        elif rest:
            host = rest
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _make_bus_pair():
    """Return (bus_a, bus_b, backend_name) over real or fake redis."""
    url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    if _redis_reachable(url):
        return MessageBus(redis_url=url), MessageBus(redis_url=url), "redis"

    fakeredis = pytest.importorskip(
        "fakeredis", reason="no Redis reachable and fakeredis not installed"
    )
    server = fakeredis.FakeServer()
    client_a = fakeredis.FakeRedis(server=server, decode_responses=True)
    client_b = fakeredis.FakeRedis(server=server, decode_responses=True)
    return MessageBus(client=client_a), MessageBus(client=client_b), "fakeredis"


class TestMessageBusEndToEnd:
    """Two independent bus connections: publish on one, receive on the other."""

    def test_publish_subscribe_receive(self):
        """Agent A publishes; agent B's subscriber receives the exact Message."""
        bus_a, bus_b, backend = _make_bus_pair()
        try:
            received = []
            bus_b.subscribe("agent.b", lambda m: received.append(m))

            payload = {"action": "ping", "parameters": {"content": "hello"}}
            message = Message(
                message_id=str(uuid.uuid4()),
                message_type=MessageType.EVENT,
                source_agent="agent-a",
                target_agent="agent-b",
                topic="agent.b",
                payload=payload,
            )
            assert bus_a.publish(message) is True

            deadline = time.time() + 10
            while time.time() < deadline and not received:
                time.sleep(0.05)

            assert len(received) == 1, f"no message received (backend={backend})"
            got = received[0]
            assert isinstance(got, Message)
            assert got.message_id == message.message_id
            assert got.source_agent == "agent-a"
            assert got.target_agent == "agent-b"
            assert got.topic == "agent.b"
            assert got.payload == payload
        finally:
            bus_a.disconnect()
            bus_b.disconnect()

    def test_multiple_subscribers_and_topics(self):
        """Each subscriber gets only the topics it subscribed to."""
        bus_a, bus_b, backend = _make_bus_pair()
        try:
            got_alpha, got_beta = [], []
            bus_b.subscribe("agent.alpha", lambda m: got_alpha.append(m))
            bus_b.subscribe("agent.beta", lambda m: got_beta.append(m))

            def publish(topic: str) -> str:
                mid = str(uuid.uuid4())
                assert bus_a.publish(
                    Message(
                        message_id=mid,
                        message_type=MessageType.NOTIFICATION,
                        source_agent="pub",
                        target_agent=None,
                        topic=topic,
                        payload={"action": "notify"},
                    )
                )
                return mid

            id_alpha = publish("agent.alpha")
            id_beta = publish("agent.beta")

            deadline = time.time() + 10
            while time.time() < deadline and not (got_alpha and got_beta):
                time.sleep(0.05)

            assert [m.message_id for m in got_alpha] == [id_alpha], backend
            assert [m.message_id for m in got_beta] == [id_beta], backend
        finally:
            bus_a.disconnect()
            bus_b.disconnect()

    def test_request_response_roundtrip(self):
        """request() receives a response produced by a subscribed responder."""
        bus_a, bus_b, backend = _make_bus_pair()
        try:

            def handle(message: Message) -> None:
                bus_b.respond(message, {"status": "ok", "value": 42})

            bus_b.subscribe("worker", handle)

            request = Message(
                message_id=str(uuid.uuid4()),
                message_type=MessageType.REQUEST,
                source_agent="agent-a",
                target_agent="worker",
                topic="worker",
                payload={"action": "compute"},
            )
            response = bus_a.request(request, timeout_seconds=15)

            assert response is not None, f"no response within timeout (backend={backend})"
            assert response.message_type == MessageType.RESPONSE
            assert response.payload == {"status": "ok", "value": 42}
            assert response.correlation_id == request.message_id
        finally:
            bus_a.disconnect()
            bus_b.disconnect()