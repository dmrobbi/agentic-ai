"""
Tests for the ACP (Agent Communication Protocol) module.

Covers: MessageType enum, Priority enum, ACPMessage creation/serialization/
deserialization, ACPBus send/publish/subscribe/broadcast/get_messages/clear,
edge cases: empty payloads, missing fields, invalid status, correlation,
expiry, delivery tracking.
"""

import json
import pytest
from agentic_ai.protocol.acp import (
    ACPMessage,
    ACPBus,
    MessageType,
    Priority,
)


# ---------------------------------------------------------------------------
# MessageType enum
# ---------------------------------------------------------------------------

class TestMessageType:
    """MessageType enum values and string behaviour."""

    def test_all_message_types_exist(self):
        expected = [
            "request", "response", "event", "notification", "error",
            "task_request", "task_response", "task_update", "task_complete",
            "task_accept", "task_reject", "task_result", "task_progress",
            "query", "broadcast",
        ]
        for val in expected:
            assert MessageType(val).value == val

    def test_message_type_is_string(self):
        assert isinstance(MessageType.REQUEST, str)
        assert MessageType.REQUEST == "request"

    def test_message_type_from_value(self):
        assert MessageType("task_request") is MessageType.TASK_REQUEST

    def test_invalid_message_type_raises(self):
        with pytest.raises(ValueError):
            MessageType("nonexistent")

    def test_message_type_count(self):
        assert len(MessageType) == 15


# ---------------------------------------------------------------------------
# Priority enum
# ---------------------------------------------------------------------------

class TestPriority:
    """Priority enum values and string behaviour."""

    def test_all_priorities_exist(self):
        expected = ["low", "normal", "high", "urgent"]
        for val in expected:
            assert Priority(val).value == val

    def test_priority_is_string(self):
        assert isinstance(Priority.NORMAL, str)
        assert Priority.NORMAL == "normal"

    def test_invalid_priority_raises(self):
        with pytest.raises(ValueError):
            Priority("critical")

    def test_priority_count(self):
        assert len(Priority) == 4


# ---------------------------------------------------------------------------
# ACPMessage creation
# ---------------------------------------------------------------------------

class TestACPMessageCreation:
    """ACPMessage defaults and custom creation."""

    def test_default_message(self):
        msg = ACPMessage()
        assert msg.message_id  # non-empty
        assert msg.message_type == MessageType.REQUEST
        assert msg.type == MessageType.REQUEST
        assert msg.priority == Priority.NORMAL
        assert msg.sender == ""
        assert msg.recipient == ""
        assert msg.subject == ""
        assert msg.channel == ""
        assert msg.body == {}
        assert msg.created_at  # non-empty
        assert msg.expires_at is None
        assert msg.correlation_id is None
        assert msg.delivered is False
        assert msg.delivered_at is None

    def test_id_property(self):
        msg = ACPMessage()
        assert msg.id == msg.message_id

    def test_custom_message(self):
        # Note: `type` parameter takes precedence over `message_type` in __post_init__
        msg = ACPMessage(
            type=MessageType.TASK_REQUEST,
            priority=Priority.HIGH,
            sender="agent-a",
            recipient="agent-b",
            subject="do-work",
            body={"task": "scan"},
            correlation_id="corr-123",
            expires_at="2026-12-31T00:00:00Z",
        )
        assert msg.message_type == MessageType.TASK_REQUEST
        assert msg.type == MessageType.TASK_REQUEST
        assert msg.priority == Priority.HIGH
        assert msg.sender == "agent-a"
        assert msg.recipient == "agent-b"
        assert msg.subject == "do-work"
        assert msg.body == {"task": "scan"}
        assert msg.correlation_id == "corr-123"
        assert msg.expires_at == "2026-12-31T00:00:00Z"

    def test_type_alias_syncs_message_type(self):
        """Setting `type` should sync to `message_type` via __post_init__."""
        msg = ACPMessage(type=MessageType.ERROR)
        assert msg.message_type == MessageType.ERROR
        assert msg.type == MessageType.ERROR

    def test_message_type_syncs_type(self):
        """Setting `type` syncs to `message_type` via __post_init__."""
        # `type` is the authoritative field (defined after message_type in dataclass)
        msg = ACPMessage(type=MessageType.BROADCAST)
        assert msg.type == MessageType.BROADCAST
        assert msg.message_type == MessageType.BROADCAST

    def test_empty_body(self):
        msg = ACPMessage(body={})
        assert msg.body == {}

    def test_nested_body(self):
        body = {"data": {"nested": [1, 2, 3]}}
        msg = ACPMessage(body=body)
        assert msg.body == body

    def test_channel_field(self):
        # channel is stored on the message but not serialized to to_dict
        msg = ACPMessage(channel="ops-alerts")
        assert msg.channel == "ops-alerts"
        assert "channel" not in msg.to_dict()


# ---------------------------------------------------------------------------
# ACPMessage serialization: to_dict / to_json
# ---------------------------------------------------------------------------

class TestACPMessageSerialization:
    """to_dict and to_json round-trip."""

    def test_to_dict_keys(self):
        msg = ACPMessage()
        d = msg.to_dict()
        expected_keys = {
            "id", "message_id", "message_type", "type", "priority",
            "sender", "recipient", "subject", "body",
            "created_at", "expires_at", "correlation_id",
            "delivered", "delivered_at",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values_are_primitives(self):
        """All values in to_dict should be JSON-serialisable primitives."""
        msg = ACPMessage(
            sender="a", recipient="b", subject="sub",
            body={"x": 1}, correlation_id="c1",
        )
        d = msg.to_dict()
        # No enum objects — everything should be str/int/bool/dict/list/None
        for v in d.values():
            assert isinstance(v, (str, int, float, bool, dict, list, type(None)))

    def test_to_json_is_valid_json(self):
        msg = ACPMessage(sender="a", recipient="b")
        j = msg.to_json()
        parsed = json.loads(j)
        assert parsed["sender"] == "a"
        assert parsed["recipient"] == "b"

    def test_to_json_roundtrip(self):
        msg = ACPMessage(
            message_type=MessageType.TASK_RESPONSE,
            priority=Priority.URGENT,
            sender="src",
            recipient="dst",
            subject="hello",
            body={"key": "val"},
            correlation_id="abc",
        )
        restored = ACPMessage.from_json(msg.to_json())
        assert restored.message_id == msg.message_id
        assert restored.message_type == msg.message_type
        assert restored.type == msg.type
        assert restored.priority == msg.priority
        assert restored.sender == msg.sender
        assert restored.recipient == msg.recipient
        assert restored.subject == msg.subject
        assert restored.body == msg.body
        assert restored.correlation_id == msg.correlation_id


# ---------------------------------------------------------------------------
# ACPMessage deserialization: from_dict / from_json
# ---------------------------------------------------------------------------

class TestACPMessageDeserialization:
    """from_dict and from_json creation."""

    def test_from_dict_basic(self):
        data = {
            "id": "msg-1",
            "type": "task_request",
            "priority": "high",
            "sender": "a",
            "recipient": "b",
            "subject": "test",
            "body": {"x": 1},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
            "correlation_id": "c1",
            "delivered": True,
            "delivered_at": "2026-01-01T00:01:00Z",
        }
        msg = ACPMessage.from_dict(data)
        assert msg.message_id == "msg-1"
        assert msg.message_type == MessageType.TASK_REQUEST
        assert msg.type == MessageType.TASK_REQUEST
        assert msg.priority == Priority.HIGH
        assert msg.sender == "a"
        assert msg.recipient == "b"
        assert msg.subject == "test"
        assert msg.body == {"x": 1}
        assert msg.created_at == "2026-01-01T00:00:00Z"
        assert msg.expires_at == "2026-12-31T00:00:00Z"
        assert msg.correlation_id == "c1"
        assert msg.delivered is True
        assert msg.delivered_at == "2026-01-01T00:01:00Z"

    def test_from_dict_with_message_id_key(self):
        """Should accept 'message_id' key as well as 'id'."""
        data = {"message_id": "mid-2", "type": "request"}
        msg = ACPMessage.from_dict(data)
        assert msg.message_id == "mid-2"

    def test_from_dict_id_takes_precedence(self):
        """When both 'id' and 'message_id' are present, 'id' wins."""
        data = {"id": "id-val", "message_id": "mid-val", "type": "request"}
        msg = ACPMessage.from_dict(data)
        assert msg.message_id == "id-val"

    def test_from_dict_uses_message_type_key(self):
        """Should accept 'message_type' as key when 'type' is absent."""
        data = {"message_type": "error"}
        msg = ACPMessage.from_dict(data)
        assert msg.message_type == MessageType.ERROR

    def test_from_dict_defaults(self):
        """Empty dict should produce defaults."""
        msg = ACPMessage.from_dict({})
        assert msg.sender == ""
        assert msg.recipient == ""
        assert msg.subject == ""
        assert msg.channel == ""
        assert msg.body == {}
        assert msg.priority == Priority.NORMAL
        assert msg.delivered is False
        assert msg.delivered_at is None
        assert msg.expires_at is None
        assert msg.correlation_id is None

    def test_from_dict_invalid_type_raises(self):
        data = {"type": "invalid_type"}
        with pytest.raises(ValueError):
            ACPMessage.from_dict(data)

    def test_from_dict_invalid_priority_raises(self):
        data = {"type": "request", "priority": "super_high"}
        with pytest.raises(ValueError):
            ACPMessage.from_dict(data)

    def test_from_json_basic(self):
        j = json.dumps({"id": "j1", "type": "broadcast", "priority": "low"})
        msg = ACPMessage.from_json(j)
        assert msg.message_id == "j1"
        assert msg.message_type == MessageType.BROADCAST
        assert msg.priority == Priority.LOW

    def test_from_json_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            ACPMessage.from_json("{not valid json}")

    def test_from_dict_preserves_channel(self):
        data = {"channel": "my-channel", "type": "request"}
        msg = ACPMessage.from_dict(data)
        assert msg.channel == "my-channel"


# ---------------------------------------------------------------------------
# ACPMessage delivery tracking
# ---------------------------------------------------------------------------

class TestACPMessageDelivery:
    """Delivery flag and timestamp."""

    def test_default_not_delivered(self):
        msg = ACPMessage()
        assert msg.delivered is False
        assert msg.delivered_at is None

    def test_mark_delivered(self):
        msg = ACPMessage()
        msg.delivered = True
        msg.delivered_at = "2026-06-01T00:00:00Z"
        assert msg.delivered is True
        assert msg.delivered_at == "2026-06-01T00:00:00Z"
        d = msg.to_dict()
        assert d["delivered"] is True
        assert d["delivered_at"] == "2026-06-01T00:00:00Z"


# ---------------------------------------------------------------------------
# ACPBus: publish, subscribe, send
# ---------------------------------------------------------------------------

class TestACPBus:
    """ACPBus send/publish/subscribe/broadcast/get_messages/clear."""

    def test_bus_creation(self):
        bus = ACPBus(agent_id="test-agent")
        assert bus.agent_id == "test-agent"
        assert bus.redis is None
        assert bus._messages == []

    def test_publish_stores_message(self):
        bus = ACPBus()
        msg = ACPMessage(subject="test-topic", sender="a")
        bus.publish(msg)
        assert len(bus._messages) == 1
        assert bus._messages[0] is msg

    def test_send_calls_publish(self):
        bus = ACPBus()
        msg = ACPMessage(subject="test-topic", recipient="b")
        bus.send(msg)
        assert len(bus._messages) == 1

    def test_subscribe_and_callback(self):
        received = []
        bus = ACPBus()
        bus.subscribe("alerts", lambda m: received.append(m))
        msg = ACPMessage(subject="alerts")
        bus.publish(msg)
        assert len(received) == 1
        assert received[0] is msg

    def test_subscribe_multiple_callbacks(self):
        results_a = []
        results_b = []
        bus = ACPBus()
        bus.subscribe("topic", lambda m: results_a.append(m))
        bus.subscribe("topic", lambda m: results_b.append(m))
        msg = ACPMessage(subject="topic")
        bus.publish(msg)
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_subscribe_different_topics(self):
        results_a = []
        results_b = []
        bus = ACPBus()
        bus.subscribe("alpha", lambda m: results_a.append(m))
        bus.subscribe("beta", lambda m: results_b.append(m))
        bus.publish(ACPMessage(subject="alpha"))
        bus.publish(ACPMessage(subject="beta"))
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_subscriber_exception_does_not_crash(self):
        """If a subscriber throws, other subscribers still get the message."""
        results = []
        bus = ACPBus()

        def bad_cb(m):
            raise RuntimeError("subscriber error")

        bus.subscribe("topic", bad_cb)
        bus.subscribe("topic", lambda m: results.append(m))
        bus.publish(ACPMessage(subject="topic"))
        assert len(results) == 1

    def test_no_subscribers_for_topic(self):
        """Publishing to a topic with no subscribers should not error."""
        bus = ACPBus()
        bus.publish(ACPMessage(subject="nobody-here"))
        assert len(bus._messages) == 1

    def test_broadcast(self):
        received = []
        bus = ACPBus()
        bus.subscribe("broadcast", lambda m: received.append(m))
        bus.broadcast(ACPMessage(subject="broadcast", body={"msg": "to all"}))
        assert len(received) == 1
        assert len(bus._messages) == 1


# ---------------------------------------------------------------------------
# ACPBus: get_messages filters
# ---------------------------------------------------------------------------

class TestACPBusGetMessages:
    """Filtering messages by sender, recipient, message_type."""

    def setup_method(self):
        self.bus = ACPBus()
        self.m1 = ACPMessage(sender="alice", recipient="bob", type=MessageType.REQUEST, subject="s1")
        self.m2 = ACPMessage(sender="bob", recipient="alice", type=MessageType.RESPONSE, subject="s2")
        self.m3 = ACPMessage(sender="alice", recipient="carol", type=MessageType.EVENT, subject="s3")
        self.bus.publish(self.m1)
        self.bus.publish(self.m2)
        self.bus.publish(self.m3)

    def test_get_all_messages(self):
        msgs = self.bus.get_messages()
        assert len(msgs) == 3

    def test_filter_by_sender(self):
        msgs = self.bus.get_messages(sender="alice")
        assert len(msgs) == 2
        assert all(m.sender == "alice" for m in msgs)

    def test_filter_by_recipient(self):
        msgs = self.bus.get_messages(recipient="alice")
        assert len(msgs) == 1
        assert msgs[0].recipient == "alice"

    def test_filter_by_message_type(self):
        msgs = self.bus.get_messages(message_type=MessageType.RESPONSE)
        assert len(msgs) == 1
        assert msgs[0].message_type == MessageType.RESPONSE

    def test_filter_by_sender_and_type(self):
        msgs = self.bus.get_messages(sender="bob", message_type=MessageType.RESPONSE)
        assert len(msgs) == 1
        assert msgs[0] is self.m2

    def test_filter_no_results(self):
        msgs = self.bus.get_messages(sender="nobody")
        assert msgs == []

    def test_filter_by_all_three(self):
        msgs = self.bus.get_messages(sender="alice", recipient="bob", message_type=MessageType.REQUEST)
        assert len(msgs) == 1
        assert msgs[0] is self.m1


# ---------------------------------------------------------------------------
# ACPBus: clear
# ---------------------------------------------------------------------------

class TestACPBusClear:
    """Clear all messages from the bus."""

    def test_clear_empties_messages(self):
        bus = ACPBus()
        bus.publish(ACPMessage())
        bus.publish(ACPMessage())
        assert len(bus._messages) == 2
        bus.clear()
        assert len(bus._messages) == 0

    def test_clear_does_not_remove_subscribers(self):
        bus = ACPBus()
        bus.subscribe("topic", lambda m: None)
        bus.clear()
        assert "topic" in bus._subscribers


# ---------------------------------------------------------------------------
# ACPMessage edge cases
# ---------------------------------------------------------------------------

class TestACPMessageEdgeCases:
    """Edge cases: empty payloads, special characters, large bodies."""

    def test_empty_body_serialization(self):
        msg = ACPMessage(body={})
        d = msg.to_dict()
        assert d["body"] == {}

    def test_large_body(self):
        body = {f"key_{i}": f"value_{i}" for i in range(100)}
        msg = ACPMessage(body=body)
        restored = ACPMessage.from_json(msg.to_json())
        assert restored.body == body

    def test_special_characters_in_subject(self):
        msg = ACPMessage(subject="hello 🌍! <script>")
        d = msg.to_dict()
        assert d["subject"] == "hello 🌍! <script>"

    def test_null_fields_in_to_dict(self):
        msg = ACPMessage()
        d = msg.to_dict()
        assert d["expires_at"] is None
        assert d["correlation_id"] is None
        assert d["delivered_at"] is None

    def test_multiple_messages_unique_ids(self):
        ids = set()
        for _ in range(50):
            msg = ACPMessage()
            ids.add(msg.message_id)
        assert len(ids) == 50

    def test_from_dict_roundtrip_preserves_data(self):
        original = ACPMessage(
            type=MessageType.TASK_PROGRESS,
            priority=Priority.LOW,
            sender="src",
            recipient="dst",
            subject="progress-update",
            body={"percent": 75},
            expires_at="2026-12-31T23:59:59Z",
            correlation_id="corr-xyz",
            delivered=True,
            delivered_at="2026-06-01T12:00:00Z",
        )
        d = original.to_dict()
        restored = ACPMessage.from_dict(d)
        assert restored.message_id == original.message_id
        assert restored.message_type == original.message_type
        assert restored.priority == original.priority
        assert restored.sender == original.sender
        assert restored.recipient == original.recipient
        assert restored.subject == original.subject
        # Note: channel is not part of to_dict/from_dict serialization
        assert restored.body == original.body
        assert restored.expires_at == original.expires_at
        assert restored.correlation_id == original.correlation_id
        assert restored.delivered == original.delivered
        assert restored.delivered_at == original.delivered_at

    def test_all_message_types_serialize(self):
        """Every MessageType value should survive serialization round-trip."""
        for mt in MessageType:
            msg = ACPMessage(type=mt)  # use `type` not `message_type` due to __post_init__
            d = msg.to_dict()
            assert d["message_type"] == mt.value
            assert d["type"] == mt.value
            restored = ACPMessage.from_dict(d)
            assert restored.message_type == mt

    def test_all_priorities_serialize(self):
        for p in Priority:
            msg = ACPMessage(priority=p)
            d = msg.to_dict()
            assert d["priority"] == p.value
            restored = ACPMessage.from_dict(d)
            assert restored.priority == p


# ---------------------------------------------------------------------------
# ACPBus Redis integration (mocked)
# ---------------------------------------------------------------------------

class TestACPBusRedis:
    """ACPBus Redis integration paths (mocked)."""

    def test_send_with_redis(self):
        """send() should call redis.publish and redis.lpush when redis is set."""
        bus = ACPBus()
        calls = []

        class FakeRedis:
            def publish(self, channel, msg_id):
                calls.append(("publish", channel, msg_id))

            def lpush(self, key, msg_id):
                calls.append(("lpush", key, msg_id))

        bus.redis = FakeRedis()
        msg = ACPMessage(subject="test-topic", recipient="agent-b")
        bus.send(msg)
        assert any(c[0] == "publish" and c[1] == "test-topic" for c in calls)
        assert any(c[0] == "lpush" and c[1] == "queue:agent-b" for c in calls)

    def test_send_redis_exception_swallowed(self):
        """Redis errors in send() should be silently swallowed."""
        bus = ACPBus()

        class BrokenRedis:
            def publish(self, *a, **kw):
                raise RuntimeError("redis down")

            def lpush(self, *a, **kw):
                raise RuntimeError("redis down")

        bus.redis = BrokenRedis()
        msg = ACPMessage(subject="test", recipient="b")
        # Should not raise
        bus.send(msg)
        assert len(bus._messages) == 1

    def test_broadcast_with_redis(self):
        """broadcast() should call redis.publish on 'broadcast' channel."""
        bus = ACPBus()
        calls = []

        class FakeRedis:
            def publish(self, channel, msg_id):
                calls.append((channel, msg_id))

        bus.redis = FakeRedis()
        msg = ACPMessage(subject="alert")
        bus.broadcast(msg)
        assert len(calls) == 1
        assert calls[0][0] == "broadcast"

    def test_broadcast_redis_exception_swallowed(self):
        bus = ACPBus()

        class BrokenRedis:
            def publish(self, *a, **kw):
                raise RuntimeError("redis down")

        bus.redis = BrokenRedis()
        msg = ACPMessage(subject="alert")
        bus.broadcast(msg)
        assert len(bus._messages) == 1

    def test_send_redis_default_subject(self):
        """When subject is empty, redis.publish should use 'default'."""
        bus = ACPBus()
        calls = []

        class FakeRedis:
            def publish(self, channel, msg_id):
                calls.append(("publish", channel, msg_id))

            def lpush(self, key, msg_id):
                calls.append(("lpush", key, msg_id))

        bus.redis = FakeRedis()
        msg = ACPMessage(recipient="agent-b")  # no subject
        bus.send(msg)
        assert any(c[0] == "publish" and c[1] == "default" for c in calls)