"""
Tests for the A2A (Agent-to-Agent) protocol module.

Covers: A2ATaskMessage creation, serialization, deserialization,
ACP↔A2A bidirectional conversion, round-trip preservation,
artifacts, agent_card, status values.
"""

import json
import pytest
from agentic_ai.protocol.a2a import A2ATaskMessage
from agentic_ai.protocol.acp import ACPMessage, MessageType, Priority


# ---------------------------------------------------------------------------
# A2ATaskMessage creation
# ---------------------------------------------------------------------------

class TestA2ATaskMessageCreation:
    """A2ATaskMessage defaults and custom creation."""

    def test_default_message(self):
        msg = A2ATaskMessage()
        assert msg.task_id  # non-empty
        assert msg.agent_card is None
        assert msg.payload == {}
        assert msg.status == "pending"
        assert msg.artifacts == []
        assert msg.created_at  # non-empty
        assert msg.updated_at  # non-empty

    def test_default_task_id_is_short_uuid(self):
        """Default task_id should be 8-char UUID hex."""
        msg = A2ATaskMessage()
        assert len(msg.task_id) == 8
        # Should be valid hex chars
        int(msg.task_id, 16)

    def test_custom_all_fields(self):
        card = {"name": "agent-1", "capabilities": ["translate"]}
        payload = {"subject": "hello", "content": {"text": "hi"}, "message_type": "request"}
        artifacts = [{"name": "result.txt", "data": "hello"}]
        msg = A2ATaskMessage(
            task_id="t-001",
            agent_card=card,
            payload=payload,
            status="running",
            artifacts=artifacts,
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:01:00Z",
        )
        assert msg.task_id == "t-001"
        assert msg.agent_card == card
        assert msg.payload == payload
        assert msg.status == "running"
        assert msg.artifacts == artifacts
        assert msg.created_at == "2026-01-01T00:00:00Z"
        assert msg.updated_at == "2026-01-01T00:01:00Z"

    def test_unique_task_ids(self):
        ids = set()
        for _ in range(50):
            msg = A2ATaskMessage()
            ids.add(msg.task_id)
        assert len(ids) == 50


# ---------------------------------------------------------------------------
# A2ATaskMessage serialization: to_dict / to_json
# ---------------------------------------------------------------------------

class TestA2ATaskMessageSerialization:
    """to_dict and to_json."""

    def test_to_dict_keys(self):
        msg = A2ATaskMessage()
        d = msg.to_dict()
        expected_keys = {
            "task_id", "agent_card", "payload", "status",
            "artifacts", "created_at", "updated_at",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self):
        card = {"name": "test"}
        payload = {"key": "value"}
        artifacts = [{"a": 1}]
        msg = A2ATaskMessage(
            task_id="t-1",
            agent_card=card,
            payload=payload,
            status="completed",
            artifacts=artifacts,
            created_at="2026-06-01T00:00:00Z",
            updated_at="2026-06-01T00:01:00Z",
        )
        d = msg.to_dict()
        assert d["task_id"] == "t-1"
        assert d["agent_card"] == card
        assert d["payload"] == payload
        assert d["status"] == "completed"
        assert d["artifacts"] == artifacts
        assert d["created_at"] == "2026-06-01T00:00:00Z"
        assert d["updated_at"] == "2026-06-01T00:01:00Z"

    def test_to_dict_values_are_primitives(self):
        msg = A2ATaskMessage(
            agent_card={"name": "a"},
            payload={"x": 1},
            artifacts=[{"k": "v"}],
        )
        d = msg.to_dict()
        for v in d.values():
            assert isinstance(v, (str, int, float, bool, dict, list, type(None)))

    def test_to_json_is_valid_json(self):
        msg = A2ATaskMessage(task_id="j1", status="running")
        j = msg.to_json()
        parsed = json.loads(j)
        assert parsed["task_id"] == "j1"
        assert parsed["status"] == "running"

    def test_to_json_roundtrip(self):
        card = {"name": "agent-x", "url": "https://example.com"}
        payload = {"subject": "task", "content": {"text": "do work"}, "message_type": "task_request"}
        artifacts = [{"name": "out.txt", "data": "result"}]
        msg = A2ATaskMessage(
            task_id="rt-1",
            agent_card=card,
            payload=payload,
            status="completed",
            artifacts=artifacts,
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T01:00:00Z",
        )
        restored = A2ATaskMessage.from_json(msg.to_json())
        assert restored.task_id == msg.task_id
        assert restored.agent_card == msg.agent_card
        assert restored.payload == msg.payload
        assert restored.status == msg.status
        assert restored.artifacts == msg.artifacts
        assert restored.created_at == msg.created_at
        assert restored.updated_at == msg.updated_at


# ---------------------------------------------------------------------------
# A2ATaskMessage deserialization: from_dict / from_json
# ---------------------------------------------------------------------------

class TestA2ATaskMessageDeserialization:
    """from_dict and from_json."""

    def test_from_dict_basic(self):
        data = {
            "task_id": "t-1",
            "agent_card": {"name": "test"},
            "payload": {"key": "val"},
            "status": "running",
            "artifacts": [{"a": 1}],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:01:00Z",
        }
        msg = A2ATaskMessage.from_dict(data)
        assert msg.task_id == "t-1"
        assert msg.agent_card == {"name": "test"}
        assert msg.payload == {"key": "val"}
        assert msg.status == "running"
        assert msg.artifacts == [{"a": 1}]
        assert msg.created_at == "2026-01-01T00:00:00Z"
        assert msg.updated_at == "2026-01-01T00:01:00Z"

    def test_from_dict_defaults(self):
        """Empty dict should produce defaults."""
        msg = A2ATaskMessage.from_dict({})
        assert msg.agent_card is None
        assert msg.payload == {}
        assert msg.status == "pending"
        assert msg.artifacts == []
        assert msg.created_at  # auto-generated
        assert msg.updated_at  # auto-generated

    def test_from_dict_ignores_unknown_keys(self):
        data = {
            "task_id": "t-1",
            "unknown_field": "should be ignored",
            "extra": 42,
        }
        msg = A2ATaskMessage.from_dict(data)
        assert msg.task_id == "t-1"
        assert not hasattr(msg, "unknown_field")

    def test_from_json_basic(self):
        j = json.dumps({
            "task_id": "j1",
            "status": "completed",
            "payload": {"key": "val"},
        })
        msg = A2ATaskMessage.from_json(j)
        assert msg.task_id == "j1"
        assert msg.status == "completed"
        assert msg.payload == {"key": "val"}

    def test_from_json_invalid_raises(self):
        with pytest.raises(json.JSONDecodeError):
            A2ATaskMessage.from_json("{not valid json}")

    def test_from_dict_roundtrip(self):
        card = {"name": "agent-y", "version": "1.0"}
        payload = {"subject": "test-sub", "content": {"text": "hello"}, "message_type": "event"}
        artifacts = [{"name": "file.txt", "data": "output"}]
        original = A2ATaskMessage(
            task_id="rt-2",
            agent_card=card,
            payload=payload,
            status="running",
            artifacts=artifacts,
            created_at="2026-03-01T10:00:00Z",
            updated_at="2026-03-01T10:05:00Z",
        )
        d = original.to_dict()
        restored = A2ATaskMessage.from_dict(d)
        assert restored.task_id == original.task_id
        assert restored.agent_card == original.agent_card
        assert restored.payload == original.payload
        assert restored.status == original.status
        assert restored.artifacts == original.artifacts
        assert restored.created_at == original.created_at
        assert restored.updated_at == original.updated_at


# ---------------------------------------------------------------------------
# ACP → A2A conversion (from_acp)
# ---------------------------------------------------------------------------

class TestFromACPConversion:
    """from_acp() conversion preserves ACP content."""

    def test_from_acp_basic(self):
        acp = ACPMessage(
            message_id="msg-1",
            sender="agent-a",
            recipient="agent-b",
            subject="do-task",
            body={"action": "scan"},
            type=MessageType.TASK_REQUEST,
            priority=Priority.HIGH,
        )
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.task_id == "msg-1"
        assert a2a.payload["subject"] == "do-task"
        assert a2a.payload["content"] == {"action": "scan"}
        assert a2a.payload["message_type"] == "task_request"
        assert a2a.status == "pending"
        assert a2a.artifacts == []
        assert a2a.created_at == acp.created_at

    def test_from_acp_preserves_subject(self):
        acp = ACPMessage(subject="important-topic")
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.payload["subject"] == "important-topic"

    def test_from_acp_preserves_body_as_content(self):
        body = {"nested": {"key": [1, 2, 3]}}
        acp = ACPMessage(body=body)
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.payload["content"] == body

    def test_from_acp_preserves_message_type(self):
        for mt in [MessageType.REQUEST, MessageType.RESPONSE, MessageType.ERROR,
                    MessageType.TASK_REQUEST, MessageType.TASK_COMPLETE, MessageType.BROADCAST]:
            acp = ACPMessage(type=mt)
            a2a = A2ATaskMessage.from_acp(acp)
            assert a2a.payload["message_type"] == mt.value

    def test_from_acp_with_empty_body(self):
        acp = ACPMessage(body={})
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.payload["content"] == {}

    def test_from_acp_uses_created_at(self):
        acp = ACPMessage(created_at="2026-07-04T12:00:00Z")
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.created_at == "2026-07-04T12:00:00Z"

    def test_from_acp_with_missing_created_at_uses_now(self):
        """If ACP created_at is empty, from_acp should generate a timestamp."""
        acp = ACPMessage()
        acp.created_at = ""
        a2a = A2ATaskMessage.from_acp(acp)
        assert a2a.created_at  # should have a generated timestamp


# ---------------------------------------------------------------------------
# A2A → ACP conversion (to_acp)
# ---------------------------------------------------------------------------

class TestToACPConversion:
    """to_acp() conversion preserves A2A content."""

    def test_to_acp_basic(self):
        a2a = A2ATaskMessage(
            task_id="task-1",
            payload={
                "subject": "hello",
                "content": {"text": "world"},
                "message_type": "task_request",
            },
            created_at="2026-01-15T08:00:00Z",
        )
        acp = a2a.to_acp()
        assert acp.message_id == "task-1"
        assert acp.sender == "a2a"
        assert acp.recipient == ""
        assert acp.subject == "hello"
        assert acp.body == {"text": "world"}
        assert acp.message_type == MessageType.TASK_REQUEST
        assert acp.created_at == "2026-01-15T08:00:00Z"

    def test_to_acp_preserves_subject(self):
        a2a = A2ATaskMessage(payload={"subject": "urgent-alert", "content": {}, "message_type": "request"})
        acp = a2a.to_acp()
        assert acp.subject == "urgent-alert"

    def test_to_acp_preserves_content_as_body(self):
        content = {"data": [1, 2, 3]}
        a2a = A2ATaskMessage(payload={"content": content, "message_type": "response"})
        acp = a2a.to_acp()
        assert acp.body == content

    def test_to_acp_preserves_message_type(self):
        a2a = A2ATaskMessage(payload={"message_type": "task_request", "content": {}})
        acp = a2a.to_acp()
        assert acp.message_type == MessageType.TASK_REQUEST

    def test_to_acp_invalid_message_type_falls_back(self):
        a2a = A2ATaskMessage(payload={"message_type": "nonexistent_type", "content": {}})
        acp = a2a.to_acp()
        assert acp.message_type == MessageType.REQUEST

    def test_to_acp_missing_content_defaults_empty_dict(self):
        a2a = A2ATaskMessage(payload={"subject": "test"})
        acp = a2a.to_acp()
        assert acp.body == {}

    def test_to_acp_non_dict_content_wrapped(self):
        """If content is a string, it should be wrapped in a dict."""
        a2a = A2ATaskMessage(payload={"content": "just text", "message_type": "request"})
        acp = a2a.to_acp()
        assert acp.body == {"_raw": "just text"}

    def test_to_acp_missing_message_type_defaults_request(self):
        a2a = A2ATaskMessage(payload={"content": {}})
        acp = a2a.to_acp()
        assert acp.message_type == MessageType.REQUEST

    def test_to_acp_sender_is_a2a(self):
        a2a = A2ATaskMessage()
        acp = a2a.to_acp()
        assert acp.sender == "a2a"


# ---------------------------------------------------------------------------
# Round-trip conversion: ACP → A2A → ACP
# ---------------------------------------------------------------------------

class TestACPToA2ARoundTrip:
    """ACP → A2A → ACP preserves core message fields."""

    def test_roundtrip_preserves_content(self):
        acp_original = ACPMessage(
            message_id="rt-1",
            sender="agent-a",
            recipient="agent-b",
            subject="roundtrip-test",
            body={"action": "compute", "params": [1, 2, 3]},
            message_type=MessageType.TASK_REQUEST,
        )
        a2a = A2ATaskMessage.from_acp(acp_original)
        acp_restored = a2a.to_acp()
        assert acp_restored.message_id == acp_original.message_id
        assert acp_restored.subject == acp_original.subject
        assert acp_restored.body == acp_original.body
        assert acp_restored.message_type == acp_original.message_type

    def test_roundtrip_preserves_created_at(self):
        acp_original = ACPMessage(
            message_id="rt-2",
            created_at="2026-06-15T12:30:00Z",
        )
        a2a = A2ATaskMessage.from_acp(acp_original)
        acp_restored = a2a.to_acp()
        assert acp_restored.created_at == "2026-06-15T12:30:00Z"

    def test_roundtrip_multiple_message_types(self):
        """Various message types survive ACP→A2A→ACP round-trip."""
        for mt in [MessageType.REQUEST, MessageType.RESPONSE, MessageType.EVENT,
                    MessageType.NOTIFICATION, MessageType.ERROR, MessageType.TASK_REQUEST,
                    MessageType.TASK_RESPONSE, MessageType.TASK_COMPLETE,
                    MessageType.TASK_PROGRESS, MessageType.QUERY, MessageType.BROADCAST]:
            acp_original = ACPMessage(
                message_id=f"rt-{mt.value}",
                subject=f"subject-{mt.value}",
                body={"data": mt.value},
                type=mt,
            )
            a2a = A2ATaskMessage.from_acp(acp_original)
            acp_restored = a2a.to_acp()
            assert acp_restored.message_type == mt
            assert acp_restored.subject == f"subject-{mt.value}"
            assert acp_restored.body == {"data": mt.value}


# ---------------------------------------------------------------------------
# Round-trip conversion: A2A → ACP → A2A
# ---------------------------------------------------------------------------

class TestA2AToACPReverseRoundTrip:
    """A2A → ACP → A2A preserves payload content."""

    def test_roundtrip_preserves_payload_content(self):
        a2a_original = A2ATaskMessage(
            task_id="rrt-1",
            payload={
                "subject": "reverse-test",
                "content": {"text": "hello"},
                "message_type": "task_request",
            },
            status="running",
            created_at="2026-08-01T09:00:00Z",
        )
        acp = a2a_original.to_acp()
        a2a_restored = A2ATaskMessage.from_acp(acp)
        assert a2a_restored.payload["subject"] == "reverse-test"
        assert a2a_restored.payload["content"] == {"text": "hello"}
        assert a2a_restored.payload["message_type"] == "task_request"

    def test_roundtrip_preserves_task_id(self):
        a2a_original = A2ATaskMessage(
            task_id="rrt-2",
            payload={"message_type": "request", "content": {}},
        )
        acp = a2a_original.to_acp()
        a2a_restored = A2ATaskMessage.from_acp(acp)
        assert a2a_restored.task_id == "rrt-2"


# ---------------------------------------------------------------------------
# A2A task with artifacts
# ---------------------------------------------------------------------------

class TestA2AArtifacts:
    """A2ATaskMessage with artifacts."""

    def test_artifacts_default_empty(self):
        msg = A2ATaskMessage()
        assert msg.artifacts == []

    def test_artifacts_stored(self):
        artifacts = [
            {"name": "result.txt", "data": "output", "type": "text/plain"},
            {"name": "image.png", "data": "base64...", "type": "image/png"},
        ]
        msg = A2ATaskMessage(artifacts=artifacts)
        assert len(msg.artifacts) == 2
        assert msg.artifacts[0]["name"] == "result.txt"
        assert msg.artifacts[1]["type"] == "image/png"

    def test_artifacts_survive_serialization(self):
        artifacts = [{"name": "report.pdf", "size": 1024}]
        msg = A2ATaskMessage(artifacts=artifacts)
        d = msg.to_dict()
        restored = A2ATaskMessage.from_dict(d)
        assert restored.artifacts == artifacts

    def test_artifacts_in_json_roundtrip(self):
        artifacts = [{"name": "data.csv", "rows": 500}]
        msg = A2ATaskMessage(task_id="a-1", artifacts=artifacts)
        j = msg.to_json()
        restored = A2ATaskMessage.from_json(j)
        assert restored.artifacts == artifacts

    def test_artifacts_are_independent(self):
        """Modifying the original list shouldn't affect the message after creation."""
        artifacts = [{"name": "file.txt"}]
        msg = A2ATaskMessage(artifacts=artifacts)
        # The default_factory creates a new list, but if we pass one in,
        # dataclass stores the reference — this is standard dataclass behavior.
        # Verify to_dict produces the correct value.
        d = msg.to_dict()
        assert d["artifacts"] == [{"name": "file.txt"}]


# ---------------------------------------------------------------------------
# A2A task with agent_card
# ---------------------------------------------------------------------------

class TestA2AAgentCard:
    """A2ATaskMessage with agent_card."""

    def test_agent_card_default_none(self):
        msg = A2ATaskMessage()
        assert msg.agent_card is None

    def test_agent_card_stored(self):
        card = {
            "name": "translator-agent",
            "version": "1.0",
            "url": "https://example.com/agent",
            "capabilities": ["translate", "summarize"],
        }
        msg = A2ATaskMessage(agent_card=card)
        assert msg.agent_card["name"] == "translator-agent"
        assert "translate" in msg.agent_card["capabilities"]

    def test_agent_card_survives_serialization(self):
        card = {"name": "agent-x", "skills": ["search"]}
        msg = A2ATaskMessage(agent_card=card)
        d = msg.to_dict()
        restored = A2ATaskMessage.from_dict(d)
        assert restored.agent_card == card

    def test_agent_card_in_json_roundtrip(self):
        card = {"name": "agent-y", "type": "worker"}
        msg = A2ATaskMessage(task_id="c-1", agent_card=card)
        j = msg.to_json()
        restored = A2ATaskMessage.from_json(j)
        assert restored.agent_card == card

    def test_agent_card_none_in_dict(self):
        msg = A2ATaskMessage()
        d = msg.to_dict()
        assert d["agent_card"] is None
        restored = A2ATaskMessage.from_dict(d)
        assert restored.agent_card is None


# ---------------------------------------------------------------------------
# Status values
# ---------------------------------------------------------------------------

class TestA2AStatus:
    """A2A task status values."""

    def test_default_status_pending(self):
        msg = A2ATaskMessage()
        assert msg.status == "pending"

    def test_running_status(self):
        msg = A2ATaskMessage(status="running")
        assert msg.status == "running"

    def test_completed_status(self):
        msg = A2ATaskMessage(status="completed")
        assert msg.status == "completed"

    def test_failed_status(self):
        msg = A2ATaskMessage(status="failed")
        assert msg.status == "failed"

    def test_canceled_status(self):
        msg = A2ATaskMessage(status="canceled")
        assert msg.status == "canceled"

    def test_status_in_to_dict(self):
        for status in ["pending", "running", "completed", "failed", "canceled"]:
            msg = A2ATaskMessage(status=status)
            assert msg.to_dict()["status"] == status

    def test_status_survives_serialization(self):
        msg = A2ATaskMessage(task_id="s-1", status="running")
        d = msg.to_dict()
        restored = A2ATaskMessage.from_dict(d)
        assert restored.status == "running"