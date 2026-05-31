"""
Tests for Real-Time Collaboration
==================================

Unit tests for operational transformation and real-time features.
"""

import pytest
from datetime import datetime, timedelta
from agentic_ai.infrastructure.utils import utcnow


@pytest.fixture
def realtime_imports():
    """Import real-time collaboration modules."""
    from agentic_ai.collaboration.realtime import (
        RealTimeCollaboration, OperationalTransformer, PubSubChannel,
        Operation, OperationType, CursorPosition, ActiveUser, ConnectionStatus
    )
    
    return {
        'RealTimeCollaboration': RealTimeCollaboration,
        'OperationalTransformer': OperationalTransformer,
        'PubSubChannel': PubSubChannel,
        'Operation': Operation,
        'OperationType': OperationType,
        'CursorPosition': CursorPosition,
        'ActiveUser': ActiveUser,
        'ConnectionStatus': ConnectionStatus,
    }


class TestOperation:
    """Test Operation class."""
    
    def test_operation_creation(self, realtime_imports):
        """Test creating an operation."""
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        op = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            position=10,
            content="Hello",
        )
        
        assert op.operation_type == OperationType.INSERT
        assert op.position == 10
        assert op.content == "Hello"
    
    def test_operation_to_dict(self, realtime_imports):
        """Test operation serialization."""
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        op = Operation(
            operation_type=OperationType.DELETE,
            document_id="doc-001",
            length=5,
        )
        
        data = op.to_dict()
        
        assert data["operation_type"] == "delete"
        assert data["length"] == 5
        assert "operation_id" in data
    
    def test_operation_from_dict(self, realtime_imports):
        """Test operation deserialization."""
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        data = {
            "operation_type": "insert",
            "document_id": "doc-001",
            "user_id": "user-1",
            "position": 5,
            "content": "test",
        }
        
        op = Operation.from_dict(data)
        
        assert op.operation_type == OperationType.INSERT
        assert op.position == 5


class TestCursorPosition:
    """Test CursorPosition class."""
    
    def test_cursor_creation(self, realtime_imports):
        """Test creating a cursor position."""
        CursorPosition = realtime_imports['CursorPosition']
        
        cursor = CursorPosition(
            user_id="user-1",
            document_id="doc-001",
            position=42,
            selection_start=40,
            selection_end=45,
        )
        
        assert cursor.user_id == "user-1"
        assert cursor.position == 42
        assert cursor.selection_start == 40
        assert cursor.selection_end == 45
    
    def test_cursor_to_dict(self, realtime_imports):
        """Test cursor serialization."""
        CursorPosition = realtime_imports['CursorPosition']
        
        cursor = CursorPosition(
            user_id="user-1",
            document_id="doc-001",
            position=10,
        )
        
        data = cursor.to_dict()
        
        assert data["user_id"] == "user-1"
        assert data["position"] == 10


class TestActiveUser:
    """Test ActiveUser class."""
    
    def test_active_user_creation(self, realtime_imports):
        """Test creating an active user."""
        ActiveUser = realtime_imports['ActiveUser']
        ConnectionStatus = realtime_imports['ConnectionStatus']
        
        user = ActiveUser(
            user_id="user-1",
            name="Alice",
        )
        
        assert user.user_id == "user-1"
        assert user.name == "Alice"
        assert user.status == ConnectionStatus.CONNECTED
    
    def test_active_user_to_dict(self, realtime_imports):
        """Test active user serialization."""
        ActiveUser = realtime_imports['ActiveUser']
        
        user = ActiveUser(
            user_id="user-1",
            name="Bob",
        )
        
        data = user.to_dict()
        
        assert data["name"] == "Bob"
        assert "user_id" in data
        assert "status" in data


class TestOperationalTransformer:
    """Test OperationalTransformer class."""
    
    def test_transformer_creation(self, realtime_imports):
        """Test creating a transformer."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        
        transformer = OperationalTransformer()
        assert transformer is not None
    
    def test_transform_insert_insert(self, realtime_imports):
        """Test transforming two insert operations."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        transformer = OperationalTransformer()
        
        op1 = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            position=5,
            content="ABC",
        )
        
        op2 = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-2",
            position=5,
            content="XYZ",
        )
        
        op1_prime, op2_prime = transformer.transform(op1, op2)
        
        # op2 should be shifted by op1's content length
        assert op2_prime.position == 8  # 5 + 3 (length of "ABC")
    
    def test_transform_insert_delete(self, realtime_imports):
        """Test transforming insert and delete operations."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        transformer = OperationalTransformer()
        
        insert_op = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            position=10,
            content="NEW",
        )
        
        delete_op = Operation(
            operation_type=OperationType.DELETE,
            document_id="doc-001",
            user_id="user-2",
            position=5,
            length=3,
        )
        
        insert_prime, delete_prime = transformer.transform(insert_op, delete_op)
        
        # Insert after delete should be shifted back
        assert insert_prime.position == 7  # 10 - 3
    
    def test_apply_insert_operation(self, realtime_imports):
        """Test applying an insert operation."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        transformer = OperationalTransformer()
        
        doc = "Hello World"
        op = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            position=5,
            content=",",
        )
        
        result = transformer.apply_operation(doc, op)
        
        assert result == "Hello, World"
    
    def test_apply_delete_operation(self, realtime_imports):
        """Test applying a delete operation."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        transformer = OperationalTransformer()
        
        doc = "Hello World"
        op = Operation(
            operation_type=OperationType.DELETE,
            document_id="doc-001",
            position=5,
            length=1,
        )
        
        result = transformer.apply_operation(doc, op)
        
        assert result == "HelloWorld"
    
    def test_apply_update_operation(self, realtime_imports):
        """Test applying an update operation."""
        OperationalTransformer = realtime_imports['OperationalTransformer']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        transformer = OperationalTransformer()
        
        doc = "Old Content"
        op = Operation(
            operation_type=OperationType.UPDATE,
            document_id="doc-001",
            content="New Content",
        )
        
        result = transformer.apply_operation(doc, op)
        
        assert result == "New Content"


class TestPubSubChannel:
    """Test PubSubChannel class."""
    
    def test_channel_creation(self, realtime_imports):
        """Test creating a pub-sub channel."""
        PubSubChannel = realtime_imports['PubSubChannel']
        
        channel = PubSubChannel(channel_id="test-channel")
        
        assert channel.channel_id == "test-channel"
        assert channel.get_subscriber_count() == 0
    
    def test_subscribe_unsubscribe(self, realtime_imports):
        """Test subscribing and unsubscribing."""
        PubSubChannel = realtime_imports['PubSubChannel']
        
        channel = PubSubChannel(channel_id="test")
        
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        # Subscribe
        success = channel.subscribe("sub-1", callback)
        assert success is True
        assert channel.get_subscriber_count() == 1
        
        # Unsubscribe
        success = channel.unsubscribe("sub-1")
        assert success is True
        assert channel.get_subscriber_count() == 0
    
    def test_publish_event(self, realtime_imports):
        """Test publishing an event."""
        PubSubChannel = realtime_imports['PubSubChannel']
        
        channel = PubSubChannel(channel_id="test")
        
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        channel.subscribe("sub-1", callback)
        channel.subscribe("sub-2", callback)
        
        event = {"type": "test", "data": "value"}
        channel.publish(event)
        
        assert len(received_events) == 2
    
    def test_publish_with_exclude(self, realtime_imports):
        """Test publishing with exclusion."""
        PubSubChannel = realtime_imports['PubSubChannel']
        
        channel = PubSubChannel(channel_id="test")
        
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        channel.subscribe("sub-1", callback)
        channel.subscribe("sub-2", callback)
        
        event = {"type": "test"}
        channel.publish(event, exclude={"sub-1"})
        
        assert len(received_events) == 1


class TestRealTimeCollaboration:
    """Test RealTimeCollaboration class."""
    
    def test_collaboration_creation(self, realtime_imports):
        """Test creating real-time collaboration manager."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        
        assert rtc is not None
    
    def test_connect_user(self, realtime_imports):
        """Test connecting a user."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        user = rtc.connect_user("user-1", name="Alice")
        
        assert user.user_id == "user-1"
        assert user.name == "Alice"
    
    def test_disconnect_user(self, realtime_imports):
        """Test disconnecting a user."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        ConnectionStatus = realtime_imports['ConnectionStatus']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1", name="Alice")
        rtc.disconnect_user("user-1")
        
        users = rtc.get_active_users()
        assert len(users) == 0
    
    def test_get_active_users(self, realtime_imports):
        """Test getting active users."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1", name="Alice")
        rtc.connect_user("user-2", name="Bob")
        
        users = rtc.get_active_users()
        
        assert len(users) == 2
    
    def test_update_cursor(self, realtime_imports):
        """Test updating cursor position."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1", name="Alice")
        
        rtc.update_cursor(
            user_id="user-1",
            document_id="doc-001",
            position=42,
            selection_start=40,
            selection_end=45,
        )
        
        users = rtc.get_active_users(document_id="doc-001")
        assert len(users) == 1
    
    def test_submit_operation(self, realtime_imports):
        """Test submitting an operation."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        rtc = RealTimeCollaboration()
        
        op = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            position=0,
            content="Hello",
        )
        
        result_op = rtc.submit_operation(op)
        
        assert result_op.version == 1
    
    def test_subscribe_to_document(self, realtime_imports):
        """Test subscribing to document events."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        success = rtc.subscribe("doc-001", "sub-1", callback)
        assert success is True
    
    def test_get_document_state(self, realtime_imports):
        """Test getting document state."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        rtc = RealTimeCollaboration()
        
        op = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            content="test",
        )
        rtc.submit_operation(op)
        
        state = rtc.get_document_state("doc-001")
        
        assert state["version"] == 1
        assert state["document_id"] == "doc-001"
    
    def test_get_collaboration_state(self, realtime_imports):
        """Test getting collaboration state."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1")
        rtc.connect_user("user-2")
        
        state = rtc.get_state()
        
        assert state["total_users"] == 2
        assert state["connected_users"] == 2
    
    def test_cleanup_inactive(self, realtime_imports):
        """Test cleaning up inactive users."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        ConnectionStatus = realtime_imports['ConnectionStatus']
        
        rtc = RealTimeCollaboration()
        user = rtc.connect_user("user-1")
        
        # Manually set old activity time
        from datetime import datetime, timedelta
        user.last_activity = (utcnow() - timedelta(minutes=60)).isoformat()
        
        removed = rtc.cleanup_inactive(inactive_minutes=30)
        
        assert removed >= 1


class TestRealtimeIntegration:
    """Integration tests for real-time collaboration."""
    
    def test_concurrent_operations(self, realtime_imports):
        """Test handling concurrent operations from multiple users."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        Operation = realtime_imports['Operation']
        OperationType = realtime_imports['OperationType']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1", name="Alice")
        rtc.connect_user("user-2", name="Bob")
        
        # Both users submit operations concurrently
        op1 = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-1",
            position=0,
            content="Alice: ",
        )
        
        op2 = Operation(
            operation_type=OperationType.INSERT,
            document_id="doc-001",
            user_id="user-2",
            position=0,
            content="Bob: ",
        )
        
        result1 = rtc.submit_operation(op1)
        result2 = rtc.submit_operation(op2)
        
        # Both operations should have versions
        assert result1.version >= 1
        assert result2.version >= 1
    
    def test_cursor_broadcast(self, realtime_imports):
        """Test cursor position broadcasting."""
        RealTimeCollaboration = realtime_imports['RealTimeCollaboration']
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("user-1", name="Alice")
        rtc.connect_user("user-2", name="Bob")
        
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        rtc.subscribe("doc-001", "user-2", callback)
        
        # User-1 updates cursor
        rtc.update_cursor(
            user_id="user-1",
            document_id="doc-001",
            position=100,
        )
        
        # User-2 should receive the update
        assert len(received_events) > 0
        assert received_events[0]["event_type"] == "cursor_update"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
