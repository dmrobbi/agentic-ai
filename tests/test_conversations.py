"""
Tests for Agentic AI Conversations Module
==========================================

Unit tests for multi-agent conversation management.
"""

import pytest
from datetime import datetime
from agentic_ai.conversations.state import ConversationStatus as _ConversationStatus

# Make ConversationStatus available at module level
ConversationStatus = _ConversationStatus


# Import fixtures
@pytest.fixture
def conversation_imports():
    """Import conversation modules."""
    from agentic_ai.conversations.thread import ConversationMessage, MessageThread, MessageType
    from agentic_ai.conversations.state import ConversationState, ConversationStatus
    from agentic_ai.conversations.manager import ConversationManager
    return {
        'ConversationMessage': ConversationMessage,
        'MessageThread': MessageThread,
        'MessageType': MessageType,
        'ConversationState': ConversationState,
        'ConversationStatus': ConversationStatus,
        'ConversationManager': ConversationManager,
    }


class TestConversationMessage:
    """Test ConversationMessage class."""
    
    def test_message_creation(self, conversation_imports):
        """Test creating a conversation message."""
        ConversationMessage = conversation_imports['ConversationMessage']
        MessageType = conversation_imports['MessageType']
        
        msg = ConversationMessage(
            thread_id="thread-001",
            sender="agent-001",
            recipient="agent-002",
            type=MessageType.MESSAGE,
            content="Hello, how are you?",
        )
        
        assert msg.thread_id == "thread-001"
        assert msg.sender == "agent-001"
        assert msg.recipient == "agent-002"
        assert msg.type == MessageType.MESSAGE
        assert msg.content == "Hello, how are you?"
        assert msg.id is not None
        assert msg.created_at is not None
    
    def test_message_to_dict(self, conversation_imports):
        """Test message serialization."""
        ConversationMessage = conversation_imports['ConversationMessage']
        
        msg = ConversationMessage(
            thread_id="thread-001",
            sender="agent-001",
            content="Test message",
        )
        
        data = msg.to_dict()
        
        assert data["thread_id"] == "thread-001"
        assert data["sender"] == "agent-001"
        assert data["content"] == "Test message"
        assert "id" in data
        assert "created_at" in data
    
    def test_message_from_dict(self, conversation_imports):
        """Test message deserialization."""
        ConversationMessage = conversation_imports['ConversationMessage']
        MessageType = conversation_imports['MessageType']
        
        data = {
            "id": "msg-001",
            "thread_id": "thread-001",
            "sender": "agent-001",
            "type": "question",
            "content": "What's the status?",
            "created_at": "2026-04-15T12:00:00",
        }
        
        msg = ConversationMessage.from_dict(data)
        
        assert msg.id == "msg-001"
        assert msg.thread_id == "thread-001"
        assert msg.sender == "agent-001"
        assert msg.type == MessageType.QUESTION
        assert msg.content == "What's the status?"


class TestMessageThread:
    """Test MessageThread class."""
    
    def test_thread_creation(self, conversation_imports):
        """Test creating a message thread."""
        MessageThread = conversation_imports['MessageThread']
        
        thread = MessageThread(
            thread_id="thread-001",
            title="Code Review Discussion",
            creator="dev-001",
        )
        
        assert thread.thread_id == "thread-001"
        assert thread.title == "Code Review Discussion"
        assert thread.creator == "dev-001"
        assert thread.is_active is True
        assert len(thread.messages) == 0
        assert len(thread.participants) == 1
        assert "dev-001" in thread.participants
    
    def test_add_message(self, conversation_imports):
        """Test adding messages to thread."""
        MessageThread = conversation_imports['MessageThread']
        
        thread = MessageThread("thread-001", "Test Thread", "agent-001")
        
        msg = thread.add_message(
            sender="agent-001",
            content="First message",
        )
        
        assert len(thread.messages) == 1
        assert msg.content == "First message"
        assert msg.sender == "agent-001"
        assert msg.thread_id == "thread-001"
    
    def test_add_message_with_reply(self, conversation_imports):
        """Test adding a reply message."""
        MessageThread = conversation_imports['MessageThread']
        
        thread = MessageThread("thread-001", "Test Thread", "agent-001")
        
        msg1 = thread.add_message(
            sender="agent-001",
            content="Original message",
        )
        
        msg2 = thread.add_message(
            sender="agent-002",
            content="Reply to original",
            in_reply_to=msg1.id,
        )
        
        assert len(thread.messages) == 2
        assert msg2.in_reply_to == msg1.id
        
        # Get replies
        replies = thread.get_replies(msg1.id)
        assert len(replies) == 1
        assert replies[0].id == msg2.id
    
    def test_get_messages_with_limit(self, conversation_imports):
        """Test getting limited messages."""
        MessageThread = conversation_imports['MessageThread']
        
        thread = MessageThread("thread-001", "Test Thread", "agent-001")
        
        # Add 10 messages
        for i in range(10):
            thread.add_message("agent-001", f"Message {i}")
        
        # Get last 3
        messages = thread.get_messages(limit=3)
        assert len(messages) == 3
        assert messages[0].content == "Message 7"
        assert messages[2].content == "Message 9"
    
    def test_close_thread(self, conversation_imports):
        """Test closing a thread."""
        MessageThread = conversation_imports['MessageThread']
        
        thread = MessageThread("thread-001", "Test Thread", "agent-001")
        
        assert thread.is_active is True
        
        thread.close()
        
        assert thread.is_active is False
        assert thread.updated_at is not None


class TestConversationState:
    """Test ConversationState class."""
    
    def test_state_creation(self, conversation_imports):
        """Test creating conversation state."""
        ConversationState = conversation_imports['ConversationState']
        ConversationStatus = conversation_imports['ConversationStatus']
        
        state = ConversationState(
            thread_id="thread-001",
            title="Test Conversation",
        )
        
        assert state.thread_id == "thread-001"
        assert state.title == "Test Conversation"
        assert state.status == ConversationStatus.ACTIVE
        assert len(state.messages) == 0
    
    def test_add_message_to_state(self, conversation_imports):
        """Test adding messages to state."""
        ConversationState = conversation_imports['ConversationState']
        
        state = ConversationState("thread-001", "Test")
        
        state.add_message({"id": "msg-001", "content": "Hello"})
        
        assert len(state.messages) == 1
        assert state.messages[0]["content"] == "Hello"
        assert state.updated_at is not None
    
    def test_complete_state(self, conversation_imports):
        """Test completing a conversation."""
        ConversationState = conversation_imports['ConversationState']
        ConversationStatus = conversation_imports['ConversationStatus']
        
        state = ConversationState("thread-001", "Test")
        
        assert state.status == ConversationStatus.ACTIVE
        
        state.complete()
        
        assert state.status == ConversationStatus.COMPLETED
        assert state.completed_at is not None
    
    def test_archive_state(self, conversation_imports):
        """Test archiving a conversation."""
        ConversationState = conversation_imports['ConversationState']
        
        state = ConversationState("thread-001", "Test")
        
        state.archive()
        
        assert state.status == ConversationStatus.ARCHIVED
    
    def test_state_to_dict(self, conversation_imports):
        """Test state serialization."""
        ConversationState = conversation_imports['ConversationState']
        
        state = ConversationState("thread-001", "Test")
        state.add_message({"id": "msg-001", "content": "Hello"})
        
        data = state.to_dict()
        
        assert data["thread_id"] == "thread-001"
        assert data["title"] == "Test"
        assert data["status"] == "active"
        assert data["message_count"] == 1


class TestConversationManager:
    """Test ConversationManager class."""
    
    def test_create_thread(self, conversation_imports):
        """Test creating a thread via manager."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        
        thread = manager.create_thread(
            title="Code Review",
            creator="dev-001",
            participants=["qa-001", "dev-002"],
        )
        
        assert thread.thread_id is not None
        assert thread.title == "Code Review"
        assert thread.creator == "dev-001"
        assert len(thread.participants) == 3
        assert "dev-001" in thread.participants
        assert "qa-001" in thread.participants
    
    def test_send_message(self, conversation_imports):
        """Test sending messages via manager."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        thread = manager.create_thread("Test Thread", "agent-001")
        
        message = manager.send_message(
            thread_id=thread.thread_id,
            sender="agent-001",
            content="Hello everyone!",
        )
        
        assert message is not None
        assert message.content == "Hello everyone!"
        assert len(thread.messages) == 1
    
    def test_get_agent_threads(self, conversation_imports):
        """Test getting threads for an agent."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        
        # Create 2 threads for agent-001
        thread1 = manager.create_thread("Thread 1", "agent-001")
        thread2 = manager.create_thread("Thread 2", "agent-001", ["agent-002"])
        
        # Create 1 thread for agent-002
        thread3 = manager.create_thread("Thread 3", "agent-002")
        
        # Get agent-001's threads
        threads = manager.get_agent_threads("agent-001")
        
        assert len(threads) == 2
        thread_ids = [t.thread_id for t in threads]
        assert thread1.thread_id in thread_ids
        assert thread2.thread_id in thread_ids
    
    def test_get_active_threads(self, conversation_imports):
        """Test getting active threads."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        
        thread1 = manager.create_thread("Thread 1", "agent-001")
        thread2 = manager.create_thread("Thread 2", "agent-001")
        
        # Close one thread
        manager.close_thread(thread1.thread_id)
        
        active = manager.get_active_threads()
        
        assert len(active) == 1
        assert active[0].thread_id == thread2.thread_id
    
    def test_close_thread(self, conversation_imports):
        """Test closing a thread via manager."""
        ConversationManager = conversation_imports['ConversationManager']
        ConversationStatus = conversation_imports['ConversationStatus']
        
        manager = ConversationManager()
        thread = manager.create_thread("Test", "agent-001")
        
        result = manager.close_thread(thread.thread_id)
        
        assert result is True
        assert thread.is_active is False
        
        state = manager.get_state(thread.thread_id)
        assert state.status == ConversationStatus.COMPLETED
    
    def test_search_messages(self, conversation_imports):
        """Test searching messages."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        thread = manager.create_thread("Test Thread", "agent-001")
        
        manager.send_message(thread.thread_id, "agent-001", "Hello world")
        manager.send_message(thread.thread_id, "agent-001", "Python is great")
        manager.send_message(thread.thread_id, "agent-001", "Hello again")
        
        results = manager.search_messages("hello")
        
        assert len(results) == 2
    
    def test_get_stats(self, conversation_imports):
        """Test getting conversation statistics."""
        ConversationManager = conversation_imports['ConversationManager']
        
        manager = ConversationManager()
        
        thread1 = manager.create_thread("Thread 1", "agent-001")
        thread2 = manager.create_thread("Thread 2", "agent-001", ["agent-002"])
        
        manager.send_message(thread1.thread_id, "agent-001", "Message 1")
        manager.send_message(thread1.thread_id, "agent-001", "Message 2")
        manager.send_message(thread2.thread_id, "agent-002", "Message 3")
        
        stats = manager.get_stats()
        
        assert stats["total_threads"] == 2
        assert stats["active_threads"] == 2
        assert stats["total_messages"] == 3
        assert stats["total_participants"] == 2
        assert stats["avg_messages_per_thread"] == 1.5


class TestConversationIntegration:
    """Integration tests for conversations."""
    
    def test_multi_agent_conversation(self, conversation_imports):
        """Test a multi-agent conversation flow."""
        ConversationManager = conversation_imports['ConversationManager']
        MessageType = conversation_imports['MessageType']
        
        manager = ConversationManager()
        
        # Create code review thread
        thread = manager.create_thread(
            title="Code Review: Payment Module",
            creator="dev-001",
            participants=["dev-002", "qa-001"],
        )
        
        # Developer 1 posts code for review
        manager.send_message(
            thread.thread_id,
            "dev-001",
            "Please review the payment module changes in PR #42",
            type=MessageType.PROPOSAL,
        )
        
        # Developer 2 responds
        msg2 = manager.send_message(
            thread.thread_id,
            "dev-002",
            "Looks good overall, but line 45 needs error handling",
            in_reply_to=thread.messages[0].id,
        )
        
        # QA asks question
        manager.send_message(
            thread.thread_id,
            "qa-001",
            "Are there unit tests for the error case?",
            type=MessageType.QUESTION,
        )
        
        # Developer 1 responds
        manager.send_message(
            thread.thread_id,
            "dev-001",
            "Good catch! I'll add error handling and tests",
            in_reply_to=msg2.id,
        )
        
        # Verify conversation
        assert len(thread.messages) == 4
        assert len(thread.participants) == 3
        
        # Get conversation history
        history = manager.get_thread_history(thread.thread_id)
        assert len(history) == 4
        
        # Complete the conversation
        manager.close_thread(thread.thread_id)
        
        assert thread.is_active is False
        
        # Verify stats
        stats = manager.get_stats()
        assert stats["total_threads"] == 1
        assert stats["total_messages"] == 4
        assert stats["total_participants"] == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
