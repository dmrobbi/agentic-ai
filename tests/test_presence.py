"""
Tests for Presence & Activity Tracking
=======================================

Unit tests for presence, activity feeds, and typing indicators.
"""

import pytest
from datetime import datetime, timedelta
from agentic_ai.infrastructure.utils import utcnow


@pytest.fixture
def presence_imports():
    """Import presence modules."""
    from agentic_ai.collaboration.presence import (
        PresenceManager, PresenceInfo, PresenceStatus,
        ActivityFeed, ActivityEvent, ActivityType,
        TypingManager, TypingIndicator,
        CollaborationHub
    )
    
    return {
        'PresenceManager': PresenceManager,
        'PresenceInfo': PresenceInfo,
        'PresenceStatus': PresenceStatus,
        'ActivityFeed': ActivityFeed,
        'ActivityEvent': ActivityEvent,
        'ActivityType': ActivityType,
        'TypingManager': TypingManager,
        'TypingIndicator': TypingIndicator,
        'CollaborationHub': CollaborationHub,
    }


class TestPresenceInfo:
    """Test PresenceInfo class."""
    
    def test_presence_creation(self, presence_imports):
        """Test creating presence info."""
        PresenceInfo = presence_imports['PresenceInfo']
        PresenceStatus = presence_imports['PresenceStatus']
        
        presence = PresenceInfo(
            user_id="user-1",
            status=PresenceStatus.ONLINE,
        )
        
        assert presence.user_id == "user-1"
        assert presence.status == PresenceStatus.ONLINE
    
    def test_presence_auto_away(self, presence_imports):
        """Test auto-away detection."""
        PresenceInfo = presence_imports['PresenceInfo']
        
        presence = PresenceInfo(
            user_id="user-1",
            last_seen=(utcnow() - timedelta(minutes=10)).isoformat(),
            auto_away_minutes=5,
        )
        
        assert presence.is_auto_away() is True
    
    def test_presence_auto_offline(self, presence_imports):
        """Test auto-offline detection."""
        PresenceInfo = presence_imports['PresenceInfo']
        
        presence = PresenceInfo(
            user_id="user-1",
            last_seen=(utcnow() - timedelta(minutes=45)).isoformat(),
            auto_offline_minutes=30,
        )
        
        assert presence.is_auto_offline() is True
    
    def test_presence_to_dict(self, presence_imports):
        """Test presence serialization."""
        PresenceInfo = presence_imports['PresenceInfo']
        PresenceStatus = presence_imports['PresenceStatus']
        
        presence = PresenceInfo(
            user_id="user-1",
            status=PresenceStatus.BUSY,
        )
        
        data = presence.to_dict()
        
        assert data["status"] == "busy"
        assert "user_id" in data


class TestPresenceManager:
    """Test PresenceManager class."""
    
    def test_manager_creation(self, presence_imports):
        """Test creating presence manager."""
        PresenceManager = presence_imports['PresenceManager']
        
        manager = PresenceManager()
        assert manager is not None
    
    def test_set_presence(self, presence_imports):
        """Test setting presence status."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager()
        manager.set_presence("user-1", PresenceStatus.ONLINE)
        
        presence = manager.get_presence("user-1")
        assert presence is not None
        assert presence.status == PresenceStatus.ONLINE
    
    def test_mark_active(self, presence_imports):
        """Test marking user as active."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager()
        manager.mark_active("user-1")
        
        presence = manager.get_presence("user-1")
        assert presence.status == PresenceStatus.ONLINE
    
    def test_set_offline(self, presence_imports):
        """Test setting user offline."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager()
        manager.set_presence("user-1", PresenceStatus.ONLINE)
        manager.set_offline("user-1")
        
        presence = manager.get_presence("user-1")
        assert presence.status == PresenceStatus.OFFLINE
    
    def test_get_online_users(self, presence_imports):
        """Test getting online users."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager()
        manager.set_presence("user-1", PresenceStatus.ONLINE)
        manager.set_presence("user-2", PresenceStatus.ONLINE)
        manager.set_presence("user-3", PresenceStatus.OFFLINE)
        
        online = manager.get_online_users()
        
        assert len(online) == 2
    
    def test_cleanup_inactive(self, presence_imports):
        """Test cleaning up inactive users."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager(
            auto_away_minutes=5,
            auto_offline_minutes=30,
        )
        
        # Set user with old last_seen
        manager.set_presence("user-1", PresenceStatus.ONLINE)
        presence = manager.get_presence("user-1")
        presence.last_seen = (utcnow() - timedelta(minutes=60)).isoformat()
        
        updated = manager.cleanup_inactive()
        
        assert updated >= 1
        
        presence = manager.get_presence("user-1")
        assert presence.status == PresenceStatus.OFFLINE
    
    def test_presence_state(self, presence_imports):
        """Test getting presence state."""
        PresenceManager = presence_imports['PresenceManager']
        PresenceStatus = presence_imports['PresenceStatus']
        
        manager = PresenceManager()
        manager.set_presence("user-1", PresenceStatus.ONLINE)
        manager.set_presence("user-2", PresenceStatus.AWAY)
        
        state = manager.get_state()
        
        assert state["total_users"] == 2
        assert state["online"] >= 1


class TestActivityEvent:
    """Test ActivityEvent class."""
    
    def test_event_creation(self, presence_imports):
        """Test creating an activity event."""
        ActivityEvent = presence_imports['ActivityEvent']
        ActivityType = presence_imports['ActivityType']
        
        event = ActivityEvent(
            event_type=ActivityType.EDITED,
            user_id="user-1",
            target_type="document",
            target_id="doc-001",
            user_name="Alice",
        )
        
        assert event.event_type == ActivityType.EDITED
        assert event.user_name == "Alice"
    
    def test_event_to_dict(self, presence_imports):
        """Test event serialization."""
        ActivityEvent = presence_imports['ActivityEvent']
        ActivityType = presence_imports['ActivityType']
        
        event = ActivityEvent(
            event_type=ActivityType.JOINED,
            user_id="user-1",
            target_type="session",
            target_id="session-001",
        )
        
        data = event.to_dict()
        
        assert data["event_type"] == "joined"
        assert "event_id" in data


class TestActivityFeed:
    """Test ActivityFeed class."""
    
    def test_feed_creation(self, presence_imports):
        """Test creating activity feed."""
        ActivityFeed = presence_imports['ActivityFeed']
        
        feed = ActivityFeed()
        assert feed is not None
    
    def test_add_event(self, presence_imports):
        """Test adding events to feed."""
        ActivityFeed = presence_imports['ActivityFeed']
        ActivityType = presence_imports['ActivityType']
        
        feed = ActivityFeed()
        event = feed.add_event(
            event_type=ActivityType.EDITED,
            user_id="user-1",
            target_type="document",
            target_id="doc-001",
            user_name="Alice",
        )
        
        assert event.event_type == ActivityType.EDITED
    
    def test_get_events(self, presence_imports):
        """Test getting events from feed."""
        ActivityFeed = presence_imports['ActivityFeed']
        ActivityType = presence_imports['ActivityType']
        
        feed = ActivityFeed()
        
        feed.add_event(ActivityType.JOINED, "user-1", "session", "s1", "Alice")
        feed.add_event(ActivityType.EDITED, "user-1", "document", "d1", "Alice")
        feed.add_event(ActivityType.JOINED, "user-2", "session", "s1", "Bob")
        
        events = feed.get_events(limit=10)
        
        assert len(events) == 3
    
    def test_get_user_activity(self, presence_imports):
        """Test getting user-specific activity."""
        ActivityFeed = presence_imports['ActivityFeed']
        ActivityType = presence_imports['ActivityType']
        
        feed = ActivityFeed()
        
        feed.add_event(ActivityType.EDITED, "user-1", "document", "d1", "Alice")
        feed.add_event(ActivityType.EDITED, "user-2", "document", "d2", "Bob")
        feed.add_event(ActivityType.VIEWED, "user-1", "document", "d1", "Alice")
        
        user1_events = feed.get_user_activity("user-1")
        
        assert len(user1_events) == 2
    
    def test_get_target_activity(self, presence_imports):
        """Test getting target-specific activity."""
        ActivityFeed = presence_imports['ActivityFeed']
        ActivityType = presence_imports['ActivityType']
        
        feed = ActivityFeed()
        
        feed.add_event(ActivityType.EDITED, "user-1", "document", "d1", "Alice")
        feed.add_event(ActivityType.VIEWED, "user-2", "document", "d1", "Bob")
        feed.add_event(ActivityType.EDITED, "user-1", "document", "d2", "Alice")
        
        doc1_events = feed.get_target_activity("document", "d1")
        
        assert len(doc1_events) == 2
    
    def test_clear_old_events(self, presence_imports):
        """Test clearing old events."""
        ActivityFeed = presence_imports['ActivityFeed']
        ActivityEvent = presence_imports['ActivityEvent']
        ActivityType = presence_imports['ActivityType']
        
        feed = ActivityFeed()
        
        # Add event with old timestamp
        event = ActivityEvent(
            event_type=ActivityType.EDITED,
            user_id="user-1",
            target_type="document",
            target_id="d1",
        )
        event.timestamp = (utcnow() - timedelta(hours=48)).isoformat()
        feed._events.append(event)
        
        # Add recent event
        feed.add_event(ActivityType.VIEWED, "user-1", "document", "d2")
        
        removed = feed.clear_old_events(older_than_hours=24)
        
        assert removed >= 1
    
    def test_feed_state(self, presence_imports):
        """Test getting feed state."""
        ActivityFeed = presence_imports['ActivityFeed']
        
        feed = ActivityFeed(max_events=500)
        feed.add_event("joined", "user-1", "session", "s1")
        
        state = feed.get_state()
        
        assert state["total_events"] == 1
        assert state["max_events"] == 500


class TestTypingIndicator:
    """Test TypingIndicator class."""
    
    def test_indicator_creation(self, presence_imports):
        """Test creating typing indicator."""
        TypingIndicator = presence_imports['TypingIndicator']
        
        indicator = TypingIndicator(
            user_id="user-1",
            target_type="session",
            target_id="session-001",
            is_typing=True,
        )
        
        assert indicator.user_id == "user-1"
        assert indicator.is_typing is True
    
    def test_indicator_to_dict(self, presence_imports):
        """Test indicator serialization."""
        TypingIndicator = presence_imports['TypingIndicator']
        
        indicator = TypingIndicator(
            user_id="user-1",
            target_type="document",
            target_id="doc-001",
        )
        
        data = indicator.to_dict()
        
        assert data["user_id"] == "user-1"
        assert "is_typing" in data


class TestTypingManager:
    """Test TypingManager class."""
    
    def test_manager_creation(self, presence_imports):
        """Test creating typing manager."""
        TypingManager = presence_imports['TypingManager']
        
        manager = TypingManager()
        assert manager is not None
    
    def test_start_typing(self, presence_imports):
        """Test starting typing indicator."""
        TypingManager = presence_imports['TypingManager']
        
        manager = TypingManager()
        manager.start_typing("user-1", "session", "session-001")
        
        typists = manager.get_typing_users("session", "session-001")
        
        assert "user-1" in typists
    
    def test_stop_typing(self, presence_imports):
        """Test stopping typing indicator."""
        TypingManager = presence_imports['TypingManager']
        
        manager = TypingManager()
        manager.start_typing("user-1", "session", "session-001")
        manager.stop_typing("user-1", "session", "session-001")
        
        typists = manager.get_typing_users("session", "session-001")
        
        assert len(typists) == 0
    
    def test_cleanup_stale(self, presence_imports):
        """Test cleaning up stale typing indicators."""
        TypingManager = presence_imports['TypingManager']
        
        manager = TypingManager(timeout_seconds=1)
        manager.start_typing("user-1", "session", "session-001")
        
        # Wait for timeout
        import time
        time.sleep(1.1)
        
        removed = manager.cleanup_stale()
        
        assert removed >= 1


class TestCollaborationHub:
    """Test CollaborationHub class."""
    
    def test_hub_creation(self, presence_imports):
        """Test creating collaboration hub."""
        CollaborationHub = presence_imports['CollaborationHub']
        
        hub = CollaborationHub()
        
        assert hub.presence is not None
        assert hub.activity is not None
        assert hub.typing is not None
    
    def test_hub_state(self, presence_imports):
        """Test getting hub state."""
        CollaborationHub = presence_imports['CollaborationHub']
        PresenceStatus = presence_imports['PresenceStatus']
        
        hub = CollaborationHub()
        hub.presence.set_presence("user-1", PresenceStatus.ONLINE)
        
        state = hub.get_state()
        
        assert "presence" in state
        assert "activity" in state
        assert "typing" in state


class TestPresenceIntegration:
    """Integration tests for presence and activity."""
    
    def test_presence_triggers_activity(self, presence_imports):
        """Test that presence changes create activity events."""
        CollaborationHub = presence_imports['CollaborationHub']
        PresenceStatus = presence_imports['PresenceStatus']
        
        hub = CollaborationHub()
        
        # Set presence
        hub.presence.set_presence(
            "user-1",
            PresenceStatus.ONLINE,
        )
        
        # Check activity feed
        events = hub.activity.get_events(user_id="user-1")
        
        # Should have status change event
        assert len(events) > 0
    
    def test_full_collaboration_flow(self, presence_imports):
        """Test complete collaboration flow with presence and activity."""
        CollaborationHub = presence_imports['CollaborationHub']
        PresenceStatus = presence_imports['PresenceStatus']
        ActivityType = presence_imports['ActivityType']
        
        hub = CollaborationHub()
        
        # User comes online
        hub.presence.mark_active("user-1", session_id="session-001")
        
        # User starts typing
        hub.typing.start_typing("user-1", "session", "session-001")
        
        typists = hub.typing.get_typing_users("session", "session-001")
        assert "user-1" in typists
        
        # User stops typing
        hub.typing.stop_typing("user-1", "session", "session-001")
        
        typists = hub.typing.get_typing_users("session", "session-001")
        assert len(typists) == 0
        
        # User performs action
        hub.activity.add_event(
            event_type=ActivityType.EDITED,
            user_id="user-1",
            target_type="document",
            target_id="doc-001",
            user_name="Alice",
        )
        
        # Get user's activity
        user_events = hub.activity.get_user_activity("user-1")
        
        assert len(user_events) > 0
        
        # User goes away
        hub.presence.set_presence("user-1", PresenceStatus.AWAY)
        
        presence = hub.presence.get_presence("user-1")
        assert presence.status == PresenceStatus.AWAY
        
        # Get hub state
        state = hub.get_state()
        assert state["presence"]["total_users"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
