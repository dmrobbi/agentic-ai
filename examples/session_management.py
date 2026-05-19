#!/usr/bin/env python3
"""
Example: Collaboration Session Management
==========================================

Demonstrates creating and managing collaboration sessions
with multiple participants, roles, and real-time features.
"""

from agentic_ai.collaboration.sessions import SessionManager, ParticipantRole
from agentic_ai.collaboration.presence import CollaborationHub
from agentic_ai.collaboration.workspace import Workspace


def main():
    """Run the session management example."""
    print("=" * 60)
    print("Collaboration Session Management")
    print("=" * 60)
    print()
    
    # Initialize managers
    session_mgr = SessionManager()
    hub = CollaborationHub()
    
    # Create a collaboration session
    print("1. Creating collaboration session...")
    session = session_mgr.create_session(
        name="Sprint Planning",
        creator_id="scrum-master",
    )
    session.start()
    print(f"   Session created: {session.session_id}")
    print(f"   Status: {session.status.value}")
    print()
    
    # Participants join
    print("2. Participants joining...")
    participants = []
    for user_id, name in [
        ("scrum-master", "Alice (SM)"),
        ("dev-1", "Bob (Dev)"),
        ("dev-2", "Charlie (Dev)"),
        ("designer", "Diana (Design)"),
    ]:
        p = session.join(user_id=user_id, name=name)
        participants.append(p)
        hub.presence.mark_active(user_id, session_id=session.session_id)
        print(f"   ✓ {name} joined")
    
    print(f"   Active participants: {session.get_active_participant_count()}")
    print()
    
    # Create workspace for session
    print("3. Creating shared workspace...")
    workspace = Workspace(name="Sprint Workspace")
    session.set_metadata("workspace_id", workspace.workspace_id)
    
    for p in participants:
        is_owner = p.user_id == "scrum-master"
        workspace.add_participant(p.user_id, is_owner=is_owner)
    print(f"   Workspace created with {len(participants)} participants")
    print()
    
    # Role changes
    print("4. Changing roles...")
    participants[0]
    dev1 = participants[1]
    
    # Promote dev-1 to cohost
    session.change_role(dev1.participant_id, ParticipantRole.COHOST, changed_by="scrum-master")
    print(f"   ✓ {dev1.name} promoted to Cohost")
    print(f"   Can edit: {dev1.can_edit}, Can invite: {dev1.can_invite}")
    print()
    
    # Create invite
    print("5. Creating session invite...")
    invite_code = session.create_invite(
        created_by="scrum-master",
        expires_minutes=60,
        max_uses=5,
    )
    print(f"   Invite code: {invite_code}")
    print()
    
    # Set session data
    print("6. Setting session data...")
    session.set_data("sprint_number", "24", set_by="scrum-master")
    session.set_data("sprint_goal", "Complete Phase 8 deployment", set_by="scrum-master")
    print(f"   Sprint: {session.get_data('sprint_number')}")
    print(f"   Goal: {session.get_data('sprint_goal')}")
    print()
    
    # Check presence
    print("7. Checking presence...")
    online = hub.presence.get_online_users()
    print(f"   Online users: {len(online)}")
    for user in online:
        print(f"   - {user.user_id}: {user.status.value}")
    print()
    
    # Activity feed
    print("8. Recent activity...")
    events = hub.activity.get_events(limit=5)
    for event in events:
        print(f"   - {event.user_name}: {event.event_type.value}")
    print()
    
    # End session
    print("9. Ending session...")
    session_mgr.end_session(session.session_id, ended_by="scrum-master")
    print(f"   Status: {session.status.value}")
    print()
    
    # Final state
    print("=" * 60)
    print("Session Summary:")
    print("=" * 60)
    state = session.get_state()
    for key, value in state.items():
        print(f"   {key}: {value}")
    
    print()
    print("Example complete! ✓")


if __name__ == "__main__":
    main()
