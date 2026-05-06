#!/usr/bin/env python3
"""
Example: Multi-Agent Collaborative Document Editing
=====================================================

Demonstrates real-time collaboration between multiple agents
editing a shared document with conflict resolution.
"""

import asyncio
from agentic_ai.collaboration.workspace import Workspace
from agentic_ai.collaboration.realtime import RealTimeCollaboration, Operation, OperationType
from agentic_ai.collaboration.presence import CollaborationHub


async def agent_editor(agent_id: str, workspace: Workspace, rtc: RealTimeCollaboration,
                       hub: CollaborationHub, doc_id: str, content: str, delay: float = 1.0):
    """Simulate an agent editing a document."""
    print(f"[{agent_id}] Starting to edit document...")
    
    # Connect to real-time system
    rtc.connect_user(agent_id, name=agent_id.title())
    
    # Set presence
    hub.presence.mark_active(agent_id)
    
    # Start typing
    hub.typing.start_typing(agent_id, "document", doc_id)
    print(f"[{agent_id}] Typing...")
    
    await asyncio.sleep(delay)
    
    # Submit edit operation
    op = Operation(
        operation_type=OperationType.INSERT,
        document_id=doc_id,
        user_id=agent_id,
        position=0,
        content=content,
    )
    
    result = rtc.submit_operation(op)
    print(f"[{agent_id}] Submitted operation (version {result.version})")
    
    # Stop typing
    hub.typing.stop_typing(agent_id, "document", doc_id)
    
    return result


async def main():
    """Run the multi-agent collaboration example."""
    print("=" * 60)
    print("Multi-Agent Collaborative Document Editing")
    print("=" * 60)
    print()
    
    # Initialize systems
    workspace = Workspace(name="Collaborative Workspace")
    rtc = RealTimeCollaboration()
    hub = CollaborationHub()
    
    # Add participants
    workspace.add_participant("developer", is_owner=True)
    workspace.add_participant("reviewer")
    workspace.add_participant("tech-writer")
    
    # Create shared document
    doc = workspace.create_resource(
        name="Project README",
        resource_type="document",
        content="# Project\n\n",
        creator_id="developer",
    )
    
    print(f"Created document: {doc.name} (ID: {doc.resource_id})")
    print()
    
    # Run concurrent edits
    tasks = [
        agent_editor("developer", workspace, rtc, doc.resource_id, "## Development Setup\n\n", 0.5),
        agent_editor("reviewer", workspace, rtc, doc.resource_id, "## Review Process\n\n", 0.7),
        agent_editor("tech-writer", workspace, rtc, doc.resource_id, "## Documentation\n\n", 0.6),
    ]
    
    await asyncio.gather(*tasks)
    
    print()
    print("=" * 60)
    print("Results:")
    print("=" * 60)
    
    # Check final document state
    doc_state = rtc.get_document_state(doc.resource_id)
    print(f"Final document version: {doc_state['version']}")
    print(f"Active users: {doc_state['active_users']}")
    print(f"Pending operations: {doc_state['pending_ops']}")
    
    # Check activity feed
    events = hub.activity.get_events(target_type="document", target_id=doc.resource_id)
    print(f"\nActivity events: {len(events)}")
    for event in events[:5]:
        print(f"  - {event.user_name}: {event.event_type.value}")
    
    # Check presence
    online = hub.presence.get_online_users()
    print(f"\nOnline users: {len(online)}")
    for user in online:
        print(f"  - {user.user_id}: {user.status.value}")
    
    print()
    print("Example complete! ✓")


if __name__ == "__main__":
    asyncio.run(main())
