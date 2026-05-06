"""
Tests for Shared Workspaces
============================

Unit tests for workspace collaboration features.
"""

import pytest
from datetime import datetime, timedelta


@pytest.fixture
def collaboration_imports():
    """Import collaboration modules."""
    from agentic_ai.collaboration.workspace import (
        Workspace, WorkspaceResource, ResourceLock, 
        ChangeRecord, LockType
    )
    from agentic_ai.collaboration.permissions import (
        PermissionManager, Permission, Role, AccessGrant
    )
    
    return {
        'Workspace': Workspace,
        'WorkspaceResource': WorkspaceResource,
        'ResourceLock': ResourceLock,
        'ChangeRecord': ChangeRecord,
        'LockType': LockType,
        'PermissionManager': PermissionManager,
        'Permission': Permission,
        'Role': Role,
        'AccessGrant': AccessGrant,
    }


class TestWorkspaceResource:
    """Test WorkspaceResource class."""
    
    def test_resource_creation(self, collaboration_imports):
        """Test creating a workspace resource."""
        WorkspaceResource = collaboration_imports['WorkspaceResource']
        
        resource = WorkspaceResource(
            name="Test Document",
            resource_type="document",
            content="Initial content",
            created_by="agent-1",
        )
        
        assert resource.name == "Test Document"
        assert resource.resource_type == "document"
        assert resource.content == "Initial content"
        assert resource.version == 0
    
    def test_resource_to_dict(self, collaboration_imports):
        """Test resource serialization."""
        WorkspaceResource = collaboration_imports['WorkspaceResource']
        
        resource = WorkspaceResource(
            name="Test",
            resource_type="file",
        )
        
        data = resource.to_dict()
        
        assert data["name"] == "Test"
        assert "resource_id" in data
        assert "created_at" in data


class TestResourceLock:
    """Test ResourceLock class."""
    
    def test_lock_creation(self, collaboration_imports):
        """Test creating a resource lock."""
        ResourceLock = collaboration_imports['ResourceLock']
        LockType = collaboration_imports['LockType']
        
        lock = ResourceLock(
            resource_id="res-001",
            holder_id="agent-1",
            lock_type=LockType.WRITE,
            purpose="Editing document",
        )
        
        assert lock.resource_id == "res-001"
        assert lock.holder_id == "agent-1"
        assert lock.lock_type == LockType.WRITE
    
    def test_lock_expiration(self, collaboration_imports):
        """Test lock expiration."""
        ResourceLock = collaboration_imports['ResourceLock']
        collaboration_imports['LockType']
        
        # Create expired lock
        lock = ResourceLock(
            resource_id="res-001",
            holder_id="agent-1",
            expires_at=(datetime.utcnow() - timedelta(minutes=5)).isoformat(),
        )
        
        assert lock.is_expired() is True
        
        # Create valid lock
        lock2 = ResourceLock(
            resource_id="res-001",
            holder_id="agent-1",
            expires_at=(datetime.utcnow() + timedelta(minutes=30)).isoformat(),
        )
        
        assert lock2.is_expired() is False
    
    def test_lock_no_expiry(self, collaboration_imports):
        """Test lock without expiration."""
        ResourceLock = collaboration_imports['ResourceLock']
        
        lock = ResourceLock(
            resource_id="res-001",
            holder_id="agent-1",
        )
        
        assert lock.is_expired() is False


class TestChangeRecord:
    """Test ChangeRecord class."""
    
    def test_change_record_creation(self, collaboration_imports):
        """Test creating a change record."""
        ChangeRecord = collaboration_imports['ChangeRecord']
        
        record = ChangeRecord(
            workspace_id="ws-001",
            resource_id="res-001",
            changer_id="agent-1",
            change_type="update",
            old_value="old",
            new_value="new",
        )
        
        assert record.workspace_id == "ws-001"
        assert record.change_type == "update"
        assert record.old_value == "old"
        assert record.new_value == "new"
    
    def test_change_record_to_dict(self, collaboration_imports):
        """Test change record serialization."""
        ChangeRecord = collaboration_imports['ChangeRecord']
        
        record = ChangeRecord(
            workspace_id="ws-001",
            resource_id="res-001",
            changer_id="agent-1",
            change_type="create",
        )
        
        data = record.to_dict()
        
        assert data["change_type"] == "create"
        assert "change_id" in data
        assert "timestamp" in data


class TestWorkspace:
    """Test Workspace class."""
    
    def test_workspace_creation(self, collaboration_imports):
        """Test creating a workspace."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(
            workspace_id="ws-001",
            name="Project Alpha",
        )
        
        assert workspace.workspace_id == "ws-001"
        assert workspace.name == "Project Alpha"
        assert len(workspace.get_participants()) == 0
    
    def test_workspace_add_participants(self, collaboration_imports):
        """Test adding participants to workspace."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1")
        workspace.add_participant("agent-2", is_owner=True)
        
        participants = workspace.get_participants()
        owners = workspace.get_owners()
        
        assert len(participants) == 2
        assert "agent-1" in participants
        assert "agent-2" in participants
        assert len(owners) == 1
        assert "agent-2" in owners
    
    def test_workspace_remove_participant(self, collaboration_imports):
        """Test removing a participant."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1")
        workspace.remove_participant("agent-1")
        
        participants = workspace.get_participants()
        assert len(participants) == 0
    
    def test_workspace_create_resource(self, collaboration_imports):
        """Test creating a resource in workspace."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Document 1",
            resource_type="document",
            content="Content",
            creator_id="agent-1",
        )
        
        assert resource.name == "Document 1"
        assert resource.created_by == "agent-1"
        
        # Verify resource is in workspace
        resources = workspace.list_resources()
        assert len(resources) == 1
    
    def test_workspace_get_resource(self, collaboration_imports):
        """Test getting a resource."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        
        retrieved = workspace.get_resource(resource.resource_id)
        assert retrieved is not None
        assert retrieved.name == "Doc"
    
    def test_workspace_update_resource(self, collaboration_imports):
        """Test updating a resource."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1", is_owner=True)
        
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
            content="v1",
            creator_id="agent-1",
        )
        
        success = workspace.update_resource(
            resource.resource_id,
            content="v2",
            updater_id="agent-1",
        )
        
        assert success is True
        
        updated = workspace.get_resource(resource.resource_id)
        assert updated.content == "v2"
        assert updated.version == 1
    
    def test_workspace_delete_resource(self, collaboration_imports):
        """Test deleting a resource."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1", is_owner=True)
        
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        
        success = workspace.delete_resource(
            resource.resource_id,
            deleter_id="agent-1",
        )
        
        assert success is True
        assert workspace.get_resource(resource.resource_id) is None
    
    def test_workspace_acquire_lock(self, collaboration_imports):
        """Test acquiring a lock."""
        Workspace = collaboration_imports['Workspace']
        LockType = collaboration_imports['LockType']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        workspace.add_participant("agent-1")
        
        lock = workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-1",
            lock_type=LockType.WRITE,
        )
        
        assert lock is not None
        assert lock.holder_id == "agent-1"
    
    def test_workspace_lock_conflict(self, collaboration_imports):
        """Test lock conflict detection."""
        Workspace = collaboration_imports['Workspace']
        LockType = collaboration_imports['LockType']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        workspace.add_participant("agent-1")
        workspace.add_participant("agent-2")
        
        # Agent 1 acquires write lock
        lock1 = workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-1",
            lock_type=LockType.WRITE,
        )
        
        # Agent 2 tries to acquire write lock (should fail)
        lock2 = workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-2",
            lock_type=LockType.WRITE,
        )
        
        assert lock1 is not None
        assert lock2 is None
    
    def test_workspace_compatible_locks(self, collaboration_imports):
        """Test compatible read locks."""
        Workspace = collaboration_imports['Workspace']
        LockType = collaboration_imports['LockType']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        workspace.add_participant("agent-1")
        workspace.add_participant("agent-2")
        
        # Both agents acquire read locks (should succeed)
        lock1 = workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-1",
            lock_type=LockType.READ,
        )
        lock2 = workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-2",
            lock_type=LockType.READ,
        )
        
        assert lock1 is not None
        assert lock2 is not None
    
    def test_workspace_release_lock(self, collaboration_imports):
        """Test releasing a lock."""
        Workspace = collaboration_imports['Workspace']
        LockType = collaboration_imports['LockType']
        
        workspace = Workspace(name="Test")
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
        )
        workspace.add_participant("agent-1")
        
        workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-1",
            lock_type=LockType.WRITE,
        )
        
        success = workspace.release_lock(
            resource.resource_id,
            holder_id="agent-1",
        )
        
        assert success is True
        
        # Lock should be released
        current_lock = workspace.get_lock(resource.resource_id)
        assert current_lock is None
    
    def test_workspace_change_log(self, collaboration_imports):
        """Test change log tracking."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1", is_owner=True)
        
        # Create resource
        resource = workspace.create_resource(
            name="Doc",
            resource_type="document",
            content="v1",
            creator_id="agent-1",
        )
        
        # Update resource
        workspace.update_resource(
            resource.resource_id,
            content="v2",
            updater_id="agent-1",
        )
        
        # Get change log
        changes = workspace.get_change_log()
        
        assert len(changes) == 2
        assert changes[0].change_type == "update"
        assert changes[1].change_type == "create"
    
    def test_workspace_state(self, collaboration_imports):
        """Test workspace state summary."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test")
        workspace.add_participant("agent-1")
        workspace.add_participant("agent-2", is_owner=True)
        workspace.create_resource("Doc", "document")
        
        state = workspace.get_state()
        
        assert state["participant_count"] == 2
        assert state["owner_count"] == 1
        assert state["resource_count"] == 1
    
    def test_workspace_to_dict(self, collaboration_imports):
        """Test workspace serialization."""
        Workspace = collaboration_imports['Workspace']
        
        workspace = Workspace(name="Test Workspace")
        
        data = workspace.to_dict()
        
        assert data["name"] == "Test Workspace"
        assert "workspace_id" in data
        assert "resources" in data


class TestPermissionManager:
    """Test PermissionManager class."""
    
    def test_manager_creation(self, collaboration_imports):
        """Test creating permission manager."""
        PermissionManager = collaboration_imports['PermissionManager']
        
        manager = PermissionManager()
        
        assert manager is not None
    
    def test_grant_access(self, collaboration_imports):
        """Test granting access."""
        PermissionManager = collaboration_imports['PermissionManager']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        grant = manager.grant_access(
            participant_id="agent-1",
            role=Role.EDITOR,
            granted_by="admin",
        )
        
        assert grant.participant_id == "agent-1"
        assert grant.role == Role.EDITOR
    
    def test_revoke_access(self, collaboration_imports):
        """Test revoking access."""
        PermissionManager = collaboration_imports['PermissionManager']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        grant = manager.grant_access(
            participant_id="agent-1",
            role=Role.EDITOR,
        )
        
        success = manager.revoke_access(grant.grant_id)
        
        assert success is True
        
        # Grant should be removed
        grants = manager.get_grants(participant_id="agent-1")
        assert len(grants) == 0
    
    def test_has_permission(self, collaboration_imports):
        """Test permission checking."""
        PermissionManager = collaboration_imports['PermissionManager']
        Permission = collaboration_imports['Permission']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        manager.grant_access(
            participant_id="agent-1",
            role=Role.EDITOR,
        )
        
        # Editor has read and write
        assert manager.has_permission("agent-1", Permission.READ) is True
        assert manager.has_permission("agent-1", Permission.WRITE) is True
        assert manager.has_permission("agent-1", Permission.DELETE) is False
        assert manager.has_permission("agent-1", Permission.ADMIN) is False
    
    def test_owner_permissions(self, collaboration_imports):
        """Test owner has all permissions."""
        PermissionManager = collaboration_imports['PermissionManager']
        Permission = collaboration_imports['Permission']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        manager.grant_access(
            participant_id="agent-1",
            role=Role.OWNER,
        )
        
        assert manager.has_permission("agent-1", Permission.READ) is True
        assert manager.has_permission("agent-1", Permission.WRITE) is True
        assert manager.has_permission("agent-1", Permission.DELETE) is True
        assert manager.has_permission("agent-1", Permission.SHARE) is True
        assert manager.has_permission("agent-1", Permission.ADMIN) is True
    
    def test_get_participants(self, collaboration_imports):
        """Test getting participants with roles."""
        PermissionManager = collaboration_imports['PermissionManager']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        manager.grant_access("agent-1", Role.VIEWER)
        manager.grant_access("agent-2", Role.EDITOR)
        manager.grant_access("agent-3", Role.OWNER)
        
        participants = manager.get_participants()
        
        assert len(participants) == 3
        assert participants["agent-1"] == Role.VIEWER
        assert participants["agent-2"] == Role.EDITOR
        assert participants["agent-3"] == Role.OWNER
    
    def test_grant_expiry(self, collaboration_imports):
        """Test grant expiration."""
        PermissionManager = collaboration_imports['PermissionManager']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        
        # Expired grant
        manager.grant_access(
            participant_id="agent-1",
            role=Role.EDITOR,
            duration_minutes=-5,  # Already expired
        )
        
        # Valid grant
        manager.grant_access(
            participant_id="agent-2",
            role=Role.EDITOR,
            duration_minutes=60,
        )
        
        # Cleanup
        removed = manager.cleanup_expired()
        
        assert removed >= 1
        
        grants = manager.get_grants()
        assert len(grants) == 1
        assert grants[0].participant_id == "agent-2"
    
    def test_update_role(self, collaboration_imports):
        """Test updating a participant's role."""
        PermissionManager = collaboration_imports['PermissionManager']
        Role = collaboration_imports['Role']
        
        manager = PermissionManager()
        manager.grant_access(
            participant_id="agent-1",
            role=Role.VIEWER,
        )
        
        success = manager.update_role("agent-1", Role.EDITOR)
        
        assert success is True
        
        role = manager.get_role("agent-1")
        assert role == Role.EDITOR


class TestCollaborationIntegration:
    """Integration tests for collaboration features."""
    
    def test_workspace_with_permissions(self, collaboration_imports):
        """Test workspace with permission management."""
        Workspace = collaboration_imports['Workspace']
        PermissionManager = collaboration_imports['PermissionManager']
        Permission = collaboration_imports['Permission']
        Role = collaboration_imports['Role']
        
        # Create workspace and permission manager
        workspace = Workspace(name="Collaborative Project")
        perm_manager = PermissionManager()
        
        # Add participants with different roles
        workspace.add_participant("agent-1", is_owner=True)
        workspace.add_participant("agent-2")
        
        perm_manager.grant_access("agent-1", Role.OWNER)
        perm_manager.grant_access("agent-2", Role.EDITOR)
        
        # Create resource
        workspace.create_resource(
            name="Shared Doc",
            resource_type="document",
            creator_id="agent-1",
        )
        
        # Owner can do anything
        assert perm_manager.has_permission("agent-1", Permission.ADMIN)
        
        # Editor can write but not delete
        assert perm_manager.has_permission("agent-2", Permission.WRITE)
        assert not perm_manager.has_permission("agent-2", Permission.DELETE)
        
        # Verify workspace state
        state = workspace.get_state()
        assert state["participant_count"] == 2
    
    def test_lock_protects_resource(self, collaboration_imports):
        """Test that locks protect resources from concurrent modification."""
        Workspace = collaboration_imports['Workspace']
        LockType = collaboration_imports['LockType']
        
        workspace = Workspace(name="Protected Workspace")
        workspace.add_participant("agent-1")
        workspace.add_participant("agent-2")
        
        resource = workspace.create_resource(
            name="Critical Doc",
            resource_type="document",
            content="original",
        )
        
        # Agent 1 acquires lock
        workspace.acquire_lock(
            resource.resource_id,
            holder_id="agent-1",
            lock_type=LockType.WRITE,
        )
        
        # Agent 1 can update (has lock)
        success1 = workspace.update_resource(
            resource.resource_id,
            content="modified by agent-1",
            updater_id="agent-1",
        )
        
        # Agent 2 cannot update (no lock)
        success2 = workspace.update_resource(
            resource.resource_id,
            content="modified by agent-2",
            updater_id="agent-2",
        )
        
        assert success1 is True
        assert success2 is False
        
        # Content should be from agent-1
        updated = workspace.get_resource(resource.resource_id)
        assert updated.content == "modified by agent-1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
