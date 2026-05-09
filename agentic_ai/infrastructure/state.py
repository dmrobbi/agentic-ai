"""State management for infrastructure and agents."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum
import json
import sqlite3
import logging
import os

logger = logging.getLogger(__name__)


class StateStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    ERROR = "error"


class TaskState(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class StateEntry:
    key: str
    value: Any
    status: StateStatus = StateStatus.ACTIVE
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StoredTask:
    task_id: str
    title: str = ""
    description: str = ""
    status: TaskState = TaskState.PENDING
    agent_id: str = ""
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class StateStore:
    """Persistent state storage with SQLite backend and Redis cache."""

    def __init__(self, path: str = "/tmp/agentic_state", db_path: str = ""):
        self.path = db_path or path
        self.db_path = db_path or path
        self._state: Dict[str, StateEntry] = {}
        self._tasks: Dict[str, StoredTask] = {}
        self.redis_client = None
        self._conn = None
        self._init_db()
        # Try to connect to Redis
        try:
            import redis
            self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            self.redis_client.ping()
        except Exception:
            self.redis_client = None

    def _init_db(self):
        """Initialize SQLite database tables."""
        try:
            os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_state (
                    agent_id TEXT PRIMARY KEY,
                    agent_type TEXT,
                    state TEXT,
                    updated_at TEXT
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    task_type TEXT,
                    agent_id TEXT,
                    status TEXT DEFAULT 'pending',
                    priority INTEGER DEFAULT 0,
                    payload TEXT,
                    result TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS project_memory (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)
            self._conn.commit()
        except Exception as e:
            logger.warning(f"SQLite init failed: {e}")
            self._conn = None

    def save(self, key: str, value: Any, metadata: Dict[str, Any] = None) -> StateEntry:
        entry = StateEntry(key=key, value=value, metadata=metadata or {})
        self._state[key] = entry
        if self.redis_client:
            try:
                self.redis_client.hset("agentic_state", key, json.dumps({"value": value, "metadata": metadata or {}}))
            except Exception:
                pass
        return entry

    def load(self, key: str, default: Any = None) -> Any:
        if self.redis_client:
            try:
                data = self.redis_client.hget("agentic_state", key)
                if data:
                    return json.loads(data)["value"]
            except Exception:
                pass
        entry = self._state.get(key)
        if entry is None:
            return default
        return entry.value

    def delete(self, key: str) -> bool:
        if key in self._state:
            del self._state[key]
            return True
        return False

    def list_keys(self, prefix: str = "") -> List[str]:
        if prefix:
            return [k for k in self._state.keys() if k.startswith(prefix)]
        return list(self._state.keys())

    def get_entry(self, key: str) -> Optional[StateEntry]:
        return self._state.get(key)

    def clear(self):
        self._state.clear()

    # Task management
    def create_task(self, task_id: str = "", title: str = "", description: str = "",
                    agent_id: str = "", status: str = "pending",
                    task_type: str = "", priority: int = 0, payload: Dict[str, Any] = None) -> StoredTask:
        tid = task_id or f"TASK-{len(self._tasks)+1:04d}"
        task = StoredTask(
            task_id=tid, title=title or task_type, description=description or "",
            agent_id=agent_id,
            status=TaskState(status) if status in [s.value for s in TaskState] else TaskState.PENDING,
        )
        self._tasks[tid] = task
        # Store in SQLite
        if self._conn:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO tasks (task_id, task_type, agent_id, status, priority, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (tid, task_type or title, agent_id, status, priority,
                     json.dumps(payload) if payload else None,
                     datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
                )
                self._conn.commit()
            except Exception:
                pass
        if payload:
            self.save(f"task:{tid}:payload", payload)
        if task_type:
            self.save(f"task:{tid}:task_type", task_type)
        return task

    def get_task(self, task_id: str) -> Optional[StoredTask]:
        return self._tasks.get(task_id)

    def update_task(self, task_id: str, **updates) -> Optional[StoredTask]:
        task = self._tasks.get(task_id)
        if not task:
            return None
        for k, v in updates.items():
            if hasattr(task, k):
                setattr(task, k, v)
        task.updated_at = datetime.now()
        return task

    def update_task_status(self, task_id: str, status: str, result: Dict[str, Any] = None) -> bool:
        """Update task status and optional result."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskState(status) if status in [s.value for s in TaskState] else TaskState.COMPLETED
        if result:
            task.result = result
        task.updated_at = datetime.now()
        # Update SQLite
        if self._conn:
            try:
                self._conn.execute(
                    "UPDATE tasks SET status=?, result=?, updated_at=? WHERE task_id=?",
                    (status, json.dumps(result) if result else None,
                     datetime.now(timezone.utc).isoformat(), task_id)
                )
                self._conn.commit()
            except Exception:
                pass
        return True

    def list_tasks(self, status: str = "") -> List[StoredTask]:
        if status:
            return [t for t in self._tasks.values() if t.status.value == status]
        return list(self._tasks.values())

    def get_pending_tasks(self, agent_id: str = "") -> List[Dict[str, Any]]:
        """Get pending tasks, optionally filtered by agent."""
        results = []
        for t in self._tasks.values():
            if t.status == TaskState.PENDING:
                if agent_id and t.agent_id != agent_id:
                    continue
                result = {"task_id": t.task_id, "title": t.title, "description": t.description,
                          "agent_id": t.agent_id, "status": t.status.value}
                task_type = self.load(f"task:{t.task_id}:task_type")
                if task_type:
                    result["task_type"] = task_type
                payload = self.load(f"task:{t.task_id}:payload")
                if payload:
                    result["payload"] = payload
                results.append(result)
        # Also check SQLite
        if self._conn and not results:
            try:
                cursor = self._conn.execute(
                    "SELECT task_id, task_type, agent_id, status, priority, payload FROM tasks WHERE status='pending' AND (agent_id=? OR ?='')",
                    (agent_id, agent_id)
                )
                for row in cursor.fetchall():
                    r = {"task_id": row[0], "task_type": row[1], "agent_id": row[2],
                         "status": row[3], "priority": row[4]}
                    if row[5]:
                        r["payload"] = json.loads(row[5])
                    results.append(r)
            except Exception:
                pass
        return results

    # Agent state management
    def save_agent_state(self, agent_id: str, agent_type: str, state: Dict[str, Any]) -> bool:
        """Save agent state."""
        key = f"agent_state:{agent_id}"
        data = {"agent_id": agent_id, "agent_type": agent_type, "state": state}
        self.save(key, data)
        # Also store in SQLite
        if self._conn:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO agent_state (agent_id, agent_type, state, updated_at) VALUES (?, ?, ?, ?)",
                    (agent_id, agent_type, json.dumps(state), datetime.now(timezone.utc).isoformat())
                )
                self._conn.commit()
            except Exception:
                pass
        return True

    def get_agent_state(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent state."""
        # Try in-memory first
        key = f"agent_state:{agent_id}"
        entry = self._state.get(key)
        if entry:
            return entry.value.get("state")
        # Try SQLite
        if self._conn:
            try:
                cursor = self._conn.execute(
                    "SELECT state FROM agent_state WHERE agent_id=?", (agent_id,)
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
            except Exception:
                pass
        return None

    def save_to_file(self, filepath: str = "") -> bool:
        path = filepath or self.path
        try:
            data = {k: {"value": v.value, "status": v.status.value, "metadata": v.metadata}
                    for k, v in self._state.items()}
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def load_from_file(self, filepath: str = "") -> bool:
        path = filepath or self.path
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            for k, v in data.items():
                self._state[k] = StateEntry(
                    key=k, value=v["value"],
                    status=StateStatus(v.get("status", "active")),
                    metadata=v.get("metadata", {}),
                )
            return True
        except Exception:
            return False