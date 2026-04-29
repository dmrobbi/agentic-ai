"""Lead agent for task orchestration and delegation."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum

from agentic_ai.agents.base import BaseAgent, Permission

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class WorkflowStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class Task:
    task_id: str = ""
    id: str = ""  # alias for task_id
    title: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    assigned_to: str = ""
    dependencies: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        if not self.task_id and self.id:
            self.task_id = self.id
        elif not self.id and self.task_id:
            self.id = self.task_id

@dataclass
class Workflow:
    workflow_id: str
    name: str
    tasks: List[Task] = field(default_factory=list)
    status: WorkflowStatus = WorkflowStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)

class LeadAgent(BaseAgent):
    agent_type = "lead"
    permission = Permission.ELEVATED

    def __init__(self, agent_id=None, name=None, inference_engine=None, state_store=None, message_bus=None,
                 project_path: str = ""):
        super().__init__(agent_id=agent_id, name=name, inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.project_path = project_path
        self.tasks: List[Task] = []
        self.workflows: List[Workflow] = []
        self._tools = {
            "route_task": self.route_task,
            "delegate_task": self.delegate_task,
            "execute_workflow": self.execute_workflow,
            "create_workflow": self.create_workflow,
            "create_task": self.create_task,
        }

    def route_task(self, task_id: str = "", agent_type: str = "", priority: str = "medium") -> Dict[str, Any]:
        return {"status": "routed", "task_id": task_id, "agent_type": agent_type, "priority": priority}

    def delegate_task(self, task_id: str = "", agent_id: str = "", instructions: str = "") -> Dict[str, Any]:
        for t in self.tasks:
            if t.task_id == task_id:
                t.assigned_to = agent_id
                t.status = TaskStatus.IN_PROGRESS
                return {"status": "delegated", "task_id": task_id, "agent_id": agent_id}
        return {"status": "delegated", "task_id": task_id, "agent_id": agent_id}

    def execute_workflow(self, workflow_id: str = "", parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        for w in self.workflows:
            if w.workflow_id == workflow_id:
                w.status = "executing"
                return {"status": "executing", "workflow_id": workflow_id, "parameters": parameters or {}}
        return {"status": "executing", "workflow_id": workflow_id, "parameters": parameters or {}}

    def create_workflow(self, name: str = "", tasks: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        workflow_id = f"WF-{len(self.workflows)+1:04d}"
        wf = Workflow(workflow_id=workflow_id, name=name, status="draft")
        self.workflows.append(wf)
        return {"status": "created", "workflow_id": workflow_id, "name": name}

    def create_task(self, title: str = "", description: str = "", priority: str = "medium",
                    dependencies: List[str] = None, id: str = "") -> Dict[str, Any]:
        task_id = id or f"TASK-{len(self.tasks)+1:04d}"
        try:
            prio = TaskPriority(priority.lower()) if isinstance(priority, str) else priority
        except ValueError:
            prio = TaskPriority.MEDIUM
        task = Task(task_id=task_id, id=id or task_id, title=title, description=description,
                    priority=prio, dependencies=dependencies or [])
        self.tasks.append(task)
        return {"status": "created", "task_id": task_id, "title": title, "priority": priority, "dependencies": dependencies or []}

    def perform_task(self, task_type: str = "", **kwargs) -> Dict[str, Any]:
        """Perform a task by type."""
        if task_type == "create_workflow":
            return self.create_workflow(**kwargs)
        elif task_type == "create_task":
            return self.create_task(**kwargs)
        elif task_type == "route_task":
            return self.route_task(**kwargs)
        elif task_type == "delegate_task":
            return self.delegate_task(**kwargs)
        elif task_type == "execute_workflow":
            return self.execute_workflow(**kwargs)
        return {"error": f"Unknown task type: {task_type}"}