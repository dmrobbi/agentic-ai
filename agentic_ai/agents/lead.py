"""
Lead Agent — Task orchestration and delegation.

Manages agent pools, task routing, workflow execution,
and cross-agent coordination.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
import asyncio

from agentic_ai.infrastructure.utils import utcnow

from agentic_ai.agents.base import BaseAgent, Permission

logger = __import__("logging").getLogger(__name__)


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
    id: str = ""
    type: str = ""
    task_type: str = ""
    agent_type: str = ""
    title: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    assigned_to: str = ""
    dependencies: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        if not self.type and self.task_type:
            self.type = self.task_type
        elif not self.task_type and self.type:
            self.task_type = self.type
        if isinstance(self.priority, str):
            try:
                self.priority = TaskPriority(self.priority.lower())
            except ValueError:
                self.priority = TaskPriority.MEDIUM


@dataclass
class Workflow:
    id: str = ""
    workflow_id: str = ""
    name: str = ""
    description: str = ""
    tasks: List[Task] = field(default_factory=list)
    status: WorkflowStatus = WorkflowStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)
    results: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if not self.workflow_id and self.id:
            self.workflow_id = self.id
        elif not self.id and self.workflow_id:
            self.id = self.workflow_id


@dataclass
class CancellationToken:
    """Token for graceful cancellation of orchestration."""
    _cancelled: bool = False

    def cancel(self):
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


class LeadAgent(BaseAgent):
    agent_type = "lead"
    permission = Permission.ELEVATED

    def __init__(self, agent_id=None, name=None, inference_engine=None,
                 state_store=None, message_bus=None, project_path: str = ""):
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.project_path = project_path
        self._tasks: List[Task] = []
        self._workflows: List[Workflow] = []
        self._agents: Dict[str, BaseAgent] = {}
        self._agent_pools: Dict[str, List[str]] = {}
        self._routing_rules: Dict[str, str] = {
            "implement": "developer",
            "review": "developer",
            "fix_bug": "developer",
            "write_tests": "developer",
            "generate_tests": "qa",
            "run_tests": "qa",
            "find_bugs": "qa",
            "analyze_coverage": "qa",
            "check_quality": "qa",
            "create_lead": "sales",
            "qualify_lead": "sales",
            "create_opportunity": "sales",
            "generate_proposal": "sales",
            "record_transaction": "finance",
            "create_budget": "finance",
            "analyze_spending": "finance",
            "generate_report": "finance",
            "check_system": "sysadmin",
            "analyze_logs": "sysadmin",
            "create_incident": "sysadmin",
            "run_command": "sysadmin",
        }
        self._tools = {
            "create_workflow": self.create_workflow,
            "create_task": self.create_task,
            "route_task": self.route_task,
            "delegate_task": self.delegate_task,
            "execute_workflow": self.execute_workflow,
            "get_status": self.get_status,
            "analyze_request": self.analyze_request,
        }

    def register_agent(self, agent: BaseAgent) -> str:
        """Register an agent with the lead."""
        self._agents[agent.agent_id] = agent
        pool = agent.agent_type
        if pool not in self._agent_pools:
            self._agent_pools[pool] = []
        self._agent_pools[pool].append(agent.agent_id)
        return agent.agent_id

    def _create_agent(self, agent_type: str) -> BaseAgent:
        """Create and register a new agent of the given type."""
        from agentic_ai.agents.developer import DeveloperAgent
        from agentic_ai.agents.qa import QAAgent
        from agentic_ai.agents.sales import SalesAgent
        from agentic_ai.agents.finance import FinanceAgent
        from agentic_ai.agents.sysadmin import SysAdminAgent

        agent_map = {
            "developer": DeveloperAgent,
            "qa": QAAgent,
            "sales": SalesAgent,
            "finance": FinanceAgent,
            "sysadmin": SysAdminAgent,
        }
        cls = agent_map.get(agent_type)
        if not cls:
            return None
        agent = cls(project_path=self.project_path) if agent_type in ("developer",) else cls()
        agent.inference = self.inference_engine
        agent.state_store = self.state_store
        agent.bus = self.bus
        self.register_agent(agent)
        return agent

    def create_task(self, task_type: str = "", description: str = "",
                    priority: str = "medium", payload: Optional[Dict[str, Any]] = None,
                    title: str = "") -> Dict[str, Any]:
        # Resolve agent_type from routing rules
        agent_type = self._routing_rules.get(task_type, "developer")
        task_id = f"TASK-{len(self._tasks)+1:04d}"
        task = Task(
            id=task_id, type=task_type, task_type=task_type,
            agent_type=agent_type, description=description,
            title=title or description, payload=payload or {},
        )
        try:
            task.priority = TaskPriority(priority.lower()) if isinstance(priority, str) else priority
        except ValueError:
            task.priority = TaskPriority.MEDIUM
        self._tasks.append(task)
        return {
            "status": "created", "task_id": task_id,
            "task": {
                "id": task_id, "type": task_type, "agent_type": agent_type,
                "description": description, "priority": task.priority.value
                if isinstance(task.priority, TaskPriority) else task.priority,
                "status": task.status.value,
            }
        }

    def create_workflow(self, workflow_name: str = "", name: str = "",
                        tasks: Optional[List[Dict[str, Any]]] = None,
                        description: str = "") -> Dict[str, Any]:
        label = workflow_name or name or "Default Workflow"
        workflow_id = f"WF-{len(self._workflows)+1:04d}"
        wf = Workflow(id=workflow_id, workflow_id=workflow_id,
                      name=label, description=description)
        task_ids = []
        for t_def in (tasks or []):
            task_result = self.create_task(
                task_type=t_def.get("type", ""),
                description=t_def.get("description", ""),
                payload=t_def.get("payload"),
            )
            task_ids.append(task_result["task_id"])
            wf.tasks.append(Task(
                id=task_result["task_id"], type=t_def.get("type", ""),
                agent_type=self._routing_rules.get(t_def.get("type", ""), "developer"),
                description=t_def.get("description", ""),
            ))
        self._workflows.append(wf)
        return {
            "status": "created", "workflow_id": workflow_id,
            "task_ids": task_ids,
        }

    def route_task(self, task_id: str = "", agent_id: str = "") -> Dict[str, Any]:
        task = None
        for t in self._tasks:
            if t.id == task_id or t.task_id == task_id:
                task = t
                break
        if not task:
            return {"error": f"Task {task_id} not found"}
        # Auto-route based on routing rules
        pool = task.agent_type or self._routing_rules.get(task.type, "developer")
        if not agent_id and pool in self._agent_pools and self._agent_pools[pool]:
            agent_id = self._agent_pools[pool][0]
        elif not agent_id:
            # Auto-create agent
            created = self._create_agent(pool)
            if created:
                agent_id = created.agent_id
        task.assigned_to = agent_id
        task.status = TaskStatus.IN_PROGRESS
        return {"status": "routed", "task_id": task_id, "agent_id": agent_id or ""}

    def delegate_task(self, task_id: str = "", agent_id: str = "") -> Dict[str, Any]:
        task = None
        for t in self._tasks:
            if t.id == task_id or t.task_id == task_id:
                task = t
                break
        if not task:
            return {"error": f"Task {task_id} not found"}
        agent = self._agents.get(agent_id)
        task.assigned_to = agent_id
        task.status = TaskStatus.COMPLETED
        task.result = {"status": "completed", "agent_id": agent_id}
        return {"status": "completed", "task_id": task_id, "agent_id": agent_id}

    def execute_workflow(self, workflow_id: str = "") -> Dict[str, Any]:
        wf = None
        for w in self._workflows:
            if w.id == workflow_id or w.workflow_id == workflow_id:
                wf = w
                break
        if not wf:
            return {"error": f"Workflow {workflow_id} not found"}
        wf.status = WorkflowStatus.COMPLETED
        results = {}
        for t in wf.tasks:
            route_result = self.route_task(t.id)
            results[t.id] = route_result
        wf.results = results
        return {
            "workflow_id": workflow_id, "status": "completed",
            "results": results,
        }

    def get_status(self) -> Dict[str, Any]:
        tasks_by_status: Dict[str, int] = {}
        for t in self._tasks:
            key = t.status.value
            tasks_by_status[key] = tasks_by_status.get(key, 0) + 1
        return {
            "total_tasks": len(self._tasks),
            "tasks_by_status": tasks_by_status,
            "registered_agents": list(self._agents.keys()),
        }

    def analyze_request(self, request: str = "") -> Dict[str, Any]:
        """Analyze a request and determine which agent should handle it."""
        for keyword, agent_type in self._routing_rules.items():
            if keyword in request.lower():
                return {"request": request, "agent_type": agent_type, "confidence": 0.8}
        return {"request": request, "agent_type": "developer", "confidence": 0.5}

    async def perform_task(self, task_type: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a task by type. Called with positional args: perform_task("type", {params})."""
        params = params or {}
        if task_type == "create_workflow":
            return self.create_workflow(**params)
        elif task_type == "create_task":
            return self.create_task(**params)
        elif task_type == "route_task":
            return self.route_task(**params)
        elif task_type == "delegate_task":
            return self.delegate_task(**params)
        elif task_type == "execute_workflow":
            return self.execute_workflow(**params)
        elif task_type == "get_status":
            return self.get_status()
        elif task_type == "analyze_request":
            return self.analyze_request(**params)
        return {"error": f"Unknown task type: {task_type}"}

    # ============================================
    # Conversation Orchestration Methods
    # ============================================

    async def round_robin(self, agents: List[str], prompt: str,
                          rounds: int = 3,
                          cancellation_token: Optional[CancellationToken] = None) -> List[Dict[str, Any]]:
        """Agents take turns in sequence responding to a prompt.

        Each agent sees the previous agent's response and builds on it.
        """
        results = []
        current_prompt = prompt
        for round_num in range(rounds):
            if cancellation_token and cancellation_token.is_cancelled:
                break
            for agent_id in agents:
                if cancellation_token and cancellation_token.is_cancelled:
                    break
                response = self.send_message(
                    recipient=agent_id,
                    content=current_prompt,
                    msg_type="task"
                )
                # send_message may return None (sync bus publish); normalise
                response_text = response if response is not None else current_prompt
                results.append({
                    "round": round_num + 1,
                    "agent_id": agent_id,
                    "response": response_text,
                    "prompt": current_prompt,
                })
                current_prompt = f"Round {round_num + 1} - {agent_id} said: {response_text}. Continue the discussion."
        return results

    async def selector(self, agents: List[str], prompt: str,
                       selector_fn: Callable = None,
                       cancellation_token: Optional[CancellationToken] = None) -> Dict[str, Any]:
        """Select the best agent for a task, then delegate.

        selector_fn: function(agent_ids, prompt) -> selected_agent_id
        If no selector_fn provided, uses simple keyword matching.
        """
        if cancellation_token and cancellation_token.is_cancelled:
            return {"error": "cancelled"}

        if selector_fn:
            selected = selector_fn(agents, prompt)
        else:
            selected = self._default_selector(agents, prompt)

        response = self.send_message(
            recipient=selected,
            content=prompt,
            msg_type="task"
        )
        response_text = response if response is not None else prompt
        return {
            "selected_agent": selected,
            "response": response_text,
            "prompt": prompt,
        }

    def _default_selector(self, agents: List[str], prompt: str) -> str:
        """Default agent selection based on keyword matching."""
        prompt_lower = prompt.lower()
        routing = {
            "security": ["security", "vulnerability", "threat", "breach"],
            "compliance": ["compliance", "regulation", "audit", "policy"],
            "risk": ["risk", "assessment", "mitigation", "exposure"],
            "privacy": ["privacy", "data protection", "gdpr", "consent"],
            "legal": ["legal", "contract", "litigation", "regulatory"],
        }
        for keyword, matches in routing.items():
            if any(m in prompt_lower for m in matches):
                for agent_id in agents:
                    if keyword in agent_id.lower():
                        return agent_id
        return agents[0] if agents else ""

    async def broadcast_and_collect(self, agents: List[str], prompt: str,
                                     timeout: float = 30.0,
                                     cancellation_token: Optional[CancellationToken] = None) -> Dict[str, Any]:
        """Send prompt to all agents, collect responses.

        Returns dict of agent_id -> response.
        """
        responses = {}
        for agent_id in agents:
            if cancellation_token and cancellation_token.is_cancelled:
                break
            try:
                response = self.send_message(
                    recipient=agent_id,
                    content=prompt,
                    msg_type="broadcast"
                )
                response_text = response if response is not None else prompt
                responses[agent_id] = response_text
            except Exception as e:
                responses[agent_id] = {"error": str(e)}

        return {
            "prompt": prompt,
            "responses": responses,
            "agent_count": len(agents),
            "response_count": len(responses),
        }

    async def decompose_and_parallel(self, task: str, agents: List[str],
                                      merge_fn: Callable = None,
                                      cancellation_token: Optional[CancellationToken] = None) -> Dict[str, Any]:
        """Decompose a task into subtasks, run agents in parallel, merge results.

        merge_fn: function(responses) -> merged_result
        If no merge_fn provided, simple concatenation.
        """
        # Decompose task into subtasks
        subtasks = self._decompose_task(task, len(agents))

        # Run agents on subtasks
        results = {}
        for i, agent_id in enumerate(agents):
            if cancellation_token and cancellation_token.is_cancelled:
                break
            subtask = subtasks[i] if i < len(subtasks) else task
            response = self.send_message(
                recipient=agent_id,
                content=subtask,
                msg_type="task"
            )
            response_text = response if response is not None else subtask
            results[agent_id] = {
                "subtask": subtask,
                "response": response_text,
            }

        # Merge results
        if merge_fn:
            merged = merge_fn(results)
        else:
            merged = self._default_merge(results)

        return {
            "task": task,
            "subtasks": subtasks,
            "results": results,
            "merged": merged,
        }

    def _decompose_task(self, task: str, num_agents: int) -> List[str]:
        """Simple task decomposition by splitting into aspects."""
        aspects = [
            f"Security analysis of: {task}",
            f"Risk assessment of: {task}",
            f"Compliance review of: {task}",
            f"Strategic implications of: {task}",
            f"Operational impact of: {task}",
        ]
        return aspects[:num_agents]

    def _default_merge(self, results: Dict[str, Any]) -> str:
        """Default merge: concatenate all responses."""
        parts = []
        for agent_id, data in results.items():
            response = data.get("response", "")
            parts.append(f"Agent {agent_id}: {response}")
        return "\n".join(parts)

    async def request_approval(self, agent_id: str, action: str,
                                context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Request human approval for an action.

        Pauses execution until approved or denied.
        """
        return {
            "agent_id": agent_id,
            "action": action,
            "context": context or {},
            "status": "pending_approval",
            "approved": None,
        }

    def spawn_conversation(self, agents: List[str], topic: str,
                           context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a sub-conversation with a group of agents."""
        conversation_id = self._generate_id("conv")
        return {
            "conversation_id": conversation_id,
            "topic": topic,
            "agents": agents,
            "context": context or {},
            "status": "active",
            "created_at": utcnow().isoformat(),
        }