"""
Tests for Advanced Workflow Features
=====================================

Unit tests for parallel execution, conditional branching,
retry logic, and rollback mechanisms.
"""

import pytest
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def workflow_imports():
    """Import workflow modules."""
    from agentic_ai.protocol.workflow import (
        Task, Workflow, TaskStatus, ExecutionMode,
        RetryConfig, RetryStrategy, Condition
    )
    return {
        'Task': Task,
        'Workflow': Workflow,
        'TaskStatus': TaskStatus,
        'ExecutionMode': ExecutionMode,
        'RetryConfig': RetryConfig,
        'RetryStrategy': RetryStrategy,
        'Condition': Condition,
    }


class TestRetryConfig:
    """Test RetryConfig class."""
    
    def test_retry_config_creation(self, workflow_imports):
        """Test creating retry config."""
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            max_retries=5,
            initial_delay_ms=1000,
            max_delay_ms=30000,
        )
        
        assert config.strategy == RetryStrategy.EXPONENTIAL
        assert config.max_retries == 5
        assert config.initial_delay_ms == 1000
    
    def test_fixed_delay(self, workflow_imports):
        """Test fixed delay calculation."""
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        config = RetryConfig(
            strategy=RetryStrategy.FIXED,
            initial_delay_ms=5000,
        )
        
        assert config.get_delay(1) == 5000
        assert config.get_delay(5) == 5000
    
    def test_linear_delay(self, workflow_imports):
        """Test linear delay calculation."""
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        config = RetryConfig(
            strategy=RetryStrategy.LINEAR,
            initial_delay_ms=1000,
            max_delay_ms=10000,
        )
        
        assert config.get_delay(1) == 1000
        assert config.get_delay(5) == 5000
        assert config.get_delay(15) == 10000
    
    def test_exponential_delay(self, workflow_imports):
        """Test exponential backoff."""
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=2.0,
            max_delay_ms=60000,
        )
        
        assert config.get_delay(1) == 1000
        assert config.get_delay(2) == 2000
        assert config.get_delay(3) == 4000
        assert config.get_delay(4) == 8000


class TestCondition:
    """Test Condition class."""
    
    def test_condition_status(self, workflow_imports):
        """Test status-based condition."""
        Condition = workflow_imports['Condition']
        TaskStatus = workflow_imports['TaskStatus']
        
        condition = Condition(
            type="status",
            required_status=TaskStatus.COMPLETED,
        )
        
        context = {"status": "completed"}
        assert condition.evaluate(context) is True
        
        context = {"status": "failed"}
        assert condition.evaluate(context) is False
    
    def test_condition_expression(self, workflow_imports):
        """Test expression-based condition."""
        Condition = workflow_imports['Condition']
        
        condition = Condition(
            type="expression",
            expression="success_count > 5",
        )
        
        context = {"success_count": 10}
        assert condition.evaluate(context) is True
        
        context = {"success_count": 3}
        assert condition.evaluate(context) is False


class TestTask:
    """Test Task class."""
    
    def test_task_creation(self, workflow_imports):
        """Test creating a task."""
        Task = workflow_imports['Task']
        
        task = Task(
            task_type="code_review",
            description="Review PR #42",
            agent_type="developer",
        )
        
        assert task.task_type == "code_review"
        assert task.agent_type == "developer"
        assert task.status.value == "pending"
        assert task.task_id is not None
    
    def test_task_with_dependencies(self, workflow_imports):
        """Test task with dependencies."""
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        
        task = Task(
            task_type="test",
            description="Run tests",
            dependencies=["task-001", "task-002"],
        )
        
        completed_tasks = {}
        assert task.can_start(completed_tasks) is False
        
        completed_tasks["task-001"] = Task(task_id="task-001", status=TaskStatus.COMPLETED)
        completed_tasks["task-002"] = Task(task_id="task-002", status=TaskStatus.COMPLETED)
        
        assert task.can_start(completed_tasks) is True
    
    def test_task_with_condition(self, workflow_imports):
        """Test task with condition."""
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        Condition = workflow_imports['Condition']
        
        task = Task(
            task_type="deploy",
            description="Deploy to production",
            conditions=[
                Condition(type="status", required_status=TaskStatus.COMPLETED),
            ],
        )
        
        completed_tasks = {}
        assert task.can_start(completed_tasks) is False
    
    def test_task_retry_logic(self, workflow_imports):
        """Test task retry logic."""
        Task = workflow_imports['Task']
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        task = Task(
            task_type="flaky_operation",
            retry_config=RetryConfig(
                strategy=RetryStrategy.EXPONENTIAL,
                max_retries=3,
            ),
        )
        
        assert task.should_retry() is True
        assert task.retry_count == 0
        
        task.retry_count = 1
        assert task.should_retry() is True
        
        task.retry_count = 3
        assert task.should_retry() is False
    
    def test_task_to_dict(self, workflow_imports):
        """Test task serialization."""
        Task = workflow_imports['Task']
        
        task = Task(
            task_type="test",
            description="Test task",
            agent_type="qa",
        )
        
        data = task.to_dict()
        
        assert data["task_type"] == "test"
        assert data["agent_type"] == "qa"
        assert "task_id" in data


class TestWorkflow:
    """Test Workflow class."""
    
    def test_workflow_creation(self, workflow_imports):
        """Test creating a workflow."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        
        workflow = Workflow(
            name="Deployment Pipeline",
            description="Deploy to production",
        )
        
        workflow.add_task(Task(task_type="build", description="Build"))
        workflow.add_task(Task(task_type="test", description="Test"))
        workflow.add_task(Task(task_type="deploy", description="Deploy"))
        
        assert workflow.name == "Deployment Pipeline"
        assert len(workflow.tasks) == 3
    
    def test_workflow_parallel_execution(self, workflow_imports):
        """Test workflow with parallel tasks."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        ExecutionMode = workflow_imports['ExecutionMode']
        workflow_imports['TaskStatus']
        
        workflow = Workflow(
            name="Parallel Tests",
            execution_mode=ExecutionMode.PARALLEL,
            parallel_limit=3,
        )
        
        for i in range(5):
            workflow.add_task(Task(
                task_type=f"test_{i}",
                execution_mode=ExecutionMode.PARALLEL,
            ))
        
        parallel = workflow.get_parallel_tasks({})
        
        assert len(parallel) == 3
    
    def test_workflow_sequential_execution(self, workflow_imports):
        """Test sequential workflow."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        
        workflow = Workflow(name="Sequential")
        
        task1 = Task(task_type="step1")
        task2 = Task(task_type="step2", dependencies=[task1.task_id])
        task3 = Task(task_type="step3", dependencies=[task2.task_id])
        
        workflow.add_task(task1)
        workflow.add_task(task2)
        workflow.add_task(task3)
        
        pending = workflow.get_pending_tasks({})
        assert len(pending) == 1
        assert pending[0].task_type == "step1"
        
        task1.status = TaskStatus.COMPLETED
        completed = {task1.task_id: task1}
        
        pending = workflow.get_pending_tasks(completed)
        assert len(pending) == 1
        assert pending[0].task_type == "step2"
    
    def test_workflow_rollback(self, workflow_imports):
        """Test workflow rollback."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        workflow_imports['TaskStatus']
        
        workflow = Workflow(
            name="With Rollback",
            enable_rollback=True,
        )
        
        main_task = Task(task_type="deploy", description="Deploy")
        rollback_task = Task(task_type="rollback", description="Rollback")
        rollback_task.task_id = "rollback-001"
        
        main_task.rollback_task_id = "rollback-001"
        
        workflow.add_task(main_task)
        workflow.add_task(rollback_task)
        
        rollback_tasks = workflow.get_rollback_tasks(main_task)
        
        assert len(rollback_tasks) == 1
        assert rollback_tasks[0].task_type == "rollback"
    
    def test_workflow_completion_check(self, workflow_imports):
        """Test workflow completion check."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        
        workflow = Workflow(name="Test")
        
        task1 = Task(task_type="step1")
        task2 = Task(task_type="step2")
        
        workflow.add_task(task1)
        workflow.add_task(task2)
        
        assert workflow.is_complete() is False
        
        task1.status = TaskStatus.COMPLETED
        task2.status = TaskStatus.COMPLETED
        
        assert workflow.is_complete() is True
    
    def test_workflow_failure_check(self, workflow_imports):
        """Test workflow failure check."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        RetryStrategy = workflow_imports['RetryStrategy']
        RetryConfig = workflow_imports['RetryConfig']
        
        workflow = Workflow(name="Test")
        
        task1 = Task(task_type="step1")
        task2 = Task(
            task_type="step2",
            retry_config=RetryConfig(strategy=RetryStrategy.NONE),
        )
        
        workflow.add_task(task1)
        workflow.add_task(task2)
        
        task1.status = TaskStatus.COMPLETED
        task2.status = TaskStatus.FAILED
        
        assert workflow.has_failed() is True
    
    def test_workflow_to_dict(self, workflow_imports):
        """Test workflow serialization."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        
        workflow = Workflow(name="Test Workflow", description="Test")
        workflow.add_task(Task(task_type="test"))
        
        data = workflow.to_dict()
        
        assert data["name"] == "Test Workflow"
        assert data["task_count"] == 1
        assert "workflow_id" in data


class TestAdvancedWorkflowIntegration:
    """Integration tests for advanced workflows."""
    
    def test_parallel_test_execution(self, workflow_imports):
        """Test parallel test execution workflow."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        ExecutionMode = workflow_imports['ExecutionMode']
        
        workflow = Workflow(
            name="Parallel Test Suite",
            execution_mode=ExecutionMode.PARALLEL,
            parallel_limit=5,
        )
        
        build_task = Task(task_type="build", description="Build application")
        workflow.add_task(build_task)
        
        for i in range(10):
            workflow.add_task(Task(
                task_type=f"test_suite_{i}",
                description=f"Run test suite {i}",
                execution_mode=ExecutionMode.PARALLEL,
                dependencies=[build_task.task_id],
            ))
        
        pending = workflow.get_pending_tasks({})
        assert len(pending) == 1
        assert pending[0].task_type == "build"
        
        build_task.status = TaskStatus.COMPLETED
        completed = {build_task.task_id: build_task}
        
        parallel = workflow.get_parallel_tasks(completed)
        assert len(parallel) == 5
    
    def test_retry_workflow(self, workflow_imports):
        """Test workflow with retry logic."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        workflow_imports['TaskStatus']
        RetryConfig = workflow_imports['RetryConfig']
        RetryStrategy = workflow_imports['RetryStrategy']
        
        workflow = Workflow(name="Flaky Service Call")
        
        flaky_task = Task(
            task_type="api_call",
            description="Call flaky API",
            retry_config=RetryConfig(
                strategy=RetryStrategy.EXPONENTIAL,
                max_retries=3,
                initial_delay_ms=1000,
            ),
        )
        
        workflow.add_task(flaky_task)
        
        for attempt in range(3):
            if flaky_task.should_retry():
                flaky_task.get_retry_delay()
                flaky_task.retry_count += 1
        
        assert flaky_task.should_retry() is False
        assert flaky_task.retry_count == 3
    
    def test_conditional_deployment(self, workflow_imports):
        """Test conditional deployment workflow."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        Condition = workflow_imports['Condition']
        
        workflow = Workflow(name="Conditional Deploy")
        
        build_task = Task(task_type="build", description="Build")
        workflow.add_task(build_task)
        
        test_task = Task(
            task_type="test",
            description="Run tests",
            dependencies=[build_task.task_id],
        )
        workflow.add_task(test_task)
        
        deploy_task = Task(
            task_type="deploy",
            description="Deploy to production",
            dependencies=[test_task.task_id],
            conditions=[
                Condition(
                    type="expression",
                    expression="test_result == 'passed'",
                ),
            ],
        )
        workflow.add_task(deploy_task)
        
        build_task.status = TaskStatus.COMPLETED
        test_task.status = TaskStatus.COMPLETED
        
        completed = {
            build_task.task_id: build_task,
            test_task.task_id: test_task,
        }
        
        pending = workflow.get_pending_tasks(completed)
        assert len(pending) == 0
    
    def test_rollback_on_failure(self, workflow_imports):
        """Test rollback on task failure."""
        Workflow = workflow_imports['Workflow']
        Task = workflow_imports['Task']
        TaskStatus = workflow_imports['TaskStatus']
        
        workflow = Workflow(
            name="Deploy with Rollback",
            enable_rollback=True,
        )
        
        deploy_task = Task(task_type="deploy", description="Deploy")
        deploy_task.task_id = "deploy-001"
        
        verify_task = Task(
            task_type="verify",
            description="Verify deployment",
            dependencies=[deploy_task.task_id],
        )
        verify_task.task_id = "verify-001"
        
        rollback_task = Task(
            task_type="rollback",
            description="Rollback deployment",
        )
        rollback_task.task_id = "rollback-001"
        
        deploy_task.rollback_task_id = "rollback-001"
        workflow.rollback_tasks = [rollback_task]
        
        workflow.add_task(deploy_task)
        workflow.add_task(verify_task)
        workflow.add_task(rollback_task)
        
        deploy_task.status = TaskStatus.COMPLETED
        verify_task.status = TaskStatus.FAILED
        
        rollback_tasks = workflow.get_rollback_tasks(deploy_task)
        
        assert len(rollback_tasks) >= 1
        assert any(t.task_type == "rollback" for t in rollback_tasks)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
