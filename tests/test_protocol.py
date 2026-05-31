"""
Tests for the workflow protocol module.

Covers: safe expression evaluation via simpleeval, malicious expression blocking,
Condition types (expression, status, function), Task lifecycle, RetryConfig delays,
and Workflow operations.
"""

import pytest
from agentic_ai.protocol.workflow import (
    Condition,
    Task,
    TaskStatus,
    Workflow,
    ExecutionMode,
    RetryConfig,
    RetryStrategy,
)


# ---------------------------------------------------------------------------
# Safe expression evaluation
# ---------------------------------------------------------------------------

class TestSafeExpressions:
    """Expressions that should evaluate correctly with simpleeval."""

    def test_equality_string(self):
        c = Condition(expression='status == "completed"')
        assert c.evaluate({"status": "completed"}) is True

    def test_equality_string_false(self):
        c = Condition(expression='status == "completed"')
        assert c.evaluate({"status": "pending"}) is False

    def test_inequality(self):
        c = Condition(expression='status != "failed"')
        assert c.evaluate({"status": "completed"}) is True
        assert c.evaluate({"status": "failed"}) is False

    def test_less_than(self):
        c = Condition(expression='count < 10')
        assert c.evaluate({"count": 5}) is True
        assert c.evaluate({"count": 15}) is False

    def test_greater_than(self):
        c = Condition(expression='priority > 0')
        assert c.evaluate({"priority": 5}) is True
        assert c.evaluate({"priority": 0}) is False

    def test_less_than_or_equal(self):
        c = Condition(expression='value <= 100')
        assert c.evaluate({"value": 100}) is True
        assert c.evaluate({"value": 50}) is True
        assert c.evaluate({"value": 101}) is False

    def test_greater_than_or_equal(self):
        c = Condition(expression='score >= 80')
        assert c.evaluate({"score": 80}) is True
        assert c.evaluate({"score": 90}) is True
        assert c.evaluate({"score": 79}) is False

    def test_boolean_and(self):
        c = Condition(expression='status == "completed" and score > 50')
        assert c.evaluate({"status": "completed", "score": 75}) is True
        assert c.evaluate({"status": "completed", "score": 30}) is False
        assert c.evaluate({"status": "pending", "score": 75}) is False

    def test_boolean_or(self):
        c = Condition(expression='status == "completed" or status == "failed"')
        assert c.evaluate({"status": "completed"}) is True
        assert c.evaluate({"status": "failed"}) is True
        assert c.evaluate({"status": "pending"}) is False

    def test_boolean_not(self):
        c = Condition(expression='not failed')
        assert c.evaluate({"failed": False}) is True
        assert c.evaluate({"failed": True}) is False

    def test_numeric_equality(self):
        c = Condition(expression='retries == 3')
        assert c.evaluate({"retries": 3}) is True
        assert c.evaluate({"retries": 0}) is False


# ---------------------------------------------------------------------------
# Malicious expression blocking
# ---------------------------------------------------------------------------

class TestMaliciousExpressions:
    """Expressions that must never execute — simpleeval blocks them."""

    def test_import_attempt(self):
        c = Condition(expression='__import__("os").system("id")')
        assert c.evaluate({}) is False

    def test_class_traversal(self):
        c = Condition(expression='__class__.__subclasses__()')
        assert c.evaluate({}) is False

    def test_builtins_access(self):
        c = Condition(expression='__builtins__')
        assert c.evaluate({}) is False

    def test_dunder_attrib_access(self):
        c = Condition(expression='x.__class__')
        assert c.evaluate({"x": 42}) is False

    def test_open_file(self):
        c = Condition(expression='open("/etc/passwd")')
        assert c.evaluate({}) is False

    def test_eval_in_expression(self):
        c = Condition(expression='eval("1+1")')
        assert c.evaluate({}) is False

    def test_exec_in_expression(self):
        c = Condition(expression='exec("pass")')
        assert c.evaluate({}) is False

    def test_os_module_via_globals(self):
        c = Condition(expression='os.system("id")')
        assert c.evaluate({"os": __import__("os")}) is False


# ---------------------------------------------------------------------------
# Type errors & missing keys
# ---------------------------------------------------------------------------

class TestExpressionErrors:
    """Expressions referencing missing context keys or having type errors."""

    def test_missing_key_returns_false(self):
        c = Condition(expression='missing_key == 1')
        assert c.evaluate({}) is False

    def test_type_mismatch_returns_false(self):
        c = Condition(expression='name > 10')
        # name is a string, comparison with int may error in simpleeval
        result = c.evaluate({"name": "hello"})
        assert result is False

    def test_invalid_syntax_returns_false(self):
        c = Condition(expression='this is not valid python!!!')
        assert c.evaluate({}) is False

    def test_underscore_keys_filtered(self):
        """Keys starting with _ should not be accessible in expressions."""
        c = Condition(expression='_secret == 1')
        assert c.evaluate({"_secret": 1}) is False

    def test_none_expression(self):
        c = Condition(type="expression", expression=None)
        assert c.evaluate({"x": 1}) is True  # falls through to return True


# ---------------------------------------------------------------------------
# Condition type="status"
# ---------------------------------------------------------------------------

class TestStatusCondition:
    """Status-based condition evaluation."""

    def test_status_match(self):
        c = Condition(type="status", required_status=TaskStatus.COMPLETED)
        assert c.evaluate({"status": "completed"}) is True

    def test_status_no_match(self):
        c = Condition(type="status", required_status=TaskStatus.COMPLETED)
        assert c.evaluate({"status": "pending"}) is False

    def test_status_missing_key(self):
        c = Condition(type="status", required_status=TaskStatus.COMPLETED)
        assert c.evaluate({}) is False


# ---------------------------------------------------------------------------
# Condition type="function"
# ---------------------------------------------------------------------------

class TestFunctionCondition:
    """Function-based condition evaluation."""

    def test_function_returns_true(self):
        c = Condition(type="function", function=lambda ctx: ctx.get("ok", False))
        assert c.evaluate({"ok": True}) is True

    def test_function_returns_false(self):
        c = Condition(type="function", function=lambda ctx: ctx.get("ok", False))
        assert c.evaluate({"ok": False}) is False

    def test_function_exception_returns_false(self):
        def bad_fn(ctx):
            raise RuntimeError("boom")
        c = Condition(type="function", function=bad_fn)
        assert c.evaluate({}) is False


# ---------------------------------------------------------------------------
# Task creation & status transitions
# ---------------------------------------------------------------------------

class TestTaskLifecycle:
    """Task creation, status, and retry checks."""

    def test_task_defaults(self):
        t = Task()
        assert t.status == TaskStatus.PENDING
        assert t.execution_mode == ExecutionMode.SEQUENTIAL
        assert t.retry_config.strategy == RetryStrategy.NONE

    def test_task_status_transition(self):
        t = Task()
        t.status = TaskStatus.RUNNING
        assert t.status == TaskStatus.RUNNING
        t.status = TaskStatus.COMPLETED
        assert t.status == TaskStatus.COMPLETED

    def test_task_to_dict(self):
        t = Task(task_type="scan", description="Run scan")
        d = t.to_dict()
        assert d["task_type"] == "scan"
        assert d["status"] == "pending"

    def test_can_start_no_deps(self):
        t = Task()
        assert t.can_start({}) is True

    def test_can_start_deps_met(self):
        dep = Task(task_id="d1", status=TaskStatus.COMPLETED)
        t = Task(dependencies=["d1"])
        assert t.can_start({"d1": dep}) is True

    def test_can_start_deps_not_met(self):
        dep = Task(task_id="d1", status=TaskStatus.PENDING)
        t = Task(dependencies=["d1"])
        assert t.can_start({"d1": dep}) is False


# ---------------------------------------------------------------------------
# RetryConfig delays
# ---------------------------------------------------------------------------

class TestRetryConfig:
    """RetryConfig delay calculations for each strategy."""

    def test_none_strategy_zero_delay(self):
        rc = RetryConfig(strategy=RetryStrategy.NONE)
        assert rc.get_delay(1) == 0

    def test_fixed_strategy_constant_delay(self):
        rc = RetryConfig(strategy=RetryStrategy.FIXED, initial_delay_ms=2000)
        assert rc.get_delay(1) == 2000
        assert rc.get_delay(3) == 2000

    def test_linear_strategy(self):
        rc = RetryConfig(strategy=RetryStrategy.LINEAR, initial_delay_ms=1000)
        assert rc.get_delay(1) == 1000
        assert rc.get_delay(3) == 3000

    def test_exponential_strategy(self):
        rc = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=2.0,
        )
        assert rc.get_delay(1) == 1000
        assert rc.get_delay(2) == 2000
        assert rc.get_delay(3) == 4000

    def test_exponential_capped_at_max(self):
        rc = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=10.0,
            max_delay_ms=5000,
        )
        assert rc.get_delay(3) == 5000

    def test_should_retry(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=2))
        t.retry_count = 0
        assert t.should_retry() is True
        t.retry_count = 2
        assert t.should_retry() is False

    def test_should_not_retry_none_strategy(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.NONE))
        assert t.should_retry() is False


# ---------------------------------------------------------------------------
# Workflow operations
# ---------------------------------------------------------------------------

class TestWorkflow:
    """Workflow creation, task management, and completion checks."""

    def test_workflow_creation(self):
        w = Workflow(name="Test Workflow")
        assert w.name == "Test Workflow"
        assert w.status == "draft"

    def test_add_task(self):
        w = Workflow()
        t = Task(task_id="t1")
        w.add_task(t)
        assert len(w.tasks) == 1

    def test_get_pending_tasks(self):
        w = Workflow()
        t = Task(task_id="t1")
        w.add_task(t)
        pending = w.get_pending_tasks({})
        assert len(pending) == 1

    def test_is_complete(self):
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.COMPLETED)
        w.add_task(t)
        assert w.is_complete() is True

    def test_is_not_complete(self):
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.PENDING)
        w.add_task(t)
        assert w.is_complete() is False

    def test_has_failed(self):
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.FAILED,
                 retry_config=RetryConfig(strategy=RetryStrategy.NONE))
        w.add_task(t)
        assert w.has_failed() is True

    def test_has_not_failed(self):
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.COMPLETED)
        w.add_task(t)
        assert w.has_failed() is False

    def test_rollback_tasks(self):
        w = Workflow(enable_rollback=True)
        rb = Task(task_id="rb1", task_type="rollback")
        w.rollback_tasks.append(rb)
        failed = Task(task_id="t1", status=TaskStatus.FAILED, rollback_task_id="rb1")
        w.add_task(failed)
        w.add_task(rb)
        result = w.get_rollback_tasks(failed)
        assert len(result) >= 1

    def test_workflow_to_dict(self):
        w = Workflow(name="W1")
        d = w.to_dict()
        assert d["name"] == "W1"
        assert d["task_count"] == 0

    def test_parallel_tasks(self):
        w = Workflow(parallel_limit=2)
        t1 = Task(task_id="t1", execution_mode=ExecutionMode.PARALLEL)
        t2 = Task(task_id="t2", execution_mode=ExecutionMode.PARALLEL)
        t3 = Task(task_id="t3", execution_mode=ExecutionMode.PARALLEL)
        w.add_task(t1)
        w.add_task(t2)
        w.add_task(t3)
        parallel = w.get_parallel_tasks({})
        assert len(parallel) == 2  # capped by parallel_limit


# ---------------------------------------------------------------------------
# Extended workflow tests (P3-02)
# ---------------------------------------------------------------------------

class TestWorkflowExtended:
    """Extended workflow tests: dependency chains, rollback, parallel, serialization."""

    # --- Dependency chains ---

    def test_complex_dependency_chain(self):
        """t1 -> t2 -> t3 chain: only t1 starts initially."""
        w = Workflow()
        t1 = Task(task_id="t1")
        t2 = Task(task_id="t2", dependencies=["t1"])
        t3 = Task(task_id="t3", dependencies=["t2"])
        w.add_task(t1)
        w.add_task(t2)
        w.add_task(t3)
        # Nothing completed yet — only t1 can start
        pending = w.get_pending_tasks({})
        assert len(pending) == 1
        assert pending[0].task_id == "t1"

    def test_dependency_chain_after_first_completes(self):
        """After t1 completes, t2 becomes eligible."""
        w = Workflow()
        t1 = Task(task_id="t1", status=TaskStatus.COMPLETED)
        t2 = Task(task_id="t2", dependencies=["t1"])
        t3 = Task(task_id="t3", dependencies=["t2"])
        w.add_task(t1)
        w.add_task(t2)
        w.add_task(t3)
        completed = {"t1": t1}
        pending = w.get_pending_tasks(completed)
        assert len(pending) == 1
        assert pending[0].task_id == "t2"

    def test_diamond_dependency(self):
        """Diamond: t1 -> t2, t1 -> t3, t2+t3 -> t4."""
        w = Workflow()
        t1 = Task(task_id="t1", status=TaskStatus.COMPLETED)
        t2 = Task(task_id="t2", dependencies=["t1"])
        t3 = Task(task_id="t3", dependencies=["t1"])
        t4 = Task(task_id="t4", dependencies=["t2", "t3"])
        w.add_task(t1)
        w.add_task(t2)
        w.add_task(t3)
        w.add_task(t4)
        completed = {"t1": t1}
        pending = w.get_pending_tasks(completed)
        # t2 and t3 are both eligible; t4 is not
        assert len(pending) == 2
        assert set(t.task_id for t in pending) == {"t2", "t3"}

    def test_get_pending_excludes_non_pending(self):
        """Running/completed tasks should not appear in pending."""
        w = Workflow()
        t1 = Task(task_id="t1", status=TaskStatus.RUNNING)
        w.add_task(t1)
        pending = w.get_pending_tasks({})
        assert len(pending) == 0

    # --- get_parallel_tasks with parallel_limit ---

    def test_parallel_tasks_respects_limit(self):
        w = Workflow(parallel_limit=1)
        t1 = Task(task_id="p1", execution_mode=ExecutionMode.PARALLEL)
        t2 = Task(task_id="p2", execution_mode=ExecutionMode.PARALLEL)
        w.add_task(t1)
        w.add_task(t2)
        parallel = w.get_parallel_tasks({})
        assert len(parallel) == 1

    def test_parallel_tasks_excludes_sequential(self):
        w = Workflow(parallel_limit=10)
        t1 = Task(task_id="p1", execution_mode=ExecutionMode.PARALLEL)
        t2 = Task(task_id="s1", execution_mode=ExecutionMode.SEQUENTIAL)
        w.add_task(t1)
        w.add_task(t2)
        parallel = w.get_parallel_tasks({})
        assert len(parallel) == 1
        assert parallel[0].task_id == "p1"

    def test_parallel_tasks_empty_when_none_parallel(self):
        w = Workflow()
        t1 = Task(task_id="s1", execution_mode=ExecutionMode.SEQUENTIAL)
        w.add_task(t1)
        parallel = w.get_parallel_tasks({})
        assert parallel == []

    # --- Rollback mechanics ---

    def test_rollback_disabled_returns_empty(self):
        w = Workflow(enable_rollback=False)
        failed = Task(task_id="t1", status=TaskStatus.FAILED, rollback_task_id="rb1")
        w.add_task(failed)
        w.add_task(Task(task_id="rb1"))
        assert w.get_rollback_tasks(failed) == []

    def test_rollback_with_specific_task(self):
        w = Workflow(enable_rollback=True)
        rb = Task(task_id="rb1", task_type="rollback")
        failed = Task(task_id="t1", status=TaskStatus.FAILED, rollback_task_id="rb1")
        w.add_task(failed)
        w.add_task(rb)
        result = w.get_rollback_tasks(failed)
        assert any(t.task_id == "rb1" for t in result)

    def test_rollback_includes_global_rollback_tasks(self):
        w = Workflow(enable_rollback=True)
        global_rb = Task(task_id="grb1", task_type="global-rollback")
        w.rollback_tasks.append(global_rb)
        failed = Task(task_id="t1", status=TaskStatus.FAILED)
        w.add_task(failed)
        result = w.get_rollback_tasks(failed)
        assert global_rb in result

    def test_rollback_task_id_not_found(self):
        """If rollback_task_id references a non-existent task, only global rollbacks returned."""
        w = Workflow(enable_rollback=True)
        global_rb = Task(task_id="grb1")
        w.rollback_tasks.append(global_rb)
        failed = Task(task_id="t1", status=TaskStatus.FAILED, rollback_task_id="missing")
        w.add_task(failed)
        result = w.get_rollback_tasks(failed)
        assert global_rb in result
        assert len(result) == 1

    def test_rollback_no_task_id_no_global(self):
        """No rollback_task_id and no global rollback tasks → empty."""
        w = Workflow(enable_rollback=True)
        failed = Task(task_id="t1", status=TaskStatus.FAILED)
        w.add_task(failed)
        assert w.get_rollback_tasks(failed) == []

    # --- has_failed with retries ---

    def test_has_failed_false_when_retries_available(self):
        """has_failed() is False when a failed task still has retries left."""
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.FAILED,
                 retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=2),
                 retry_count=0)
        w.add_task(t)
        assert w.has_failed() is False

    def test_has_failed_true_when_retries_exhausted(self):
        """has_failed() is True when retries are exhausted."""
        w = Workflow()
        t = Task(task_id="t1", status=TaskStatus.FAILED,
                 retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=2),
                 retry_count=2)
        w.add_task(t)
        assert w.has_failed() is True

    # --- to_dict serialization ---

    def test_workflow_to_dict_counts(self):
        w = Workflow(name="wf1")
        w.add_task(Task(task_id="t1", status=TaskStatus.COMPLETED))
        w.add_task(Task(task_id="t2", status=TaskStatus.FAILED,
                        retry_config=RetryConfig(strategy=RetryStrategy.NONE)))
        w.add_task(Task(task_id="t3", status=TaskStatus.PENDING))
        d = w.to_dict()
        assert d["task_count"] == 3
        assert d["completed_tasks"] == 1
        assert d["failed_tasks"] == 1

    def test_workflow_to_dict_all_fields(self):
        w = Workflow(
            name="full-wf",
            description="A test workflow",
            status="running",
            execution_mode=ExecutionMode.PARALLEL,
            enable_rollback=False,
            result={"output": "ok"},
            error=None,
        )
        d = w.to_dict()
        assert d["name"] == "full-wf"
        assert d["description"] == "A test workflow"
        assert d["status"] == "running"
        assert d["execution_mode"] == "parallel"
        assert d["enable_rollback"] is False
        assert d["result"] == {"output": "ok"}
        assert d["error"] is None

    # --- is_complete edge cases ---

    def test_is_complete_empty_workflow(self):
        w = Workflow()
        assert w.is_complete() is True  # 0 completed == 0 tasks

    def test_is_complete_all_must_be_completed(self):
        w = Workflow()
        w.add_task(Task(status=TaskStatus.COMPLETED))
        w.add_task(Task(status=TaskStatus.RUNNING))
        assert w.is_complete() is False

    def test_is_complete_rolled_back_not_complete(self):
        w = Workflow()
        w.add_task(Task(status=TaskStatus.ROLLED_BACK))
        assert w.is_complete() is False

    # --- Workflow timeout ---

    def test_workflow_timeout_field(self):
        w = Workflow(timeout_ms=30000)
        assert w.timeout_ms == 30000

    def test_workflow_started_at_completed_at(self):
        w = Workflow(started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T01:00:00Z")
        d = w.to_dict()
        assert d["started_at"] == "2026-01-01T00:00:00Z"
        assert d["completed_at"] == "2026-01-01T01:00:00Z"


class TestTaskExtended:
    """Extended Task tests: status transitions, retry delay, conditions, to_dict."""

    # --- Status transitions ---

    def test_pending_to_running_to_completed(self):
        t = Task()
        assert t.status == TaskStatus.PENDING
        t.status = TaskStatus.RUNNING
        assert t.status == TaskStatus.RUNNING
        t.status = TaskStatus.COMPLETED
        assert t.status == TaskStatus.COMPLETED

    def test_pending_to_failed(self):
        t = Task()
        t.status = TaskStatus.FAILED
        assert t.status == TaskStatus.FAILED

    def test_pending_to_running_to_retrying_to_completed(self):
        t = Task()
        t.status = TaskStatus.RUNNING
        t.status = TaskStatus.RETRYING
        t.retry_count = 1
        assert t.status == TaskStatus.RETRYING
        t.status = TaskStatus.RUNNING
        t.status = TaskStatus.COMPLETED
        assert t.status == TaskStatus.COMPLETED

    def test_pending_to_cancelled(self):
        t = Task()
        t.status = TaskStatus.CANCELLED
        assert t.status == TaskStatus.CANCELLED

    def test_all_task_status_values(self):
        expected = ["pending", "queued", "running", "paused", "completed",
                    "failed", "retrying", "cancelled", "rolled_back"]
        for val in expected:
            assert TaskStatus(val).value == val

    # --- can_start with conditions ---

    def test_can_start_condition_not_met(self):
        cond = Condition(type="expression", expression='status == "completed"')
        t = Task(conditions=[cond])
        # task's status is PENDING, not completed
        assert t.can_start({}) is False

    def test_can_start_condition_met(self):
        cond = Condition(type="status", required_status=TaskStatus.PENDING)
        t = Task(conditions=[cond])
        # task's status is PENDING, which matches
        assert t.can_start({}) is True

    def test_can_start_dependency_missing_from_completed(self):
        """If a dependency ID is not in completed_tasks dict, can't start."""
        t = Task(dependencies=["missing-dep"])
        assert t.can_start({}) is False

    def test_can_start_dependency_not_completed(self):
        dep = Task(task_id="d1", status=TaskStatus.RUNNING)
        t = Task(dependencies=["d1"])
        assert t.can_start({"d1": dep}) is False

    # --- should_retry edge cases ---

    def test_should_retry_at_max(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=3))
        t.retry_count = 3
        assert t.should_retry() is False

    def test_should_retry_below_max(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.EXPONENTIAL, max_retries=3))
        t.retry_count = 2
        assert t.should_retry() is True

    # --- get_retry_delay ---

    def test_get_retry_delay_fixed(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.FIXED, initial_delay_ms=5000))
        assert t.get_retry_delay() == 5000

    def test_get_retry_delay_exponential(self):
        t = Task(retry_config=RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL, initial_delay_ms=1000, multiplier=2.0))
        t.retry_count = 2  # next attempt is 3
        assert t.get_retry_delay() == 4000  # 1000 * 2^(3-1)

    def test_get_retry_delay_none(self):
        t = Task(retry_config=RetryConfig(strategy=RetryStrategy.NONE))
        assert t.get_retry_delay() == 0

    # --- to_dict fields ---

    def test_task_to_dict_includes_all_fields(self):
        t = Task(
            task_id="tid1",
            task_type="scan",
            description="Run scan",
            agent_type="scanner",
            status=TaskStatus.RUNNING,
            execution_mode=ExecutionMode.PARALLEL,
            priority=5,
            dependencies=["d1"],
            retry_count=1,
            last_error="timeout",
            result={"output": "ok"},
        )
        t.started_at = "2026-01-01T00:00:00Z"
        t.completed_at = None
        d = t.to_dict()
        assert d["task_id"] == "tid1"
        assert d["task_type"] == "scan"
        assert d["description"] == "Run scan"
        assert d["agent_type"] == "scanner"
        assert d["status"] == "running"
        assert d["execution_mode"] == "parallel"
        assert d["priority"] == 5
        assert d["dependencies"] == ["d1"]
        assert d["retry_count"] == 1
        assert d["last_error"] == "timeout"
        assert d["started_at"] == "2026-01-01T00:00:00Z"
        assert d["completed_at"] is None
        assert d["result"] == {"output": "ok"}

    # --- Timeout ---

    def test_task_timeout_field(self):
        t = Task(timeout_ms=10000)
        assert t.timeout_ms == 10000

    def test_task_default_timeout_is_none(self):
        t = Task()
        assert t.timeout_ms is None

    # --- Rollback fields ---

    def test_task_rollback_fields(self):
        t = Task(
            rollback_task_id="rb1",
            compensating_transaction={"action": "undo"},
        )
        assert t.rollback_task_id == "rb1"
        assert t.compensating_transaction == {"action": "undo"}

    def test_task_default_rollback_fields(self):
        t = Task()
        assert t.rollback_task_id is None
        assert t.compensating_transaction is None


class TestRetryConfigExtended:
    """Extended RetryConfig tests: all strategies with edge cases."""

    def test_linear_capped_at_max_delay(self):
        rc = RetryConfig(
            strategy=RetryStrategy.LINEAR,
            initial_delay_ms=20000,
            max_delay_ms=50000,
        )
        # attempt 3: 20000 * 3 = 60000, capped to 50000
        assert rc.get_delay(3) == 50000

    def test_linear_attempt_1(self):
        rc = RetryConfig(strategy=RetryStrategy.LINEAR, initial_delay_ms=5000)
        assert rc.get_delay(1) == 5000

    def test_exponential_attempt_1(self):
        rc = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=2.0,
        )
        assert rc.get_delay(1) == 1000

    def test_exponential_large_attempt_capped(self):
        rc = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=10.0,
            max_delay_ms=30000,
        )
        # attempt 5: 1000 * 10^4 = 10000000, capped to 30000
        assert rc.get_delay(5) == 30000

    def test_fixed_always_same(self):
        rc = RetryConfig(strategy=RetryStrategy.FIXED, initial_delay_ms=3000)
        for attempt in range(1, 10):
            assert rc.get_delay(attempt) == 3000

    def test_none_always_zero(self):
        rc = RetryConfig(strategy=RetryStrategy.NONE)
        for attempt in range(1, 10):
            assert rc.get_delay(attempt) == 0

    def test_default_config(self):
        rc = RetryConfig()
        assert rc.strategy == RetryStrategy.NONE
        assert rc.max_retries == 3
        assert rc.initial_delay_ms == 1000
        assert rc.max_delay_ms == 60000
        assert rc.multiplier == 2.0

    def test_custom_multiplier(self):
        rc = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=500,
            multiplier=3.0,
        )
        # attempt 1: 500 * 3^0 = 500
        assert rc.get_delay(1) == 500
        # attempt 2: 500 * 3^1 = 1500
        assert rc.get_delay(2) == 1500
        # attempt 3: 500 * 3^2 = 4500
        assert rc.get_delay(3) == 4500


class TestConditionExtended:
    """Extended Condition tests: default evaluation, expression with context."""

    def test_default_condition_returns_true(self):
        """Default condition (no type set specifically) returns True."""
        c = Condition()
        assert c.evaluate({}) is True

    def test_expression_with_multiple_vars(self):
        c = Condition(expression='x > 0 and y < 100')
        assert c.evaluate({"x": 50, "y": 75}) is True
        assert c.evaluate({"x": -1, "y": 75}) is False
        assert c.evaluate({"x": 50, "y": 200}) is False

    def test_status_condition_with_enum(self):
        c = Condition(type="status", required_status=TaskStatus.RUNNING)
        assert c.evaluate({"status": "running"}) is True

    def test_function_condition_with_context(self):
        def check_deps(ctx):
            return len(ctx.get("dependencies", {})) > 0
        c = Condition(type="function", function=check_deps)
        assert c.evaluate({"dependencies": {"t1": Task()}}) is True
        assert c.evaluate({"dependencies": {}}) is False

    def test_unknown_condition_type_returns_true(self):
        """Unknown condition type falls through and returns True."""
        c = Condition(type="unknown")
        assert c.evaluate({}) is True

    def test_condition_id_auto_generated(self):
        c = Condition()
        assert c.condition_id  # non-empty


class TestExecutionMode:
    """ExecutionMode enum values."""

    def test_all_execution_modes(self):
        assert ExecutionMode.SEQUENTIAL.value == "sequential"
        assert ExecutionMode.PARALLEL.value == "parallel"
        assert ExecutionMode.BATCH.value == "batch"

    def test_execution_mode_count(self):
        assert len(ExecutionMode) == 3


class TestRetryStrategyEnum:
    """RetryStrategy enum values."""

    def test_all_strategies(self):
        assert RetryStrategy.NONE.value == "none"
        assert RetryStrategy.FIXED.value == "fixed"
        assert RetryStrategy.EXPONENTIAL.value == "exponential"
        assert RetryStrategy.LINEAR.value == "linear"

    def test_strategy_count(self):
        assert len(RetryStrategy) == 4