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