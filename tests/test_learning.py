"""
Tests for Agentic AI Learning Module
=====================================

Unit tests for feedback collection and performance tracking.
"""

import pytest
from datetime import datetime, timedelta


@pytest.fixture
def learning_imports():
    """Import learning modules."""
    from agentic_ai.learning.feedback import FeedbackCollector, Feedback, FeedbackType
    from agentic_ai.learning.performance import PerformanceTracker, AgentMetrics
    return {
        'FeedbackCollector': FeedbackCollector,
        'Feedback': Feedback,
        'FeedbackType': FeedbackType,
        'PerformanceTracker': PerformanceTracker,
        'AgentMetrics': AgentMetrics,
    }


class TestFeedback:
    """Test Feedback class."""
    
    def test_feedback_creation(self, learning_imports):
        """Test creating feedback."""
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        feedback = Feedback(
            agent_id="agent-001",
            task_type="code_review",
            feedback_type=FeedbackType.EXPLICIT_POSITIVE,
            rating=5.0,
            content="Great analysis!",
        )
        
        assert feedback.agent_id == "agent-001"
        assert feedback.task_type == "code_review"
        assert feedback.feedback_type == FeedbackType.EXPLICIT_POSITIVE
        assert feedback.rating == 5.0
        assert feedback.content == "Great analysis!"
    
    def test_feedback_score_positive(self, learning_imports):
        """Test positive feedback score."""
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        feedback = Feedback(
            agent_id="agent-001",
            task_type="test",
            feedback_type=FeedbackType.EXPLICIT_POSITIVE,
            rating=5.0,
        )
        
        assert feedback.get_score() == 1.0
    
    def test_feedback_score_negative(self, learning_imports):
        """Test negative feedback score."""
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        feedback = Feedback(
            agent_id="agent-001",
            task_type="test",
            feedback_type=FeedbackType.EXPLICIT_NEGATIVE,
            rating=1.0,
        )
        
        assert feedback.get_score() == -1.0
    
    def test_feedback_score_implicit_success(self, learning_imports):
        """Test implicit success score."""
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        feedback = Feedback(
            agent_id="agent-001",
            task_type="test",
            feedback_type=FeedbackType.IMPLICIT_SUCCESS,
        )
        
        assert feedback.get_score() == 0.5
    
    def test_feedback_to_dict(self, learning_imports):
        """Test feedback serialization."""
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        feedback = Feedback(
            agent_id="agent-001",
            task_type="test",
            feedback_type=FeedbackType.EXPLICIT_POSITIVE,
            rating=4.0,
        )
        
        data = feedback.to_dict()
        
        assert data["agent_id"] == "agent-001"
        assert data["feedback_type"] == "explicit_positive"
        assert data["rating"] == 4.0


class TestFeedbackCollector:
    """Test FeedbackCollector class."""
    
    def test_add_feedback(self, learning_imports):
        """Test adding feedback."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        Feedback = learning_imports['Feedback']
        FeedbackType = learning_imports['FeedbackType']
        
        collector = FeedbackCollector()
        feedback = Feedback(
            agent_id="agent-001",
            task_type="test",
            feedback_type=FeedbackType.IMPLICIT_SUCCESS,
        )
        
        feedback_id = collector.add_feedback(feedback)
        
        assert feedback_id == feedback.feedback_id
        assert len(collector.feedback) == 1
    
    def test_submit_rating(self, learning_imports):
        """Test submitting rating."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        feedback = collector.submit_rating(
            agent_id="agent-001",
            task_type="code_review",
            rating=5.0,
            content="Excellent!",
        )
        
        assert feedback.rating == 5.0
        assert feedback.feedback_type.value == "explicit_positive"
    
    def test_record_success(self, learning_imports):
        """Test recording success."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        feedback = collector.record_success(
            agent_id="agent-001",
            task_type="implement",
        )
        
        assert feedback.feedback_type.value == "implicit_success"
    
    def test_record_failure(self, learning_imports):
        """Test recording failure."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        feedback = collector.record_failure(
            agent_id="agent-001",
            task_type="implement",
            error="SyntaxError: invalid syntax",
        )
        
        assert feedback.feedback_type.value == "implicit_failure"
        assert feedback.content == "SyntaxError: invalid syntax"
    
    def test_record_correction(self, learning_imports):
        """Test recording correction."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        feedback = collector.record_correction(
            agent_id="agent-001",
            task_type="write_code",
            original="print('hello'",
            corrected="print('hello')",
        )
        
        assert feedback.feedback_type.value == "correction"
        assert feedback.original_output == "print('hello'"
        assert feedback.corrected_output == "print('hello')"
    
    def test_get_average_rating(self, learning_imports):
        """Test getting average rating."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        collector.submit_rating("agent-001", "test", 4.0)
        collector.submit_rating("agent-001", "test", 5.0)
        collector.submit_rating("agent-001", "test", 3.0)
        
        avg = collector.get_average_rating("agent-001")
        
        assert avg == pytest.approx(4.0)
    
    def test_get_success_rate(self, learning_imports):
        """Test getting success rate."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        FeedbackType = learning_imports['FeedbackType']
        Feedback = learning_imports['Feedback']
        
        collector = FeedbackCollector()
        
        # 3 positive, 1 negative
        collector.add_feedback(Feedback(agent_id="agent-001", task_type="test", feedback_type=FeedbackType.IMPLICIT_SUCCESS))
        collector.add_feedback(Feedback(agent_id="agent-001", task_type="test", feedback_type=FeedbackType.EXPLICIT_POSITIVE, rating=5.0))
        collector.add_feedback(Feedback(agent_id="agent-001", task_type="test", feedback_type=FeedbackType.IMPLICIT_SUCCESS))
        collector.add_feedback(Feedback(agent_id="agent-001", task_type="test", feedback_type=FeedbackType.IMPLICIT_FAILURE))
        
        rate = collector.get_success_rate("agent-001")
        
        assert rate == pytest.approx(0.75)
    
    def test_get_learning_score(self, learning_imports):
        """Test getting learning score."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        # Add mostly positive feedback
        collector.submit_rating("agent-001", "test", 5.0)
        collector.submit_rating("agent-001", "test", 4.0)
        collector.record_success("agent-001", "test")
        
        score = collector.get_learning_score("agent-001")
        
        assert score > 0.5
    
    def test_get_stats(self, learning_imports):
        """Test getting statistics."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        
        collector = FeedbackCollector()
        
        collector.submit_rating("agent-001", "test", 5.0)
        collector.record_success("agent-002", "test")
        collector.record_failure("agent-003", "test")
        
        stats = collector.get_stats()
        
        assert stats["total_feedback"] == 3
        assert stats["agents_tracked"] == 3


class TestAgentMetrics:
    """Test AgentMetrics class."""
    
    def test_metrics_creation(self, learning_imports):
        """Test creating metrics."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(
            agent_id="agent-001",
            task_type="code_review",
        )
        
        assert metrics.agent_id == "agent-001"
        assert metrics.task_type == "code_review"
        assert metrics.total_tasks == 0
    
    def test_record_task_success(self, learning_imports):
        """Test recording successful task."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        metrics.record_task(success=True, duration_ms=1000.0)
        
        assert metrics.total_tasks == 1
        assert metrics.successful_tasks == 1
        assert metrics.failed_tasks == 0
        assert metrics.avg_time_ms == 1000.0
    
    def test_record_task_failure(self, learning_imports):
        """Test recording failed task."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        metrics.record_task(
            success=False,
            duration_ms=500.0,
            error="TimeoutError",
        )
        
        assert metrics.total_tasks == 1
        assert metrics.failed_tasks == 1
        assert metrics.error_counts["TimeoutError"] == 1
    
    def test_record_feedback(self, learning_imports):
        """Test recording feedback."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        metrics.record_feedback(rating=5.0, is_positive=True)
        metrics.record_feedback(rating=4.0, is_positive=True)
        
        assert metrics.total_feedback_count == 2
        assert metrics.avg_rating == pytest.approx(4.5)
        assert metrics.positive_feedback == 2
    
    def test_get_success_rate(self, learning_imports):
        """Test success rate calculation."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        metrics.record_task(success=True, duration_ms=100)
        metrics.record_task(success=True, duration_ms=100)
        metrics.record_task(success=False, duration_ms=100)
        metrics.record_task(success=True, duration_ms=100)
        
        assert metrics.get_success_rate() == pytest.approx(0.75)
    
    def test_get_performance_score(self, learning_imports):
        """Test performance score calculation."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        # Perfect performance
        for _ in range(10):
            metrics.record_task(success=True, duration_ms=1000.0)
            metrics.record_feedback(rating=5.0, is_positive=True)
        
        score = metrics.get_performance_score()
        
        assert score > 0.8
    
    def test_get_performance_score_poor(self, learning_imports):
        """Test poor performance score."""
        AgentMetrics = learning_imports['AgentMetrics']
        
        metrics = AgentMetrics(agent_id="agent-001", task_type="test")
        
        # Poor performance
        for _ in range(10):
            metrics.record_task(success=False, duration_ms=30000.0, error="Error")
            metrics.record_feedback(rating=1.0, is_positive=False)
            metrics.record_correction()
        
        score = metrics.get_performance_score()
        
        assert score < 0.3


class TestPerformanceTracker:
    """Test PerformanceTracker class."""
    
    def test_record_task(self, learning_imports):
        """Test recording task."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        metrics = tracker.record_task(
            agent_id="agent-001",
            task_type="code_review",
            success=True,
            duration_ms=1500.0,
        )
        
        assert metrics.total_tasks == 1
        assert metrics.successful_tasks == 1
    
    def test_get_agent_metrics(self, learning_imports):
        """Test getting agent metrics."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        tracker.record_task("agent-001", "task1", True, 100)
        tracker.record_task("agent-001", "task2", True, 100)
        tracker.record_task("agent-002", "task1", True, 100)
        
        agent_metrics = tracker.get_agent_metrics("agent-001")
        
        assert len(agent_metrics) == 2
    
    def test_get_top_performers(self, learning_imports):
        """Test getting top performers."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        # Agent 1: perfect
        for _ in range(10):
            tracker.record_task("agent-001", "test", True, 100)
        
        # Agent 2: mixed
        for i in range(10):
            tracker.record_task("agent-002", "test", i % 2 == 0, 100)
        
        top = tracker.get_top_performers(limit=1)
        
        assert len(top) == 1
        assert top[0].agent_id == "agent-001"
    
    def test_get_stats(self, learning_imports):
        """Test getting statistics."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        tracker.record_task("agent-001", "task1", True, 100)
        tracker.record_task("agent-002", "task2", False, 200)
        
        stats = tracker.get_stats()
        
        assert stats["total_metrics"] == 2
        assert stats["total_agents"] == 2
        assert stats["total_task_types"] == 2
    
    def test_export_metrics(self, learning_imports):
        """Test exporting metrics."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        tracker.record_task("agent-001", "test", True, 100)
        
        export = tracker.export_metrics()
        
        assert "agent-001:test" in export
        assert "total_tasks" in export


class TestLearningIntegration:
    """Integration tests for learning module."""
    
    def test_full_learning_cycle(self, learning_imports):
        """Test complete learning cycle."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        collector = FeedbackCollector()
        tracker = PerformanceTracker()
        
        # Simulate agent working and receiving feedback
        for i in range(20):
            success = i % 4 != 0  # 75% success rate (5 failures in 20)
            duration = 1000 + (i * 10)  # Getting slower
            
            # Record task
            tracker.record_task(
                agent_id="agent-001",
                task_type="code_review",
                success=success,
                duration_ms=duration,
                error=None if success else "Timeout",
            )
            
            # Record feedback
            if success:
                collector.record_success("agent-001", "code_review")
                if i % 5 == 0:
                    collector.submit_rating("agent-001", "code_review", 5.0)
            else:
                collector.record_failure("agent-001", "code_review", "Timeout")
                if i % 3 == 0:
                    collector.submit_rating("agent-001", "code_review", 2.0)
        
        # Get metrics
        metrics = tracker.get_or_create_metrics("agent-001", "code_review")
        avg_rating = collector.get_average_rating("agent-001")
        learning_score = collector.get_learning_score("agent-001")
        
        assert metrics.total_tasks == 20
        assert metrics.successful_tasks == 15
        assert metrics.get_success_rate() == pytest.approx(0.75)
        assert avg_rating is not None
        assert learning_score > 0
    
    def test_improvement_tracking(self, learning_imports):
        """Test improvement rate calculation."""
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        tracker = PerformanceTracker()
        
        # First 10 tasks: 50% success
        for i in range(10):
            tracker.record_task("agent-001", "test", i % 2 == 0, 1000)
        
        # Next 10 tasks: 90% success (improved)
        for i in range(10):
            tracker.record_task("agent-001", "test", i != 0, 1000)
        
        rate = tracker.get_improvement_rate("agent-001", "test")
        
        assert rate > 0.0  # Positive improvement
    
    def test_correction_tracking(self, learning_imports):
        """Test correction tracking."""
        FeedbackCollector = learning_imports['FeedbackCollector']
        PerformanceTracker = learning_imports['PerformanceTracker']
        
        collector = FeedbackCollector()
        tracker = PerformanceTracker()
        
        # Agent makes mistakes and gets corrected
        for i in range(5):
            tracker.record_task("agent-001", "write_code", True, 500)
            collector.record_correction(
                agent_id="agent-001",
                task_type="write_code",
                original=f"bad_code_{i}",
                corrected=f"good_code_{i}",
            )
        
        metrics = tracker.get_or_create_metrics("agent-001", "write_code")
        
        assert metrics.corrections_count == 5
        # Performance score should be penalized
        assert metrics.get_performance_score() < 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
