#!/usr/bin/env python3
"""
Agentic AI - Performance Benchmark Suite
=========================================

Measures performance across key operations:
- Agent creation and task execution
- Real-time operation throughput
- Collaboration session scaling
- Database query performance
"""

import asyncio
from datetime import datetime
from typing import List
from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    """Benchmark result."""
    test_name: str
    operations: int
    duration_seconds: float
    throughput: float  # ops/second
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float


class PerformanceBenchmark:
    """Performance benchmark runner."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    async def benchmark_realtime_operations(self, count: int = 1000) -> BenchmarkResult:
        """Benchmark real-time operation throughput."""
        from agentic_ai.collaboration.realtime import RealTimeCollaboration, Operation, OperationType
        
        print(f"\n📊 Benchmark: Real-time Operations ({count} ops)")
        
        rtc = RealTimeCollaboration()
        rtc.connect_user("benchmark-user")
        
        latencies = []
        start = datetime.utcnow()
        
        for i in range(count):
            op_start = datetime.utcnow()
            
            op = Operation(
                operation_type=OperationType.INSERT,
                document_id="bench-doc",
                user_id="benchmark-user",
                position=i,
                content="x",
            )
            rtc.submit_operation(op)
            
            op_end = datetime.utcnow()
            latencies.append((op_end - op_start).total_seconds() * 1000)
        
        end = datetime.utcnow()
        duration = (end - start).total_seconds()
        
        latencies.sort()
        result = BenchmarkResult(
            test_name="Real-time Operations",
            operations=count,
            duration_seconds=duration,
            throughput=count / duration,
            latency_p50_ms=latencies[int(len(latencies) * 0.50)],
            latency_p95_ms=latencies[int(len(latencies) * 0.95)],
            latency_p99_ms=latencies[int(len(latencies) * 0.99)],
        )
        
        self.results.append(result)
        self._print_result(result)
        return result
    
    async def benchmark_workspace_operations(self, count: int = 100) -> BenchmarkResult:
        """Benchmark workspace CRUD operations."""
        from agentic_ai.collaboration.workspace import Workspace
        
        print(f"\n📊 Benchmark: Workspace Operations ({count} resources)")
        
        workspace = Workspace(name="Benchmark Workspace")
        workspace.add_participant("benchmark-user", is_owner=True)
        
        latencies = []
        start = datetime.utcnow()
        
        # Create resources
        for i in range(count):
            op_start = datetime.utcnow()
            
            workspace.create_resource(
                name=f"Resource-{i}",
                resource_type="document",
                content=f"Content {i}",
                creator_id="benchmark-user",
            )
            
            op_end = datetime.utcnow()
            latencies.append((op_end - op_start).total_seconds() * 1000)
        
        end = datetime.utcnow()
        duration = (end - start).total_seconds()
        
        latencies.sort()
        result = BenchmarkResult(
            test_name="Workspace Operations",
            operations=count,
            duration_seconds=duration,
            throughput=count / duration,
            latency_p50_ms=latencies[int(len(latencies) * 0.50)],
            latency_p95_ms=latencies[int(len(latencies) * 0.95)],
            latency_p99_ms=latencies[int(len(latencies) * 0.99)],
        )
        
        self.results.append(result)
        self._print_result(result)
        return result
    
    async def benchmark_session_scaling(self, max_participants: int = 50) -> BenchmarkResult:
        """Benchmark session scaling with multiple participants."""
        from agentic_ai.collaboration.sessions import CollaborationSession
        
        print(f"\n📊 Benchmark: Session Scaling ({max_participants} participants)")
        
        session = CollaborationSession(name="Benchmark Session", creator_id="host")
        session.start()
        
        latencies = []
        start = datetime.utcnow()
        
        # Add participants
        for i in range(max_participants):
            op_start = datetime.utcnow()
            
            session.join(user_id=f"user-{i}", name=f"User {i}")
            
            op_end = datetime.utcnow()
            latencies.append((op_end - op_start).total_seconds() * 1000)
        
        end = datetime.utcnow()
        duration = (end - start).total_seconds()
        
        latencies.sort()
        result = BenchmarkResult(
            test_name="Session Scaling",
            operations=max_participants,
            duration_seconds=duration,
            throughput=max_participants / duration,
            latency_p50_ms=latencies[int(len(latencies) * 0.50)],
            latency_p95_ms=latencies[int(len(latencies) * 0.95)],
            latency_p99_ms=latencies[int(len(latencies) * 0.99)],
        )
        
        self.results.append(result)
        self._print_result(result)
        return result
    
    async def benchmark_presence_tracking(self, count: int = 100) -> BenchmarkResult:
        """Benchmark presence system performance."""
        from agentic_ai.collaboration.presence import CollaborationHub
        
        print(f"\n📊 Benchmark: Presence Tracking ({count} users)")
        
        hub = CollaborationHub()
        
        latencies = []
        start = datetime.utcnow()
        
        # Mark users active
        for i in range(count):
            op_start = datetime.utcnow()
            
            hub.presence.mark_active(f"user-{i}", session_id="bench-session")
            
            op_end = datetime.utcnow()
            latencies.append((op_end - op_start).total_seconds() * 1000)
        
        end = datetime.utcnow()
        duration = (end - start).total_seconds()
        
        latencies.sort()
        result = BenchmarkResult(
            test_name="Presence Tracking",
            operations=count,
            duration_seconds=duration,
            throughput=count / duration,
            latency_p50_ms=latencies[int(len(latencies) * 0.50)],
            latency_p95_ms=latencies[int(len(latencies) * 0.95)],
            latency_p99_ms=latencies[int(len(latencies) * 0.99)],
        )
        
        self.results.append(result)
        self._print_result(result)
        return result
    
    def _print_result(self, result: BenchmarkResult):
        """Print benchmark result."""
        print(f"   Duration: {result.duration_seconds:.2f}s")
        print(f"   Throughput: {result.throughput:.0f} ops/sec")
        print(f"   Latency P50: {result.latency_p50_ms:.2f}ms")
        print(f"   Latency P95: {result.latency_p95_ms:.2f}ms")
        print(f"   Latency P99: {result.latency_p99_ms:.2f}ms")
    
    def print_summary(self):
        """Print benchmark summary."""
        print("\n" + "=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)
        
        for result in self.results:
            print(f"\n{result.test_name}:")
            print(f"  {result.operations} ops in {result.duration_seconds:.2f}s")
            print(f"  Throughput: {result.throughput:.0f} ops/sec")
            print(f"  Latency (P50/P95/P99): {result.latency_p50_ms:.1f}/{result.latency_p95_ms:.1f}/{result.latency_p99_ms:.1f}ms")
        
        print("\n" + "=" * 70)


async def main():
    """Run all benchmarks."""
    print("=" * 70)
    print("Agentic AI Performance Benchmark Suite")
    print("=" * 70)
    print(f"Started: {datetime.utcnow().isoformat()}")
    
    benchmark = PerformanceBenchmark()
    
    # Run benchmarks
    await benchmark.benchmark_realtime_operations(count=1000)
    await benchmark.benchmark_workspace_operations(count=100)
    await benchmark.benchmark_session_scaling(max_participants=50)
    await benchmark.benchmark_presence_tracking(count=100)
    
    # Print summary
    benchmark.print_summary()
    
    print(f"\nCompleted: {datetime.utcnow().isoformat()}")
    print("\n✓ All benchmarks complete!")


if __name__ == "__main__":
    asyncio.run(main())
