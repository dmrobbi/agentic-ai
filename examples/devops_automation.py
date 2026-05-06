#!/usr/bin/env python3
"""
DevOpsAgent Examples
====================

Demonstrates infrastructure automation, CI/CD pipeline management,
deployment orchestration, and monitoring.
"""

from agentic_ai.agents.devops import (
    DevOpsAgent,
    DeploymentStatus,
    InfrastructureType,
    InfrastructureResource,
)


def example_deployment_workflow():
    """Example: Complete deployment workflow."""
    print("=" * 70)
    print("Example 1: Deployment Workflow")
    print("=" * 70)
    print()
    
    agent = DevOpsAgent()
    
    # Create deployment
    print("Creating deployment...")
    deployment = agent.create_deployment(
        application="my-app",
        version="2.0.0",
        environment="production",
        deployed_by="ci-bot",
        health_check_url="https://my-app.com/health",
    )
    
    print(f"  Deployment ID: {deployment.deployment_id}")
    print(f"  Application: {deployment.application}:{deployment.version}")
    print(f"  Environment: {deployment.environment}")
    print(f"  Status: {deployment.status.value}")
    print()
    
    # Simulate deployment progress
    print("Starting deployment...")
    agent.update_deployment_status(
        deployment.deployment_id,
        DeploymentStatus.BUILDING,
        logs=["Building Docker image...", "Pushing to registry..."],
    )
    
    print("Running tests...")
    agent.update_deployment_status(
        deployment.deployment_id,
        DeploymentStatus.TESTING,
        logs=["Running integration tests...", "All tests passed!"],
    )
    
    print("Deploying to production...")
    agent.update_deployment_status(
        deployment.deployment_id,
        DeploymentStatus.DEPLOYING,
        logs=["Pulling image...", "Updating containers...", "Running health checks..."],
    )
    
    # Complete deployment
    agent.update_deployment_status(
        deployment.deployment_id,
        DeploymentStatus.DEPLOYED,
    )
    
    print("Deployment complete!")
    print()
    
    # Show deployment history
    deployments = agent.get_deployments(environment="production", limit=5)
    print(f"Recent production deployments: {len(deployments)}")
    for dep in deployments:
        print(f"  - {dep.application}:{dep.version} ({dep.status.value})")


def example_pipeline_orchestration():
    """Example: CI/CD pipeline orchestration."""
    print("\n" + "=" * 70)
    print("Example 2: CI/CD Pipeline")
    print("=" * 70)
    print()
    
    agent = DevOpsAgent()
    
    # Create pipeline
    print("Creating CI/CD pipeline...")
    pipeline = agent.create_pipeline(
        name="Main CI/CD",
        repository="my-app",
        branch="main",
        stages=["build", "test", "lint", "security-scan", "deploy"],
    )
    
    print(f"  Pipeline: {pipeline.name}")
    print(f"  Repository: {pipeline.repository}@{pipeline.branch}")
    print(f"  Stages: {' → '.join(pipeline.stages)}")
    print()
    
    # Start pipeline
    print("Starting pipeline...")
    agent.start_pipeline(pipeline.pipeline_id)
    
    # Simulate stage progression
    stages_status = [
        ("build", "passed"),
        ("test", "passed"),
        ("lint", "passed"),
        ("security-scan", "passed"),
        ("deploy", "passed"),
    ]
    
    for stage, status in stages_status:
        print(f"  Stage '{stage}': {status}")
        agent.update_pipeline_stage(pipeline.pipeline_id, stage, status)
    
    # Show result
    print()
    print(f"Pipeline completed: {pipeline.status.value}")
    
    # Get pipeline history
    pipelines = agent.get_pipelines(limit=5)
    print(f"\nRecent pipelines: {len(pipelines)}")
    for p in pipelines:
        print(f"  - {p.name} ({p.status.value})")


def example_infrastructure_management():
    """Example: Infrastructure resource management."""
    print("\n" + "=" * 70)
    print("Example 3: Infrastructure Management")
    print("=" * 70)
    print()
    
    agent = DevOpsAgent()
    
    # Register new resources
    print("Registering infrastructure resources...")
    
    resources = [
        InfrastructureResource(
            resource_id="web-server-2",
            resource_type=InfrastructureType.VM,
            name="Web Server 2",
            region="us-west-2",
            status="running",
            cost_per_hour=0.15,
            tags={"env": "prod", "team": "platform"},
        ),
        InfrastructureResource(
            resource_id="cache-redis",
            resource_type=InfrastructureType.DATABASE,
            name="Redis Cache",
            region="us-east-1",
            status="running",
            cost_per_hour=0.25,
            tags={"env": "prod", "team": "platform"},
        ),
    ]
    
    for resource in resources:
        agent.register_resource(resource)
        print(f"  ✓ {resource.name} ({resource.region})")
    
    print()
    
    # Get infrastructure summary
    summary = agent.get_infrastructure_summary()
    print("Infrastructure Summary:")
    print(f"  Total Resources: {summary['total_resources']}")
    print(f"  By Type: {summary['by_type']}")
    print(f"  By Status: {summary['by_status']}")
    print(f"  Hourly Cost: ${summary['hourly_cost']:.2f}")
    print(f"  Daily Cost: ${summary['daily_cost']:.2f}")
    print(f"  Monthly Cost: ${summary['monthly_cost']:.2f}")
    print()
    
    # Get cost breakdown
    costs = agent.get_resource_costs(hours=24)
    print("24-Hour Cost Breakdown:")
    for resource_id, cost in costs.items():
        if resource_id != 'total':
            print(f"  {resource_id}: ${cost:.2f}")
    print(f"  Total: ${costs['total']:.2f}")


def example_monitoring_alerting():
    """Example: Monitoring and alerting."""
    print("\n" + "=" * 70)
    print("Example 4: Monitoring & Alerting")
    print("=" * 70)
    print()
    
    agent = DevOpsAgent()
    
    # Record metrics
    print("Recording metrics...")
    metrics_data = [
        ("cpu_usage", 45.5),
        ("cpu_usage", 62.3),
        ("cpu_usage", 78.9),
        ("cpu_usage", 92.5),  # Critical!
        ("memory_usage", 65.0),
        ("memory_usage", 72.5),
        ("memory_usage", 88.0),  # Warning!
        ("error_rate", 0.5),
        ("latency_p99", 250.0),
    ]
    
    for metric, value in metrics_data:
        agent.record_metric(metric, value, {"host": "web-1"})
        print(f"  {metric}: {value}")
    
    print()
    
    # Check thresholds
    print("Checking thresholds...")
    alerts = agent.check_thresholds()
    
    if alerts:
        print(f"⚠️  {len(alerts)} alerts triggered:")
        for alert in alerts:
            print(f"  [{alert.severity.upper()}] {alert.name}")
            print(f"      {alert.metric} = {alert.current_value} (threshold: {alert.threshold})")
    else:
        print("✓ All metrics within thresholds")
    
    print()
    
    # Get active alerts
    active = agent.get_active_alerts()
    print(f"Active alerts: {len(active)}")
    
    # Acknowledge and resolve
    if active:
        print("\nAcknowledging and resolving alerts...")
        for alert in active:
            agent.acknowledge_alert(alert.alert_id, "oncall-engineer")
            agent.resolve_alert(alert.alert_id)
            print(f"  ✓ {alert.name} - resolved")


def example_cost_optimization():
    """Example: Cost optimization analysis."""
    print("\n" + "=" * 70)
    print("Example 5: Cost Optimization")
    print("=" * 70)
    print()
    
    agent = DevOpsAgent()
    
    # Generate cost report
    print("Analyzing costs...")
    report = agent.get_cost_report(days=30)
    
    print(f"\nCost Report ({report['period_days']} days):")
    print(f"  Current Monthly Cost: ${report['current_costs']['monthly_cost']:.2f}")
    print()
    
    # Show optimization opportunities
    if report['optimization_opportunities']:
        print("Optimization Opportunities:")
        for i, opp in enumerate(report['optimization_opportunities'], 1):
            print(f"  {i}. [{opp['type']}] {opp['resource_id']}")
            print(f"     Recommendation: {opp['recommendation']}")
            print(f"     Potential Savings: ${opp['potential_savings']:.2f}/month")
        print()
        print(f"Total Potential Monthly Savings: ${report['potential_monthly_savings']:.2f}")
    else:
        print("✓ No optimization opportunities identified")


def main():
    """Run all DevOps examples."""
    print("\n" + "=" * 70)
    print("DevOpsAgent - Comprehensive Examples")
    print("=" * 70)
    
    example_deployment_workflow()
    example_pipeline_orchestration()
    example_infrastructure_management()
    example_monitoring_alerting()
    example_cost_optimization()
    
    print("\n" + "=" * 70)
    print("All examples complete!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  - Integrate with your CI/CD system")
    print("  - Set up automated monitoring")
    print("  - Configure cost alerts")
    print("  - Enable auto-scaling policies")
    print()


if __name__ == "__main__":
    main()
