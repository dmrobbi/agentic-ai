# DevOpsAgent - Infrastructure Automation & CI/CD

**Version:** 1.0.0  
**Status:** Production Ready ✅

---

## Overview

The **DevOpsAgent** provides infrastructure automation, CI/CD pipeline management, deployment orchestration, monitoring, and cost optimization for your applications and infrastructure.

### Key Capabilities

- 🚀 **Deployment Management** - Create, track, and rollback deployments
- 🔧 **CI/CD Pipelines** - Orchestrate build, test, and deploy stages
- 🖥️ **Infrastructure** - Track VMs, databases, storage, networks
- 📊 **Monitoring** - Metrics, alerts, threshold checking
- 💰 **Cost Optimization** - Track costs, identify savings

---

## Quick Start

```python
from agentic_ai.agents.devops import DevOpsAgent, DeploymentStatus

# Initialize
devops = DevOpsAgent()

# Create deployment
deployment = devops.create_deployment(
    application="my-app",
    version="1.0.0",
    environment="production",
    deployed_by="ci-bot",
)

# Track progress
devops.update_deployment_status(deployment.deployment_id, DeploymentStatus.DEPLOYING)
```

---

## Deployment Management

### Create Deployment

```python
from agentic_ai.agents.devops import DevOpsAgent

devops = DevOpsAgent()

deployment = devops.create_deployment(
    application="my-app",
    version="1.2.0",
    environment="production",  # dev, staging, prod
    deployed_by="ci-bot",
    health_check_url="https://my-app.com/health",
)

print(f"Deployment ID: {deployment.deployment_id}")
print(f"Status: {deployment.status.value}")
```

### Update Deployment Status

```python
from agentic_ai.agents.devops import DeploymentStatus

# Building
devops.update_deployment_status(
    deployment.deployment_id,
    DeploymentStatus.BUILDING,
    logs=["Building Docker image..."],
)

# Testing
devops.update_deployment_status(
    deployment.deployment_id,
    DeploymentStatus.TESTING,
    logs=["Running tests..."],
)

# Deploying
devops.update_deployment_status(
    deployment.deployment_id,
    DeploymentStatus.DEPLOYING,
)

# Deployed
devops.update_deployment_status(
    deployment.deployment_id,
    DeploymentStatus.DEPLOYED,
)
```

### Rollback Deployment

```python
devops.rollback_deployment(
    deployment.deployment_id,
    rollback_to="1.0.0",
    rolled_back_by="admin",
)
```

### Get Deployments

```python
# All deployments
deployments = devops.get_deployments()

# Filter by environment
prod = devops.get_deployments(environment="production")

# Filter by status
failed = devops.get_deployments(status=DeploymentStatus.FAILED)

# Limit results
recent = devops.get_deployments(limit=10)
```

---

## CI/CD Pipeline Management

### Create Pipeline

```python
pipeline = devops.create_pipeline(
    name="Main CI/CD",
    repository="my-app",
    branch="main",
    stages=["build", "test", "lint", "security-scan", "deploy"],
)
```

### Start Pipeline

```python
devops.start_pipeline(pipeline.pipeline_id)
```

### Update Stage Status

```python
# Pass a stage
devops.update_pipeline_stage(pipeline.pipeline_id, "build", "passed")

# Fail a stage
devops.update_pipeline_stage(pipeline.pipeline_id, "test", "failed")
```

### Get Pipelines

```python
from agentic_ai.agents.devops import PipelineStatus

# All pipelines
pipelines = devops.get_pipelines()

# Filter by status
running = devops.get_pipelines(status=PipelineStatus.RUNNING)
passed = devops.get_pipelines(status=PipelineStatus.PASSED)
```

---

## Infrastructure Management

### Register Resource

```python
from agentic_ai.agents.devops import InfrastructureType, InfrastructureResource

resource = InfrastructureResource(
    resource_id="web-server-1",
    resource_type=InfrastructureType.VM,
    name="Production Web Server 1",
    region="us-east-1",
    status="running",
    cost_per_hour=0.10,
    tags={"env": "prod", "team": "platform"},
)

devops.register_resource(resource)
```

### Update Resource Status

```python
devops.update_resource_status("web-server-1", "stopped")
```

### Get Infrastructure Summary

```python
summary = devops.get_infrastructure_summary()

print(f"Total Resources: {summary['total_resources']}")
print(f"By Type: {summary['by_type']}")
print(f"By Status: {summary['by_status']}")
print(f"Hourly Cost: ${summary['hourly_cost']:.2f}")
print(f"Daily Cost: ${summary['daily_cost']:.2f}")
print(f"Monthly Cost: ${summary['monthly_cost']:.2f}")
```

### Get Resource Costs

```python
costs = devops.get_resource_costs(hours=24)

for resource_id, cost in costs.items():
    if resource_id != 'total':
        print(f"{resource_id}: ${cost:.2f}")

print(f"Total (24h): ${costs['total']:.2f}")
```

---

## Monitoring & Alerting

### Record Metrics

```python
devops.record_metric("cpu_usage", 75.5, {"host": "web-1"})
devops.record_metric("memory_usage", 82.0, {"host": "web-1"})
devops.record_metric("error_rate", 0.5, {"service": "api"})
```

### Create Alert

```python
alert = devops.create_alert(
    name="High CPU Usage",
    severity="critical",  # critical, warning, info
    metric="cpu_usage",
    threshold=90.0,
    current_value=95.5,
)
```

### Acknowledge & Resolve Alerts

```python
# Acknowledge
devops.acknowledge_alert(alert.alert_id, "oncall-engineer")

# Resolve
devops.resolve_alert(alert.alert_id)
```

### Check Thresholds

```python
# Automatically check metrics against thresholds
alerts = devops.check_thresholds()

for alert in alerts:
    print(f"[{alert.severity.upper()}] {alert.name}")
    print(f"  {alert.metric} = {alert.current_value} (threshold: {alert.threshold})")
```

### Get Active Alerts

```python
# All active alerts
active = devops.get_active_alerts()

# Filter by severity
critical = devops.get_active_alerts(severity="critical")
```

---

## Cost Optimization

### Generate Cost Report

```python
report = devops.get_cost_report(days=30)

print(f"Current Monthly Cost: ${report['current_costs']['monthly_cost']:.2f}")
print(f"Potential Savings: ${report['potential_monthly_savings']:.2f}")

# Show optimization opportunities
for opp in report['optimization_opportunities']:
    print(f"\n{opp['type']}: {opp['resource_id']}")
    print(f"  Recommendation: {opp['recommendation']}")
    print(f"  Savings: ${opp['potential_savings']:.2f}/month")
```

---

## Deployment Statuses

| Status | Description |
|--------|-------------|
| `pending` | Deployment created, waiting to start |
| `building` | Building artifacts/images |
| `testing` | Running tests |
| `deploying` | Deploying to environment |
| `deployed` | Successfully deployed |
| `failed` | Deployment failed |
| `rolled_back` | Rolled back to previous version |

---

## Pipeline Statuses

| Status | Description |
|--------|-------------|
| `queued` | Pipeline waiting to start |
| `running` | Pipeline executing |
| `passed` | All stages passed |
| `failed` | Stage failed |
| `cancelled` | Pipeline cancelled |

---

## Infrastructure Types

| Type | Description |
|------|-------------|
| `virtual_machine` | VM instances |
| `container` | Container instances |
| `database` | Database instances |
| `storage` | Storage buckets/volumes |
| `network` | VPCs, subnets, gateways |
| `load_balancer` | Load balancers |
| `cdn` | CDN distributions |
| `dns` | DNS zones/records |

---

## Default Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU Usage | 70% | 90% |
| Memory Usage | 75% | 95% |
| Disk Usage | 80% | 95% |
| Error Rate | 1% | 5% |
| Latency P99 | 500ms | 1000ms |

---

## Examples

See `examples/devops_automation.py` for comprehensive examples:

```bash
cd ~/agentic-ai/agentic_ai
PYTHONPATH=. ./venv/bin/python examples/devops_automation.py
```

**Examples Include:**
1. Deployment workflow
2. CI/CD pipeline orchestration
3. Infrastructure management
4. Monitoring & alerting
5. Cost optimization

---

## Testing

```bash
# Run unit tests
pytest tests/test_devops_agent.py -v
```

**Test Coverage:**
- Initialization (2 tests)
- Deployment management (4 tests)
- Pipeline management (4 tests)
- Infrastructure management (4 tests)
- Monitoring & alerting (7 tests)
- Cost optimization (1 test)
- Capabilities export (1 test)

---

## Lead Agent Integration

```python
from agentic_ai.agents.devops import get_capabilities

caps = get_capabilities()

# Returns:
# {
#   'agent_type': 'devops',
#   'version': '1.0.0',
#   'capabilities': ['create_deployment', 'start_pipeline', ...],
#   'deployment_statuses': [...],
#   'pipeline_statuses': [...],
#   'infrastructure_types': [...],
# }
```

---

## Best Practices

### 1. Track All Deployments

```python
# Always create deployment records
deployment = devops.create_deployment(...)

# Update status as you progress
devops.update_deployment_status(deployment.deployment_id, status)
```

### 2. Monitor Costs Regularly

```python
# Generate weekly cost reports
report = devops.get_cost_report(days=7)

# Review optimization opportunities
for opp in report['optimization_opportunities']:
    print(f"Save ${opp['potential_savings']:.2f}/month: {opp['recommendation']}")
```

### 3. Set Up Alerting

```python
# Record metrics continuously
devops.record_metric("cpu_usage", cpu_percent)

# Check thresholds periodically
alerts = devops.check_thresholds()

# Notify team of critical alerts
for alert in alerts:
    if alert.severity == "critical":
        notify_team(alert)
```

### 4. Use CI/CD Pipelines

```python
# Define pipeline stages
pipeline = devops.create_pipeline(
    name="Main CI/CD",
    stages=["build", "test", "deploy"],
)

# Track progress through stages
for stage in pipeline.stages:
    devops.update_pipeline_stage(pipeline.pipeline_id, stage, "passed")
```

---

## Support

- **Documentation:** `docs/DEVOPS.md`
- **Examples:** `examples/devops_automation.py`
- **Tests:** `tests/test_devops_agent.py`
- **Issues:** https://github.com/openclaw/openclaw/issues

---

**DevOpsAgent v1.0.0 - Production Ready** 🚀
