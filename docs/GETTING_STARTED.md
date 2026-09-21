# Getting Started with Agentic AI

Quick start guide for setting up and using Agentic AI.

## Prerequisites

- Python 3.10+
- Redis 6.0+
- SQLite 3.35+
- (Optional) PostgreSQL 14+
- (Optional) Docker & Docker Compose

## Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Docker Install

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

## Configuration

### Environment Variables

Create `.env` file:

```bash
# Redis
REDIS_URL=redis://localhost:6379

# Database (optional, defaults to SQLite)
DATABASE_URL=sqlite:///agentic_ai.db
# or
DATABASE_URL=postgresql://user:pass@localhost:5432/agentic_ai

# API Server
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=your-secret-key-here
JWT_EXPIRY=3600

# Logging
LOG_LEVEL=INFO
```

### Default Configuration

```python
# config.py
REDIS_URL = "redis://localhost:6379"
DATABASE_URL = "sqlite:///agentic_ai.db"
LOG_LEVEL = "INFO"
```

## Quick Start

### 1. Start Redis

```bash
# Docker
docker run -d -p 6379:6379 redis:7

# Or native
redis-server
```

### 2. Verify Installation

```bash
# Run health check
python -m agentic_ai.cli doctor

# Or use CLI
agenticai doctor
```

Expected output:
```
┌─────────────────────────────────────┐
│ Agentic AI Health Check             │
└─────────────────────────────────────┘
✓ Python Version: 3.11.5
✓ Agents Loaded: 33+
✓ Message Bus: Ready
✓ Task Queue: Ready
✓ Redis Connection: localhost:6379
✓ All checks passed!
```

### 3. Run Your First Agent

```python
from agentic_ai.agents.developer import DeveloperAgent

# Create agent
agent = DeveloperAgent("dev-1")

# Execute capability
result = agent.execute(
    action="implement",
    params={
        "spec": "Create a function to calculate fibonacci numbers",
        "language": "python",
    },
)

print(result)
```

### 4. Use the CLI

```bash
# Check system status
agenticai status

# List all agents
agenticai agent list

# Create chaos experiment
agenticai chaos experiment create \
  --name "Test Experiment" \
  --type instance_termination \
  --severity medium \
  --duration 15

# List vendors
agenticai vendor list

# Create audit
agenticai audit create \
  --title "SOC2 Audit" \
  --type it_general \
  --auditor "auditor@example.com"
```

### 5. Start the API Server

```bash
# Run server
python -m agentic_ai.server

# Or with uvicorn
uvicorn agentic_ai.server:app --reload
```

Access API at: http://localhost:8000

API docs: http://localhost:8000/docs

### 6. Access the Dashboard

```bash
# Build dashboard
cd dashboard
npm install
npm run build

# Or development mode
npm run dev
```

Access dashboard at: http://localhost:5173

## Core Concepts

### Agents

Agents are autonomous units with specific capabilities:

```python
from agentic_ai.agents.security import SecurityAgent

agent = SecurityAgent("security-1")

# Get available capabilities
capabilities = agent.get_capabilities()

# Execute capability
result = agent.execute(
    action="scan_vulnerabilities",
    params={"target": "192.0.2.1", "scan_type": "full"},
)
```

### Messages

Agents communicate via messages:

```python
from agentic_ai.messaging import MessageBus, Message

bus = MessageBus()
bus.connect()

# Publish message
bus.publish(Message(
    message_id="msg-1",
    message_type=MessageType.EVENT,
    topic="agent.security",
    payload={"action": "scan", "target": "192.0.2.1"},
))

# Subscribe to topic
def handler(message):
    print(f"Received: {message.payload}")

bus.subscribe("agent.security", handler)
```

### Events

Events are published to the event bus:

```python
from agentic_ai.messaging import EventBus, Event, EventPriority
from agentic_ai.messaging.event_bus import on_event

bus = EventBus()
bus.connect()

# Emit event
bus.emit(
    event_type="security.incident",
    data={"incident_id": "123", "severity": "high"},
    source="soc-agent",
    priority=EventPriority.HIGH,
)

# Handle event
@on_event('security.incident')
def handle_incident(event: Event):
    print(f"Incident: {event.data}")
```

### Tasks

Tasks are queued for async processing:

```python
from agentic_ai.messaging import TaskQueue

queue = TaskQueue()

# Register handler
@queue.register_handler('email.send')
def send_email(payload):
    # Send email logic
    return True

# Enqueue task
task = queue.enqueue(
    task_type='email.send',
    payload={'to': 'user@example.com', 'subject': 'Test'},
    priority=8,
)

# Run worker
queue.run_worker(queue_names=['default'])
```

## Common Workflows

### Multi-Agent Collaboration

```python
from agentic_ai.agents.lead import LeadAgent
from agentic_ai.agents.developer import DeveloperAgent
from agentic_ai.agents.qa import QAAgent

lead = LeadAgent("lead-1")
dev = DeveloperAgent("dev-1")
qa = QAAgent("qa-1")

# Orchestrate workflow
result = lead.orchestrate(
    task="Implement user login feature",
    agents=[dev, qa],
    workflow=[
        {"agent": dev, "action": "implement", "params": {"spec": "..."}},
        {"agent": dev, "action": "review", "params": {"code": "..."}},
        {"agent": qa, "action": "generate_tests", "params": {"code": "..."}},
        {"agent": qa, "action": "run_tests", "params": {}},
    ],
)
```

### Chaos Engineering

```python
from agentic_ai.agents.chaos_monkey import ChaosMonkeyAgent, ExperimentType

agent = ChaosMonkeyAgent()

# Create experiment
experiment = agent.create_experiment(
    name="AZ Failure Test",
    description="Test resilience to AZ failure",
    experiment_type=ExperimentType.AZ_FAILURE,
    severity=SeverityLevel.HIGH,
    blast_radius=BlastRadius.LIMITED,
    duration_minutes=30,
)

# Start experiment
run = agent.start_experiment(experiment.experiment_id)

# Monitor
status = agent.get_experiment_status(experiment.experiment_id)
```

### Vendor Risk Assessment

```python
from agentic_ai.agents.vendor_risk import VendorRiskAgent, VendorTier

agent = VendorRiskAgent()

# Add vendor
vendor = agent.add_vendor(
    name="CloudProvider Inc",
    legal_name="CloudProvider Inc.",
    tier=VendorTier.TIER_1,
    category="cloud",
    relationship_type="vendor",
)

# Create assessment
assessment = agent.create_assessment(
    vendor_id=vendor.vendor_id,
    assessment_type=AssessmentType.INITIAL,
    assessor="security-team",
)

# Get risk report
report = agent.get_vendor_risk_report(vendor.vendor_id)
```

## Testing

### Run Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_developer_agent.py

# With coverage
pytest --cov=agentic_ai

# Integration tests
pytest tests/integration/
```

### Write Tests

```python
# tests/test_my_agent.py
import pytest
from agentic_ai.agents.base import BaseAgent

def test_agent_initialization():
    agent = BaseAgent("test-1")
    assert agent.agent_id == "test-1"
    assert agent.get_state() is not None

def test_agent_capability():
    agent = BaseAgent("test-1")
    capabilities = agent.get_capabilities()
    assert len(capabilities) > 0
```

## Deployment

### Docker

```bash
# Build image
docker build -t agentic-ai:latest .

# Run container
docker run -d \
  -p 8000:8000 \
  -e REDIS_URL=redis://redis:6379 \
  --name agentic-ai \
  agentic-ai:latest
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml

# Check status
kubectl get pods -n agentic-ai
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all
docker-compose down
```

## Troubleshooting

### Redis Connection Issues

```bash
# Check Redis is running
redis-cli ping
# Should return: PONG

# Check connection from Python
python -c "import redis; r = redis.Redis(); print(r.ping())"
```

### Agent Not Responding

```python
# Check agent state
agent = DeveloperAgent("dev-1")
print(agent.get_state())

# Check logs
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Task Queue Issues

```bash
# Check Redis queues
redis-cli
> KEYS task:*
> LLEN task:queue:default
```

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- Check [AGENT_MATRIX.md](AGENT_MATRIX.md) for all agent capabilities
- See [examples/](../examples/) for usage examples
- Review [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment
- Join [Discord](https://discord.com/invite/clawd) for community support

## Resources

- **Documentation**: https://github.com/dmrobbi/agentic-ai/tree/main/docs
- **Examples**: https://github.com/dmrobbi/agentic-ai/tree/main/examples
- **API Reference**: http://localhost:8000/docs (when server running)
- **Issues**: https://github.com/dmrobbi/agentic-ai/issues
- **Discussions**: https://github.com/dmrobbi/agentic-ai/discussions

---

*Last updated: April 16, 2026*
