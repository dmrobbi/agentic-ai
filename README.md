# Agentic AI 🤖

**Version:** 1.0.0  
**Status:** Production Ready ✅  
**License:** MIT

[![Tests](https://img.shields.io/badge/tests-780%2B%20passing-green)]()
[![Coverage](https://img.shields.io/badge/coverage-95%25-blue)]()
[![Python](https://img.shields.io/badge/python-3.10+-blue)]()
[![Agents](https://img.shields.io/badge/agents-33-purple)]()
[![Docker](https://img.shields.io/badge/docker-ready-blue)]()
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-blue)]()

---

## What is Agentic AI?

**Agentic AI** is an enterprise-grade multi-agent orchestration platform with 33+ specialized agents for security, compliance, DevOps, business operations, and more.

Think of it as an **"operating system for AI agents"** — providing infrastructure for communication, collaboration, decision-making, and production deployment.

### 🎯 Use Cases

- **Security Operations**: SOC, vulnerability management, red teaming, malware analysis
- **Compliance & Governance**: GDPR, CCPA, SOC2, HIPAA, ethics, risk management
- **DevOps & SRE**: Chaos engineering, infrastructure automation, monitoring
- **Business Operations**: Sales, finance, HR, marketing, product management
- **Data & ML**: Data analysis, MLOps, research, data governance
- **Supply Chain**: SBOM generation, vendor risk, audit management

---

## ✨ Key Features

| Category | Features |
|----------|----------|
| **🤖 33+ Agents** | Security, Compliance, DevOps, Business, Data, Governance, Specialized |
| **💬 Messaging** | Redis pub/sub, event bus, task queues, agent protocol |
| **📊 Dashboard** | React/TypeScript web UI with 6 views (Chaos, Vendor Risk, Audit, etc.) |
| **🖥️ CLI** | Interactive CLI for chaos experiments, assessments, audits |
| **🔗 Orchestration** | Multi-agent workflows, lead agent coordination |
| **📈 Monitoring** | Prometheus metrics, Grafana dashboards, alerting |
| **🚀 Deployment** | Docker, Kubernetes, CI/CD, auto-scaling (HPA) |
| **🧪 Testing** | 780+ tests, integration tests with cloud API mocks |

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai

# Start full stack
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Option 2: Local Installation

```bash
# Clone and setup
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt

# Start Redis (required)
docker run -d -p 6379:6379 redis:7

# Run health check
python -m agentic_ai.cli doctor
```

### Option 3: CLI Tool

```bash
# Install CLI
pip install -e .

# Check status
agenticai status

# List agents
agenticai agent list

# Create chaos experiment
agenticai chaos experiment create -n "Test" -t instance_termination -s high
```

---

## 📦 Agent Catalog

### Core Agents (5)
| Agent | Purpose |
|-------|---------|
| `Base` | Foundation agent with core functionality |
| `Developer` | Code implementation, review, refactoring |
| `QA` | Testing, quality assurance, coverage analysis |
| `SysAdmin` | System administration, log analysis |
| `Lead` | Multi-agent orchestration and coordination |

### Business Agents (5)
| Agent | Purpose |
|-------|---------|
| `Sales` | Lead management, opportunity tracking |
| `Finance` | Transactions, budgeting, financial reports |
| `HR` | Employee management, benefits, payroll |
| `Marketing` | Campaigns, content generation, analytics |
| `Product` | Feature management, roadmap, metrics |

### Security Agents (6)
| Agent | Purpose |
|-------|---------|
| `Security` | Vulnerability scanning, threat detection |
| `SOC` | Security operations center, incident response |
| `VulnMan` | Vulnerability management, prioritization |
| `RedTeam` | Penetration testing, attack simulation |
| `Malware` | Malware analysis, reverse engineering |
| `CloudSecurity` | CSPM for AWS/Azure/GCP |

### Governance Agents (5)
| Agent | Purpose |
|-------|---------|
| `Legal` | Contract review, legal research |
| `Compliance` | SOC2, ISO27001, compliance monitoring |
| `Privacy` | GDPR, CCPA, LGPD, HIPAA compliance |
| `Risk` | Risk assessment, exposure calculation |
| `Ethics` | AI ethics, bias assessment |

### Specialized Agents (5)
| Agent | Purpose |
|-------|---------|
| `MLOps` | ML lifecycle, model training, drift detection |
| `SupplyChain` | SBOM, dependency scanning |
| `Audit` | Internal audit, controls testing |
| `VendorRisk` | Vendor assessments, SIG questionnaires |
| `ChaosMonkey` | Chaos engineering, resiliency testing |

**See [AGENT_MATRIX.md](docs/AGENT_MATRIX.md) for complete capability reference.**

---

## 📊 Web Dashboard

Real-time monitoring dashboard with 6 specialized views:

```bash
# Build and run dashboard
cd dashboard
npm install
npm run dev

# Access at http://localhost:5173
```

### Dashboard Views

| View | Description |
|------|-------------|
| **Overview** | System health, agent status, recent activity |
| **Chaos Monkey** | Experiments, runs, resiliency scores |
| **Vendor Risk** | Vendor assessments, risk scores, findings |
| **Audit** | Audit progress, findings, remediation |
| **Cloud Security** | CSPM findings, compliance scores |
| **ML Ops** | Models, experiments, drift detection |

---

## 🖥️ CLI Commands

```bash
# System
agenticai status          # System status
agenticai doctor          # Health check
agenticai version         # Version info

# Agents
agenticai agent list      # List all agents
agenticai agent info dev  # Agent details

# Chaos Monkey
agenticai chaos experiment create -n "Test" -t az_failure -s high
agenticai chaos experiment list
agenticai chaos status

# Vendor Risk
agenticai vendor list
agenticai vendor add -n "CloudProvider" -t 1
agenticai vendor assess -v vendor-123

# Audit
agenticai audit create -t "SOC2 2026" -a auditor@firm.com
agenticai audit status -a audit-123

# Cloud Security
agenticai cloud finding list -s critical
agenticai cloud compliance -f cis_aws

# ML Ops
agenticai ml model list
agenticai ml experiment list
```

**See [cmd/README.md](cmd/README.md) for full CLI documentation.**

---

## 🔗 Multi-Agent Orchestration

### Example: Security Incident Response

```python
from agentic_ai.agents.lead import LeadAgent
from agentic_ai.agents.cyber.soc import SOCAgent
from agentic_ai.agents.security import SecurityAgent

lead = LeadAgent("lead-1")
soc = SOCAgent("soc-1")
security = SecurityAgent("sec-1")

# Orchestrate incident response
result = lead.orchestrate(
    task="Respond to security incident",
    agents=[soc, security],
    workflow=[
        {"agent": soc, "action": "triage_alert", "params": {"alert_id": "alert-123"}},
        {"agent": security, "action": "scan_vulnerabilities", "params": {"target": "192.0.2.1"}},
        {"agent": soc, "action": "investigate_incident", "params": {"incident_id": "inc-123"}},
        {"agent": lead, "action": "aggregate", "params": {"results": "..."}},
    ],
)
```

**See [examples/orchestration/](examples/orchestration/) for 5 complete workflows:**
- Security Incident Response
- Product Launch
- Chaos Monitoring
- Vendor Assessment
- Audit Preparation

---

## 📡 Event-Driven Architecture

### Message Bus (Redis Pub/Sub)

```python
from agentic_ai.messaging import MessageBus, Message

bus = MessageBus()
bus.connect()

# Publish
bus.publish(Message(
    topic="agent.security",
    payload={"action": "scan", "target": "192.0.2.1"},
))

# Subscribe
bus.subscribe("agent.security", lambda msg: print(msg.payload))
```

### Event Bus (Event Sourcing)

```python
from agentic_ai.messaging import EventBus, EventPriority
from agentic_ai.messaging.event_bus import on_event

bus = EventBus()

# Emit
bus.emit(
    event_type="security.incident",
    data={"incident_id": "123"},
    priority=EventPriority.HIGH,
)

# Handle
@on_event('security.incident')
def handle_incident(event):
    print(f"Incident: {event.data}")
```

### Task Queue

```python
from agentic_ai.messaging import TaskQueue

queue = TaskQueue()

@queue.register_handler('email.send')
def send_email(payload):
    # Send email
    return True

queue.enqueue(
    task_type='email.send',
    payload={'to': 'user@example.com'},
    priority=8,
)
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agentic_ai

# Integration tests
pytest tests/integration/

# Specific test file
pytest tests/test_chaos_monkey.py
```

### Test Coverage

| Suite | Tests | Coverage |
|-------|-------|----------|
| Unit Tests | 720+ | 95% |
| Integration Tests | 25+ | Cloud API mocks |
| E2E Tests | 35+ | Full workflows |
| **Total** | **780+** | **95%** |

---

## 🚀 Deployment

### Docker

```bash
# Build
docker build -t agentic-ai:latest .

# Run
docker run -d -p 8000:8000 --name agentic-ai agentic-ai:latest
```

### Kubernetes

```bash
# Deploy
kubectl apply -f kubernetes/

# Check status
kubectl get pods -n agentic-ai
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# Includes: app, Redis, PostgreSQL, Prometheus, Grafana
```

**See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment guide.**

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Quick start guide |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture |
| [AGENT_MATRIX.md](docs/AGENT_MATRIX.md) | Agent capability reference |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment |
| [SECURITY.md](docs/SECURITY.md) | Security practices |
| [DEVOPS.md](docs/DEVOPS.md) | DevOps guide |
| [DATA.md](docs/DATA.md) | Data management |
| [SUPPORT.md](docs/SUPPORT.md) | Support and troubleshooting |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AGENTIC AI PLATFORM                   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Web UI   │  │ CLI      │  │ REST API │  │ ACP      │ │
│  │ (React)  │  │ (Typer)  │  │ (FastAPI)│  │ Protocol │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       └─────────────┴─────────────┴─────────────┘       │
│                          │                               │
│                 ┌────────▼────────┐                      │
│                 │  Message Bus    │                      │
│                 │  (Redis)        │                      │
│                 └────────┬────────┘                      │
│                          │                               │
│       ┌──────────────────┼──────────────────┐           │
│       │                  │                  │           │
│  ┌────▼────┐      ┌─────▼─────┐     ┌──────▼──────┐    │
│  │Event Bus│      │Task Queue │     │Agent Registry│   │
│  └─────────┘      └───────────┘     └─────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │              33+ SPECIALIZED AGENTS                │ │
│  │  Core │ Business │ Security │ Governance │ etc.   │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.**

---

## 📊 Performance

| Metric | Target | Actual |
|--------|--------|--------|
| Real-time ops/sec | 500 | **570** |
| Workspace ops/sec | 50K | **60K+** |
| Session ops/sec | 50K | **65K+** |
| P99 Latency | <5ms | **<4ms** |
| P95 Latency | <3ms | **<2ms** |
| P50 Latency | <1ms | **<0.5ms** |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone fork
git clone https://github.com/your-username/agentic-ai.git
cd agentic-ai

# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Start Redis
docker run -d -p 6379:6379 redis:7
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- CLI powered by [Typer](https://typer.tiangolo.com/)
- Dashboard uses [React](https://react.dev/) + [Vite](https://vitejs.dev/)
- Testing with [pytest](https://pytest.org/)
- Monitoring with [Prometheus](https://prometheus.io/) + [Grafana](https://grafana.com/)

---

## 📬 Contact

- **GitHub**: https://github.com/dmrobbi/agentic-ai
- **GitLab**: https://gitlab.example.internal/crab-meat-repos/agentic-ai
- **Discord**: https://discord.com/invite/clawd

---

*Last updated: April 16, 2026*
