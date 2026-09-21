# Agentic AI - Deployment Guide

**Version:** 0.7.0  
**Last Updated:** April 16, 2026

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Configuration](#configuration)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Docker | 24.0+ | Container runtime |
| kubectl | 1.28+ | Kubernetes CLI |
| Python | 3.12+ | Development |
| Redis | 7.0+ | Message bus |
| Ollama | Latest | LLM inference |

### Hardware Requirements

| Environment | CPU | Memory | Storage | GPU |
|-------------|-----|--------|---------|-----|
| Development | 4 cores | 8GB | 20GB | Optional |
| Staging | 8 cores | 16GB | 50GB | Recommended |
| Production | 16+ cores | 32GB+ | 100GB+ | Required |

---

## Quick Start

### Development Environment

```bash
# Clone repository
git clone https://gitlab.example.internal/crab-meat-repos/agentic-ai.git
cd agentic-ai

# Start full stack (app + Redis + Ollama + Prometheus + Grafana)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f agentic-ai
```

**Access Points:**
- API: http://localhost:5000
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090

---

## Docker Deployment

### Build Image

```bash
# Build production image
docker build -t agentic-ai:latest .

# Tag for registry
docker tag agentic-ai:latest gitlab.example.internal:5050/crab-meat-repos/agentic-ai:0.7.0
```

### Run Container

```bash
docker run -d \
  --name agentic-ai \
  -p 5000:5000 \
  -p 8000:8000 \
  -e REDIS_HOST=redis \
  -e DATABASE_URL=sqlite:///app/data/agentic.db \
  -v ./data:/app/data \
  -v ./logs:/app/logs \
  agentic-ai:latest
```

### Docker Compose Services

| Service | Port | Description |
|---------|------|-------------|
| agentic-ai | 5000, 8000 | Main application |
| redis | 6379 | Message bus |
| ollama | 11434 | LLM inference |
| prometheus | 9090 | Metrics collection |
| grafana | 3000 | Dashboards |

---

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl apply -f kubernetes/namespace.yaml
```

### 2. Configure Secrets

```bash
# Create database secret
kubectl create secret generic agentic-ai-secrets \
  --from-literal=database-url='sqlite:///app/data/agentic.db' \
  -n agentic-ai

# Create Redis secret (if password required)
kubectl create secret generic agentic-ai-secrets \
  --from-literal=redis-password='your-password' \
  -n agentic-ai
```

### 3. Apply Manifests

```bash
# Apply all manifests
kubectl apply -f kubernetes/

# Or apply individually
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
```

### 4. Verify Deployment

```bash
# Check pods
kubectl get pods -n agentic-ai

# Check services
kubectl get services -n agentic-ai

# Check ingress
kubectl get ingress -n agentic-ai

# View logs
kubectl logs -f deployment/agentic-ai -n agentic-ai
```

### 5. Scale Application

```bash
# Manual scaling
kubectl scale deployment agentic-ai --replicas=5 -n agentic-ai

# Auto-scaling is configured via HPA (3-10 replicas based on CPU/memory)
kubectl get hpa -n agentic-ai
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTIC_AI_ENV` | production | Environment (dev/staging/prod) |
| `AGENTIC_AI_LOG_LEVEL` | INFO | Logging level |
| `REDIS_HOST` | localhost | Redis hostname |
| `REDIS_PORT` | 6379 | Redis port |
| `DATABASE_URL` | sqlite:///app/data/agentic.db | Database connection |
| `OLLAMA_HOST` | http://localhost:11434 | Ollama endpoint |
| `MAX_WORKERS` | 10 | Maximum agent workers |
| `SESSION_TIMEOUT_MINUTES` | 30 | Session inactivity timeout |

### ConfigMap Settings

Edit `kubernetes/configmap.yaml`:

```yaml
data:
  redis-host: "redis.agentic-ai.svc.cluster.local"
  redis-port: "6379"
  log-level: "INFO"
  max-workers: "10"
  session-timeout-minutes: "30"
```

---

## Monitoring

### Prometheus Metrics

Agentic AI exposes metrics on port 8000:

- `agentic_ai_agents_total` - Total active agents
- `agentic_ai_sessions_active` - Active collaboration sessions
- `agentic_ai_operations_total` - Total operations processed
- `agentic_ai_collaboration_events_total` - Collaboration events
- `agentic_ai_request_duration_seconds` - Request latency histogram

### Grafana Dashboards

Pre-configured dashboards:

1. **System Overview** - CPU, memory, network
2. **Agent Performance** - Agent activity, task completion
3. **Collaboration Metrics** - Sessions, participants, operations
4. **Error Tracking** - Error rates, types, sources

Access Grafana: http://localhost:3000

### Alerting Rules

Configure alerts in `monitoring/prometheus-rules.yaml`:

```yaml
groups:
  - name: agentic-ai-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(agentic_ai_errors_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High error rate detected"
      
      - alert: SessionTimeout
        expr: agentic_ai_sessions_active < 1
        for: 30m
        annotations:
          summary: "No active sessions for 30 minutes"
```

---

## Troubleshooting

### Common Issues

#### Pod Not Starting

```bash
# Check pod status
kubectl describe pod <pod-name> -n agentic-ai

# Check logs
kubectl logs <pod-name> -n agentic-ai

# Check events
kubectl get events -n agentic-ai --sort-by='.lastTimestamp'
```

#### Database Connection Failed

```bash
# Verify secret exists
kubectl get secret agentic-ai-secrets -n agentic-ai

# Check DATABASE_URL format
kubectl get secret agentic-ai-secrets -o jsonpath='{.data.database-url}' -n agentic-ai | base64 -d
```

#### Redis Connection Issues

```bash
# Test Redis connectivity
kubectl run redis-test --rm -it --image=redis:alpine --restart=Never -- redis-cli -h redis ping

# Check Redis logs
kubectl logs deployment/redis -n agentic-ai
```

#### High Latency

```bash
# Check resource usage
kubectl top pods -n agentic-ai

# Check HPA status
kubectl get hpa -n agentic-ai

# Scale manually if needed
kubectl scale deployment agentic-ai --replicas=5 -n agentic-ai
```

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Basic health check |
| `/ready` | Readiness probe (dependencies checked) |
| `/metrics` | Prometheus metrics |
| `/api/v1/status` | Application status |

---

## Support

For issues and questions:
- **GitHub Issues:** https://github.com/openclaw/openclaw/issues
- **Documentation:** https://docs.openclaw.ai
- **Discord:** https://discord.com/invite/clawd
