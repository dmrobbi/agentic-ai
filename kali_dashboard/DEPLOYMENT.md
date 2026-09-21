# KaliAgent Deployment Guide

Production deployment instructions for various environments.

---

## Table of Contents

1. [Docker Deployment](#docker-deployment)
2. [Kubernetes Deployment](#kubernetes-deployment)
3. [Cloud Deployment (AWS)](#cloud-deployment-aws)
4. [On-Premises Deployment](#on-premises-deployment)
5. [High Availability Setup](#high-availability-setup)
6. [Monitoring & Logging](#monitoring--logging)
7. [Backup & Recovery](#backup--recovery)
8. [Scaling Guide](#scaling-guide)

---

## Docker Deployment

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum
- 50GB storage

### Quick Deploy

```bash
# Clone repository
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai/kali_dashboard

# Create .env file
cat > .env << EOF
POSTGRES_USER=kali
POSTGRES_PASSWORD=secure_password_here
MSFRPC_PASSWORD=metasploit_password_here
AUTH_LEVEL=BASIC
EOF

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Docker Compose File

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  # KaliAgent Backend
  kali-agent:
    build: .
    ports:
      - "8001:8001"
    environment:
      - DATABASE_URL=postgresql://kali:secure_password_here@postgres:5432/kali
      - MSFRPC_HOST=metasploit
      - MSFRPC_PORT=55553
      - MSFRPC_PASSWORD=metasploit_password_here
      - AUTH_LEVEL=BASIC
      - AUDIT_LOG_PATH=/var/log/kali/audit.jsonl
    volumes:
      - kali_logs:/var/log/kali
      - kali_workspace:/tmp/kali-workspace
    depends_on:
      - postgres
      - metasploit
    restart: unless-stopped

  # Frontend Dashboard
  kali-frontend:
    build: ./frontend
    ports:
      - "80:80"
    volumes:
      - ./frontend/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - kali-agent
    restart: unless-stopped

  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=kali
      - POSTGRES_PASSWORD=secure_password_here
      - POSTGRES_DB=kali
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  # Metasploit RPC
  metasploit:
    image: metasploitframework/metasploit-framework
    command: >
      sh -c "msfdb init && 
             msfrpcd -P metasploit_password_here -a 0.0.0.0 -p 55553"
    ports:
      - "55553:55553"
    volumes:
      - msf_data:/root/.msf4
    restart: unless-stopped

  # Redis Cache
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

volumes:
  postgres_data:
  msf_data:
  kali_logs:
  kali_workspace:
```

### Dockerfile (Backend)

**Dockerfile:**

```dockerfile
FROM python:3.10-slim

# Install Kali tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    wpscan \
    john \
    hashcat \
    hydra \
    aircrack-ng \
    wireshark \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p /tmp/kali-workspace /var/log/kali

EXPOSE 8001

CMD ["python3", "server.py"]
```

### Dockerfile (Frontend)

**frontend/Dockerfile:**

```dockerfile
FROM node:18-alpine as builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### Verify Docker Deployment

```bash
# Test backend health
curl http://localhost:8001/api/health

# Expected: {"status":"healthy","tools_loaded":52}

# Test frontend
curl http://localhost

# Expected: HTML dashboard

# Check all services running
docker-compose ps

# Expected: All services showing "Up"
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.25+
- kubectl configured
- PersistentVolume provisioner
- LoadBalancer or Ingress controller

### Namespace & ConfigMap

**k8s/namespace.yaml:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kali-agent
  labels:
    name: kali-agent
```

**k8s/configmap.yaml:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kali-config
  namespace: kali-agent
data:
  AUTH_LEVEL: "BASIC"
  AUDIT_LOG_ENABLED: "true"
  DRY_RUN: "false"
  SAFE_MODE: "false"
  LOG_LEVEL: "INFO"
```

### Secrets

**k8s/secrets.yaml:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kali-secrets
  namespace: kali-agent
type: Opaque
stringData:
  postgres-password: "secure_password_here"
  msfrpc-password: "metasploit_password_here"
  api-key: "your_api_key_here"
```

### Deployments

**k8s/backend-deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kali-backend
  namespace: kali-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kali-backend
  template:
    metadata:
      labels:
        app: kali-backend
    spec:
      containers:
      - name: kali-agent
        image: wezzels/kali-agent:1.0.0
        ports:
        - containerPort: 8001
        env:
        - name: DATABASE_URL
          value: "postgresql://kali:$(POSTGRES_PASSWORD)@postgres:5432/kali"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: kali-secrets
              key: postgres-password
        - name: AUTH_LEVEL
          valueFrom:
            configMapKeyRef:
              name: kali-config
              key: AUTH_LEVEL
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8001
          initialDelaySeconds: 5
          periodSeconds: 5
```

**k8s/frontend-deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kali-frontend
  namespace: kali-agent
spec:
  replicas: 2
  selector:
    matchLabels:
      app: kali-frontend
  template:
    metadata:
      labels:
        app: kali-frontend
    spec:
      containers:
      - name: nginx
        image: wezzels/kali-frontend:1.0.0
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### Services

**k8s/services.yaml:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kali-backend
  namespace: kali-agent
spec:
  selector:
    app: kali-backend
  ports:
  - port: 8001
    targetPort: 8001
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: kali-frontend
  namespace: kali-agent
spec:
  selector:
    app: kali-frontend
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

### Ingress

**k8s/ingress.yaml:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kali-ingress
  namespace: kali-agent
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - kali.example.com
    secretName: kali-tls
  rules:
  - host: kali.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kali-frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: kali-backend
            port:
              number: 8001
```

### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/frontend-deployment.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/ingress.yaml

# Check deployment
kubectl get pods -n kali-agent
kubectl get services -n kali-agent
kubectl get ingress -n kali-agent

# View logs
kubectl logs -n kali-agent -l app=kali-backend -f
```

---

## Cloud Deployment (AWS)

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AWS Cloud                        │
│                                                     │
│  ┌─────────────┐                                   │
│  │  ALB        │                                   │
│  │  (HTTPS)    │                                   │
│  └──────┬──────┘                                   │
│         │                                          │
│    ┌────┴────┐                                     │
│    │         │                                     │
│ ┌──▼──┐  ┌──▼──────┐                              │
│ │ ECS │  │  RDS    │                              │
│ │Fargate│ │PostgreSQL│                             │
│ │(App) │  │         │                              │
│ └─────┘  └─────────┘                              │
│                                                     │
│  ┌─────────────┐  ┌──────────┐                    │
│  │   ECR       │  │  S3      │                    │
│  │  (Images)   │  │ (Reports)│                    │
│  └─────────────┘  └──────────┘                    │
└─────────────────────────────────────────────────────┘
```

### Terraform Configuration

**terraform/main.tf:**

```hcl
provider "aws" {
  region = "us-east-1"
}

# VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "kali-vpc"
  cidr = "198.51.100.0/16"
  
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["198.51.100.0/24", "198.51.100.0/24"]
  public_subnets  = ["198.51.100.0/24", "198.51.100.0/24"]
  
  enable_nat_gateway = true
  single_nat_gateway = true
}

# ECR Repository
resource "aws_ecr_repository" "kali_backend" {
  name                 = "kali-agent-backend"
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier     = "kali-postgres"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  
  allocated_storage = 100
  storage_encrypted = true
  
  db_name  = "kali"
  username = "kali"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.kali.name
  
  backup_retention_period = 30
  skip_final_snapshot    = false
}

# ECS Cluster
resource "aws_ecs_cluster" "kali" {
  name = "kali-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ALB
resource "aws_lb" "kali" {
  name               = "kali-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
  
  enable_deletion_protection = true
}

# S3 Bucket for Reports
resource "aws_s3_bucket" "kali_reports" {
  bucket = "kali-agent-reports-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kali_reports" {
  bucket = aws_s3_bucket.kali_reports.bucket
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### Deploy to AWS

```bash
# Initialize Terraform
cd terraform
terraform init

# Plan deployment
terraform plan -out=tfplan

# Apply deployment
terraform apply tfplan

# Build and push Docker image
docker build -t kali-agent .
docker tag kali-agent:latest ${AWS_ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/kali-agent-backend:latest
docker push ${AWS_ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/kali-agent-backend:latest

# Deploy to ECS
aws ecs update-service \
  --cluster kali-cluster \
  --service kali-backend \
  --force-new-deployment
```

---

## On-Premises Deployment

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Server** | 1x 8-core | 2x 16-core |
| **RAM** | 16 GB | 64 GB |
| **Storage** | 100 GB SSD | 500 GB NVMe |
| **Network** | 1 Gbps | 10 Gbps |

### Installation Script

**install.sh:**

```bash
#!/bin/bash

set -e

echo "=== KaliAgent On-Premises Installation ==="

# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y \
    python3.10 \
    python3-pip \
    nodejs \
    npm \
    postgresql \
    nginx \
    git \
    curl

# Create user
useradd -m -s /bin/bash kali-agent

# Clone repository
sudo -u kali-agent git clone https://github.com/dmrobbi/agentic-ai.git /opt/kali-agent
cd /opt/kali-agent

# Create virtual environment
sudo -u kali-agent python3 -m venv /opt/kali-agent/venv
sudo -u kali-agent /opt/kali-agent/venv/bin/pip install -r requirements.txt

# Setup PostgreSQL
sudo -u postgres psql -c "CREATE USER kali WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "CREATE DATABASE kali OWNER kali;"

# Configure systemd service
cat > /etc/systemd/system/kali-agent.service << EOF
[Unit]
Description=KaliAgent Backend
After=network.target postgresql.service

[Service]
Type=simple
User=kali-agent
WorkingDirectory=/opt/kali-agent
Environment=PATH=/opt/kali-agent/venv/bin:/usr/bin
ExecStart=/opt/kali-agent/venv/bin/python3 server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx
cat > /etc/nginx/sites-available/kali-agent << EOF
server {
    listen 80;
    server_name kali.local;
    
    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    
    location /static {
        alias /opt/kali-agent/kali_dashboard/frontend/dist;
    }
}
EOF

# Enable and start services
systemctl daemon-reload
systemctl enable kali-agent
systemctl start kali-agent
systemctl enable nginx
systemctl restart nginx

echo "=== Installation Complete ==="
echo "Access dashboard at: http://kali.local"
```

### Run Installation

```bash
# Download and run
curl -O https://raw.githubusercontent.com/wezzels/agentic-ai/main/kali_dashboard/install.sh
chmod +x install.sh
sudo ./install.sh

# Verify installation
systemctl status kali-agent
systemctl status nginx

# Check logs
journalctl -u kali-agent -f
```

---

## High Availability Setup

### Architecture

```
                    ┌─────────────┐
                    │  Load       │
                    │  Balancer   │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
    │ Backend │      │ Backend │      │ Backend │
    │ Node 1  │      │ Node 2  │      │ Node 3  │
    └────┬────┘      └────┬────┘      └────┬────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
         ┌────▼────┐            ┌────▼────┐
         │PostgreSQL│            │  Redis  │
         │  (HA)    │            │ Cluster │
         └──────────┘            └─────────┘
```

### PostgreSQL HA with Patroni

**patroni.yaml:**

```yaml
scope: kali-cluster
namespace: /service/
name: postgres-1

restapi:
  listen: 0.0.0.0:8008
  connect_address: postgres-1:8008

etcd:
  hosts: etcd-1:2379,etcd-2:2379,etcd-3:2379

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    synchronous_mode: true
    
  initdb:
    - encoding: UTF8
    - data-checksums
    
  users:
    postgres:
      password: postgres
      options:
        - superuser
    
    kali:
      password: kali_password
      options:
        - createdb

postgresql:
  listen: 0.0.0.0:5432
  connect_address: postgres-1:5432
  data_dir: /var/lib/postgresql/data
  pgpass: /tmp/pgpass0
  authentication:
    replication:
      username: replication
      password: replication_password
    superuser:
      username: postgres
      password: postgres
```

### Redis Cluster

**redis-cluster.conf:**

```conf
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
appendonly yes
port 6379
```

### Deploy HA Cluster

```bash
# Deploy etcd cluster
for i in 1 2 3; do
  docker run -d \
    --name etcd-$i \
    -p 2379:2379 \
    quay.io/coreos/etcd:v3.5.9 \
    etcd --name etcd-$i \
    --initial-advertise-peer-urls http://etcd-$i:2380 \
    --listen-peer-urls http://0.0.0.0:2380 \
    --listen-client-urls http://0.0.0.0:2379 \
    --advertise-client-urls http://etcd-$i:2379 \
    --initial-cluster-token etcd-cluster \
    --initial-cluster etcd-1=http://etcd-1:2380,etcd-2=http://etcd-2:2380,etcd-3=http://etcd-3:2380 \
    --initial-cluster-state new
done

# Deploy Patroni
for i in 1 2 3; do
  docker run -d \
    --name patroni-$i \
    -p 8008:8008 \
    -p 5432:5432 \
    -v patroni-$i-data:/var/lib/postgresql/data \
    -e PATRONI_NAME=postgres-$i \
    -e PATRONI_POSTGRESQL_DATA_DIR=/var/lib/postgresql/data \
    registry.opensource.zalan.do/acid/patroni-15:latest
done

# Deploy Redis cluster
for i in 1 2 3; do
  docker run -d \
    --name redis-$i \
    -p 6379:6379 \
    redis:7-alpine \
    redis-server --cluster-enabled yes
done

# Create Redis cluster
docker exec redis-1 redis-cli --cluster create \
  redis-1:6379 redis-2:6379 redis-3:6379 \
  --cluster-replicas 0
```

---

## Monitoring & Logging

### Prometheus Configuration

**prometheus.yml:**

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'kali-backend'
    static_configs:
      - targets: ['kali-backend:8001']
    metrics_path: '/metrics'
  
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
  
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### Grafana Dashboard

**Import Dashboard ID:** 12345 (KaliAgent Monitoring)

**Key Metrics:**
- Request rate
- Error rate
- Response time (p50, p95, p99)
- Tool execution count
- Findings discovered
- Active engagements
- System resources (CPU, Memory, Disk)

### Log Aggregation (ELK Stack)

**logstash.conf:**

```conf
input {
  file {
    path => "/var/log/kali/audit.jsonl"
    codec => json
    type => "kali-audit"
  }
}

filter {
  if [type] == "kali-audit" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "kali-audit-%{+YYYY.MM.dd}"
  }
}
```

---

## Backup & Recovery

### Backup Script

**backup.sh:**

```bash
#!/bin/bash

set -e

BACKUP_DIR="/backups/kali"
DATE=$(date +%Y%m%d_%H%M%S)

echo "Starting backup at $(date)"

# Create backup directory
mkdir -p $BACKUP_DIR/$DATE

# Backup PostgreSQL
pg_dump -h postgres -U kali kali > $BACKUP_DIR/$DATE/database.sql
gzip $BACKUP_DIR/$DATE/database.sql

# Backup audit logs
tar -czf $BACKUP_DIR/$DATE/audit_logs.tar.gz /var/log/kali/

# Backup reports
tar -czf $BACKUP_DIR/$DATE/reports.tar.gz /opt/kali-agent/reports/

# Backup configuration
cp /opt/kali-agent/.env $BACKUP_DIR/$DATE/
cp /etc/systemd/system/kali-agent.service $BACKUP_DIR/$DATE/

# Upload to S3
aws s3 sync $BACKUP_DIR/$DATE s3://kali-backups/$DATE/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -type d -mtime +30 -exec rm -rf {} \;

echo "Backup completed at $(date)"
```

### Recovery Script

**recovery.sh:**

```bash
#!/bin/bash

set -e

BACKUP_DATE=$1

if [ -z "$BACKUP_DATE" ]; then
  echo "Usage: $0 <backup_date>"
  echo "Example: $0 20260418_012345"
  exit 1
fi

BACKUP_DIR="/backups/kali/$BACKUP_DATE"

echo "Starting recovery from $BACKUP_DATE"

# Download from S3
aws s3 sync s3://kali-backups/$BACKUP_DATE $BACKUP_DIR/

# Restore database
gunzip -c $BACKUP_DIR/database.sql.gz | psql -h postgres -U kali kali

# Restore audit logs
tar -xzf $BACKUP_DIR/audit_logs.tar.gz -C /

# Restore reports
tar -xzf $BACKUP_DIR/reports.tar.gz -C /

# Restore configuration
cp $BACKUP_DIR/.env /opt/kali-agent/
cp $BACKUP_DIR/kali-agent.service /etc/systemd/system/

# Restart services
systemctl daemon-reload
systemctl restart kali-agent

echo "Recovery completed at $(date)"
```

### Automated Backups (Cron)

```bash
# Add to crontab
0 2 * * * /opt/kali-agent/backup.sh >> /var/log/kali/backup.log 2>&1
```

---

## Scaling Guide

### Horizontal Scaling

**Add Backend Nodes:**

```bash
# Kubernetes
kubectl scale deployment kali-backend --replicas=5

# Docker Swarm
docker service scale kali-backend=5

# Manual
for i in 4 5; do
  docker run -d \
    --name kali-backend-$i \
    -e DATABASE_URL=postgresql://... \
    wezzels/kali-agent:1.0.0
done
```

### Vertical Scaling

**Increase Resources:**

```yaml
# Kubernetes
resources:
  requests:
    memory: "2Gi"    # Was 512Mi
    cpu: "1000m"     # Was 250m
  limits:
    memory: "8Gi"    # Was 2Gi
    cpu: "4000m"     # Was 1000m
```

### Database Scaling

**Read Replicas:**

```yaml
# Add read replicas
postgresql:
  replication:
    - name: replica-1
      instance_class: db.t3.medium
    - name: replica-2
      instance_class: db.t3.medium
```

### Load Testing

```bash
# Install k6
sudo apt install k6

# Run load test
k6 run tests/load_test.js

# Expected results:
# - 1000 req/s sustained
# - p95 < 200ms
# - Error rate < 0.1%
```

---

## Troubleshooting

### Common Issues

#### Backend Won't Start

```bash
# Check logs
journalctl -u kali-agent -f

# Check database connection
psql -h postgres -U kali -c "SELECT 1"

# Check dependencies
pip list | grep -E "fastapi|uvicorn|pydantic"
```

#### High Memory Usage

```bash
# Check memory
docker stats kali-backend

# Profile application
python3 -m cProfile -o profile.stats server.py

# Optimize queries
psql -h postgres -U kali -c "EXPLAIN ANALYZE SELECT ..."
```

#### Slow Response Times

```bash
# Check slow queries
psql -h postgres -U kali -c "SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10"

# Add indexes
psql -h postgres -U kali -c "CREATE INDEX CONCURRENTLY idx_engagements_status ON engagements(status)"

# Check Redis
redis-cli INFO stats
```

---

## Resources

- **Docker Docs**: https://docs.docker.com
- **Kubernetes Docs**: https://kubernetes.io/docs
- **AWS ECS**: https://aws.amazon.com/ecs
- **Terraform**: https://terraform.io
- **Prometheus**: https://prometheus.io
- **Grafana**: https://grafana.com

---

*Last Updated: April 18, 2026*
*Version: 1.0.0*
