#!/bin/bash
# Agentic AI Production Deployment Script (Podman version)
# Usage: ./deploy-podman.sh [dev|staging|prod]

set -e

# Configuration
ENVIRONMENT=${1:-prod}
COMPOSE_FILE="docker-compose.podman.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

generate_secrets() {
    log_info "Generating secrets..."
    
    if [ ! -f .env ]; then
        cat > .env << EOF
# Agentic AI Environment Configuration
# Generated: $(date)

# PostgreSQL
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Application
SECRET_KEY=$(openssl rand -base64 32)

# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16)
EOF
        chmod 600 .env
        log_success "Created .env file with secure secrets"
    else
        log_warning ".env file already exists"
    fi
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p logs scripts
    log_success "Directories created"
}

initialize_database() {
    log_info "Creating database init script..."
    cat > scripts/init-db.sql << 'EOF'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE SCHEMA IF NOT EXISTS agentic_ai;
GRANT ALL PRIVILEGES ON SCHEMA agentic_ai TO postgres;
EOF
    log_success "Database init script created"
}

deploy() {
    log_info "Deploying Agentic AI (${ENVIRONMENT})..."
    
    # Pull images
    log_info "Pulling images..."
    podman-compose -f ${COMPOSE_FILE} pull
    
    # Start services
    log_info "Starting services..."
    podman-compose -f ${COMPOSE_FILE} up -d --build
    
    # Wait for services
    log_info "Waiting for services to start..."
    sleep 30
    
    # Check status
    podman-compose -f ${COMPOSE_FILE} ps
    
    log_success "Deployment complete!"
}

show_status() {
    log_info "Service Status:"
    podman-compose -f ${COMPOSE_FILE} ps
    echo ""
    log_info "Access URLs:"
    echo "  - API:         http://agents.example.com:8000"
    echo "  - Dashboard:   http://agents.example.com:3000"
    echo "  - Grafana:     http://agents.example.com:3001 (admin/admin)"
    echo "  - Prometheus:  http://agents.example.com:9090"
}

show_logs() {
    log_info "Logs (Ctrl+C to stop):"
    podman-compose -f ${COMPOSE_FILE} logs -f
}

# Main
case "${2:-}" in
    status) show_status ;;
    logs) show_logs ;;
    *)
        generate_secrets
        create_directories
        initialize_database
        deploy
        show_status
        ;;
esac
