# Agentic AI Dashboard v2.0 - Backend Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY dashboard_v2/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (build context is the REPO ROOT - see
# dashboard_v2/docker-compose.yml) plus the agentic_ai package that
# server.py imports (agentic_ai.infrastructure.utils)
COPY dashboard_v2/backend/ ./
COPY agentic_ai/ ./agentic_ai/

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/api/health || exit 1

# Run server
CMD ["python", "server.py"]
