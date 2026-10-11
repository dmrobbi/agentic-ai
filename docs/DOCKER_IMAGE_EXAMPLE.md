# Docker / Podman Image — Working Example

Verified end-to-end walkthrough for the production image (`Dockerfile`).
Cross-references: [DEPLOYMENT.md](DEPLOYMENT.md) (full deploy guide),
`docker-compose.yml` (Docker stack), `docker-compose.podman.yaml` (rootless/Podman stack),
`Dockerfile.demo` (thin demo image, port 8080).

Verified 2026-10-11 on thing1 with Docker `29.1.3` (overlay2): built the image,
ran the container, and captured every output below from the live container.
Podman commands are documented from the repo's own `deploy-podman.sh`;
the Podman compose file was validated on this host (`docker compose -f docker-compose.podman.yaml config` → OK).

## Image anatomy (Dockerfile)

| Ingredient | Value |
|---|---|
| Base | `python:3.11-slim` |
| Deps | `pip install -r requirements.txt` (FastAPI, uvicorn, redis, litellm, ...) |
| Runtime dirs | `/app/data`, `/app/logs`, `/app/config` |
| Port | `8000` |
| Healthcheck | Python urllib GET `http://localhost:8000/health` — interval 30s, timeout 10s, start-period 40s, retries 3 |
| Command | `python -m agentic_ai.server` (FastAPI demo server, binds `0.0.0.0:8000`) |

The server is self-contained: health and demo endpoints run with **no**
Redis/Ollama/Postgres present — those are only needed for the full compose stacks.

## 1. Build

```bash
cd agentic-ai          # repo root (Dockerfile + source live here)
docker build -t agentic-ai:latest .
```

Verification run: 13/13 steps OK → image `291f12039e10`, **693 MB**, tagged `agentic-ai:example`.

```bash
docker images agentic-ai
# agentic-ai   example   291f12039e10   693MB
```

Podman equivalent:

```bash
podman build -t agentic-ai:latest .
```

`.dockerignore` keeps the context small (~511 MB of node_modules/venvs/caches excluded).

## 2. Run as a single container

```bash
docker run -d --name agentic-ai -p 8000:8000 agentic-ai:latest

# wait for the built-in healthcheck
docker ps --filter name=agentic-ai --format '{{.Names}} {{.Status}}'
# agentic-ai   Up 3 seconds (health: starting)   ->   ... (healthy)
```

Podman equivalent (rootless works; repo compose file already carries the SELinux `:Z` labels):

```bash
podman run -d --name agentic-ai -p 8000:8000 agentic-ai:latest
```

## 3. Prove it (captured outputs)

```bash
curl -s http://localhost:8000/health
# {"status":"healthy","version":"1.0.0","environment":"production",
#  "timestamp":"2026-10-11T23:38:53.894722+00:00","agents_loaded":33}

curl -s http://localhost:8000/
# {"name":"Agentic AI","version":"1.0.0","status":"running","docs":"/docs"}

curl -s http://localhost:8000/api/agents | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["total"], d["agents"][0])'
# 33 {'agent_id': 'base-1', 'agent_type': 'base', 'status': 'healthy'}

curl -s http://localhost:8000/.well-known/agent-card | head -c 160
# {"name":"base_agent","description":"base agent with 3 tools",...}   (A2A agent-card discovery)

curl -o /dev/null -s -w '%{http_code}\n' http://localhost:8000/docs
# 200   (Swagger UI at /docs, ReDoc at /redoc)

docker inspect --format '{{.State.Health.Status}}' agentic-ai
# healthy
```

Container logs after those calls:

```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     172.17.0.1:49626 - "GET /health HTTP/1.1" 200 OK
INFO:     172.17.0.1:49638 - "GET / HTTP/1.1" 200 OK
INFO:     172.17.0.1:49646 - "GET /api/agents HTTP/1.1" 200 OK
```

## 4. Full stacks with compose

| File | Stack | Distinguishers |
|---|---|---|
| `docker-compose.yml` | app, redis, ollama (GPU), prometheus:9090, grafana:3000 | dev stack; LLM via Ollama, SQLite |
| `docker-compose.podman.yaml` | app, dashboard (nginx:3000), redis, postgres, prometheus:9090, grafana:3001 | rootless/Podman; `:Z` volume labels, full-qualified `docker.io` refs; validated with Docker Compose v2 as well |
| `Dockerfile.demo` | thin demo image | port **8080**, runs `api_server.py` |

```bash
# Docker stack
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps

# Podman stack (what deploy-podman.sh drives)
podman-compose -f docker-compose.podman.yaml up -d --build
./deploy-podman.sh prod           # same thing, with secret generation
```

Note: Docker Compose v2 warns `the attribute 'version' is obsolete` on the compose
files — harmless, the attribute is simply ignored.

## 5. Cleanup

```bash
docker stop agentic-ai && docker rm agentic-ai
docker rmi agentic-ai:latest
```

## Troubleshooting quick hits

- **`curl /health` fails right after start** — check `docker logs agentic-ai`; the
  healthcheck start-period is 40 s, so a healthy status can lag the port opening.
- **Port 8000 busy** — `ss -tlnp | grep :8000`; another stack may already hold it.
- **Build context huge** — make sure `COPY . .` is filtered by `.dockerignore`
  (it excludes venvs, node_modules, caches by design).