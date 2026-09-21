#!/bin/bash
# =============================================================================
# Deploy KaliAgent Documentation to papers.example.internal
# =============================================================================

set -e

# Configuration
JUMP_HOST="${JUMP_HOST:-jump.example.internal}"
JUMP_PORT="${JUMP_PORT:-2222}"
JUMP_USER="${JUMP_USER:-deploy}"
JUMP_KEY="${JUMP_KEY:-$HOME/.ssh/deploy_key}"
MINER_HOST="${MINER_HOST:-gpu-host}"
REMOTE_PATH="${REMOTE_PATH:-/home/deploy/app-portal/static/papers/cyber-division}"
LOCAL_PATH="${LOCAL_PATH:-$PWD/docs/papers_stsgym}"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   🚀 KaliAgent Documentation Deployment                   ║"
echo "║   Deploying to papers.example.internal                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Create remote directory structure
echo "📁 Step 1/5: Creating directory structure..."
ssh -i ${JUMP_KEY} -p ${JUMP_PORT} ${JUMP_USER}@${JUMP_HOST} \
  "ssh ${MINER_HOST} 'mkdir -p ${REMOTE_PATH}/{kaliagent/{quickstart,user-guide,deployment,integration,training,api-reference,examples,media/{screenshots,diagrams,videos}},cyber-agents/{soc-agent,vulnman-agent,redteam-agent,malware-agent,security-agent,cloudsec-agent},resources/{presentations,videos,downloads}}'"
echo "   ✅ Directory structure created"
echo ""

# Step 2: Copy KaliAgent core documentation
echo "📄 Step 2/5: Copying KaliAgent core documentation..."

# Main index
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/index.md

# Quick start
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/quickstart/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/quickstart/index.md

# User guide
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/user-guide/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/user-guide/index.md

# Deployment
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/deployment/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/deployment/index.md

# Integration
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/integration/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/integration/index.md

# Training
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/training/index.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/training/index.md

# Additional docs
scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/kaliagent/*.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/kaliagent/

echo "   ✅ KaliAgent documentation copied"
echo ""

# Step 3: Copy Cyber Agents documentation
echo "🤖 Step 3/5: Copying Cyber Agents documentation..."

scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/cyber-agents/overview.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/cyber-agents/overview.md

echo "   ✅ Cyber Agents documentation copied"
echo ""

# Step 4: Copy resources
echo "📚 Step 4/5: Copying resources..."

scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/resources/presentations/*.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/resources/presentations/

scp -i ${JUMP_KEY} -P ${JUMP_PORT} \
  ${LOCAL_PATH}/resources/*.md \
  ${JUMP_USER}@${JUMP_HOST}:${REMOTE_PATH}/resources/

echo "   ✅ Resources copied"
echo ""

# Step 5: Set permissions
echo "🔒 Step 5/5: Setting permissions..."

ssh -i ${JUMP_KEY} -p ${JUMP_PORT} ${JUMP_USER}@${JUMP_HOST} \
  "ssh ${MINER_HOST} 'chmod -R 755 ${REMOTE_PATH} && chown -R deploy:deploy ${REMOTE_PATH}'"

echo "   ✅ Permissions set"
echo ""

# Summary
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              ✅ Deployment Complete!                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "📄 Documentation is now live at:"
echo ""
echo "   🏠 Landing Page:"
echo "      https://papers.example.internal/papers/cyber-division/"
echo ""
echo "   🚀 KaliAgent:"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/quickstart/"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/user-guide/"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/deployment/"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/integration/"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/training/"
echo ""
echo "   🤖 Cyber Agents:"
echo "      https://papers.example.internal/papers/cyber-division/cyber-agents/"
echo ""
echo "   📊 Resources:"
echo "      https://papers.example.internal/papers/cyber-division/resources/"
echo ""
echo "🎉 KaliAgent documentation is now publicly accessible!"
echo ""
echo "🍀 Made with ❤️ by the Agentic AI Team"
