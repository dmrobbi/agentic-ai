#!/bin/bash
# =============================================================================
# Deploy Cyber Division to papers.example.internal
# =============================================================================

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   🚀 Deploying Cyber Division to papers.example.internal        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Configuration
SSH_KEY="${SSH_KEY:-$HOME/.ssh/deploy_key}"
SSH_USER="${SSH_USER:-deploy}"
SSH_HOST="${SSH_HOST:-jump.example.internal}"
SSH_PORT="${SSH_PORT:-2222}"
REMOTE_PATH="${REMOTE_PATH:-/home/deploy/app-portal/static/papers}"
LOCAL_DOCS="${LOCAL_DOCS:-$PWD/docs/papers_stsgym}"

echo "📁 Step 1/4: Uploading main index.html with Cyber Division links..."
scp -i ${SSH_KEY} -P ${SSH_PORT} \
  ${LOCAL_DOCS}/index-updated.html \
  ${SSH_USER}@${SSH_HOST}:${REMOTE_PATH}/index.html
echo "   ✅ Main page uploaded"
echo ""

echo "📁 Step 2/4: Uploading Cyber Division files..."
scp -i ${SSH_KEY} -P ${SSH_PORT} \
  ${LOCAL_DOCS}/cyber-division.html \
  ${SSH_USER}@${SSH_HOST}:${REMOTE_PATH}/cyber-division.html
echo "   ✅ Cyber Division landing page uploaded"
echo ""

echo "📁 Step 3/4: Setting permissions..."
ssh -i ${SSH_KEY} -P ${SSH_PORT} \
  ${SSH_USER}@${SSH_HOST} \
  "chmod -R 755 ${REMOTE_PATH}/cyber-division && chmod 644 ${REMOTE_PATH}/index.html"
echo "   ✅ Permissions set"
echo ""

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              ✅ Deployment Complete!                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "📄 Cyber Division is now live at:"
echo ""
echo "   🏠 Main Page (with Cyber Division links):"
echo "      https://papers.example.internal/"
echo ""
echo "   🤖 Cyber Division Hub:"
echo "      https://papers.example.internal/papers/cyber-division/index.html"
echo ""
echo "   🚀 KaliAgent Documentation:"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/"
echo ""
echo "   ⚡ Quick Start:"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/quickstart/"
echo ""
echo "   📊 Deployment Guide:"
echo "      https://papers.example.internal/papers/cyber-division/kaliagent/deployment/"
echo ""
echo "🎉 Cyber Division is now accessible from the main page!"
echo ""
