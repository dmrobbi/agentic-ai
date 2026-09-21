# KaliAgent v3 - Quick Installation on KVM VM

**Target:** 198.51.100.99 or 198.51.100.70 (Kali Linux VM)  
**User:** demo-user (with sudo)  
**Time:** ~10 minutes

---

## 🚀 Quick Installation (Copy & Paste)

### Step 1: Clone Repository

```bash
cd /tmp
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai/kali_agent_v3/install
chmod +x install.sh
```

### Step 2: Run Installer

```bash
# For standard installation (~2GB)
sudo ./install.sh --standard

# OR for minimal installation (~500MB)
sudo ./install.sh --minimal

# OR for advanced installation (~5GB)
sudo ./install.sh --advanced
```

### Step 3: Configure

```bash
# Edit configuration
sudo nano /etc/kaliagent_v3/.env

# Change these defaults:
KALIAGENT_PIN=your_secure_pin_here
KALIAGENT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

### Step 4: Start Service

```bash
sudo systemctl start kaliagent
sudo systemctl enable kaliagent
```

### Step 5: Verify Installation

```bash
# Check service status
sudo systemctl status kaliagent

# Test CLI
kaliagent --version

# Run health check
kaliagent health

# List tools
kaliagent tools list --limit 10
```

---

## 📋 Pre-Installation Checklist

### Requirements
- [ ] Kali Linux 2023.x or later
- [ ] Python 3.9+ (`python3 --version`)
- [ ] 10GB+ free disk space (`df -h`)
- [ ] 4GB+ RAM (`free -h`)
- [ ] Internet access (`ping -c 3 kali.org`)
- [ ] Sudo access (`sudo whoami`)

### Verify System
```bash
# Check OS
cat /etc/os-release | grep Kali

# Check Python
python3 --version

# Check disk space
df -h /opt /var

# Check RAM
free -h
```

---

## 🔧 Troubleshooting

### If Git Not Installed
```bash
sudo apt-get update
sudo apt-get install -y git
```

### If Python Not Installed
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
```

### If Installation Fails
```bash
# Check logs
sudo journalctl -u kaliagent -n 50

# Verify Python environment
sudo /opt/kaliagent_v3/venv/bin/python --version

# Test imports
sudo /opt/kaliagent_v3/venv/bin/python -c "from core.tool_manager import ToolManager; print('OK')"
```

### If Service Won't Start
```bash
# Check status
sudo systemctl status kaliagent

# Restart service
sudo systemctl restart kaliagent

# View logs
sudo journalctl -u kaliagent -f
```

---

## 📊 Installation Profiles

| Profile | Size | Tools | Best For |
|---------|------|-------|----------|
| **--minimal** | ~500MB | Essential | Learning, testing |
| **--standard** ⭐ | ~2GB | Common | Most users |
| **--advanced** | ~5GB | Extended | Red teams |
| **--expert** | ~8GB | All 602 | Researchers |

---

## 🎯 Post-Installation

### 1. Change Default Credentials

```bash
sudo nano /etc/kaliagent_v3/.env
```

**Must Change:**
```bash
KALIAGENT_PIN=changeme  # ← CHANGE THIS!
KALIAGENT_SECRET_KEY=changeme  # ← CHANGE THIS!
```

### 2. Test Functionality

```bash
# Check tool database
kaliagent tools list --limit 5

# Search for tools
kaliagent tools search nmap

# Request authorization
kaliagent auth request nmap_scan --reason "Network mapping"

# Run security audit
kaliagent audit run

# Check system health
kaliagent health
```

### 3. View Documentation

```bash
cd /opt/kaliagent_v3/docs
ls -la

# Read guides
cat README.md
cat API_REFERENCE.md
cat TRAINING_GUIDE.md
```

---

## 🔒 Security Hardening

### 1. Set Strong PIN
```bash
# Generate secure PIN
python3 -c "import secrets; print(''.join([str(secrets.randbelow(10)) for _ in range(8)]))"
```

### 2. Configure Firewall
```bash
# If exposing API (not recommended without auth)
sudo ufw allow from 127.0.0.1 to any port 8080
sudo ufw enable
```

### 3. Enable Audit Logging
```bash
sudo nano /etc/kaliagent_v3/kaliagent.conf
```

Ensure:
```ini
[authorization]
audit_all_actions = true
```

### 4. Regular Updates
```bash
# Update KaliAgent
cd /opt/kaliagent_v3
sudo git pull
sudo systemctl restart kaliagent
```

---

## 📞 Support

### Logs
- Service: `sudo journalctl -u kaliagent -f`
- Application: `sudo tail -f /var/log/kaliagent_v3/kaliagent.log`

### Documentation
- Local: `/opt/kaliagent_v3/docs/`
- Repository: `kali_agent_v3/docs/`

### Issues
- Check: `sudo systemctl status kaliagent`
- Logs: `sudo journalctl -xe`

---

## ✅ Installation Verification Checklist

After installation, verify:

- [ ] Service running: `sudo systemctl is-active kaliagent`
- [ ] CLI working: `kaliagent --version`
- [ ] Tools loaded: `kaliagent tools list` (should show 67 tools)
- [ ] Authorization working: `kaliagent auth request test`
- [ ] Logs accessible: `sudo tail /var/log/kaliagent_v3/kaliagent.log`
- [ ] Configuration secure: PIN and secret key changed
- [ ] Health check passes: `kaliagent health`

---

**Installation complete! 🍀**

*For detailed documentation, see INSTALL_GUIDE.md*
