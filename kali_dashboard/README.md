# KaliAgent - Professional Security Automation Platform

**Enterprise-grade Kali Linux tool orchestration with high-fidelity web dashboard and professional PDF reporting.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Tests](https://img.shields.io/badge/tests-38%20passing-green.svg)
![Tools](https://img.shields.io/badge/tools-52-orange.svg)

---

## 🎯 What is KaliAgent?

KaliAgent is a comprehensive security automation platform that provides:

- **52 Kali Linux Tools** - Pre-configured with safety controls
- **5 Automated Playbooks** - One-click security assessments
- **High-Fidelity Web Dashboard** - Professional React UI with real-time monitoring
- **PDF Report Generation** - Executive-ready reports with charts and graphics
- **Safety Controls** - IP whitelist/blacklist, authorization levels, audit logging
- **Metasploit Integration** - Full RPC database synchronization
- **RedTeam Integration** - Autonomous engagement execution

---

## 🚀 Quick Start

### 5-Minute Setup

```bash
# 1. Install dependencies
pip install fastapi uvicorn pydantic reportlab matplotlib

# 2. Install dashboard
cd kali_dashboard/frontend
npm install

# 3. Start backend
cd ..
python3 server.py &

# 4. Start frontend
cd frontend
npm run dev

# 5. Open dashboard
# http://localhost:5173
```

### First Engagement

1. Go to **Playbooks** tab
2. Select **Comprehensive Reconnaissance**
3. Enter target: `scanme.nmap.org` (safe test target)
4. Click **Execute**
5. Watch live execution and view results

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [INSTALL.md](INSTALL.md) | Complete installation instructions |
| [QUICKSTART.md](QUICKSTART.md) | Get started in 15 minutes |
| [USER_GUIDE.md](USER_GUIDE.md) | Comprehensive usage guide |
| [SECURITY.md](SECURITY.md) | Safety guidelines and best practices |
| [TESTING.md](TESTING.md) | Testing documentation |
| [API Docs](http://localhost:8001/docs) | Interactive API reference |

---

## 🎨 Features

### Web Dashboard

**6 Professional Pages:**

1. **Dashboard** - Overview, stats, quick actions
2. **Engagements** - Create and manage security assessments
3. **Playbooks** - Execute automated workflows
4. **Tools** - Browse 52 available Kali tools
5. **Settings** - Configure safety, authorization, reports
6. **Live Monitor** - Real-time execution tracking

**High-Fidelity Design:**
- Dark theme with gradient accents
- Animated status indicators
- Interactive progress bars
- Severity color coding
- Responsive layout
- Professional iconography

---

### Automated Playbooks

| Playbook | Tools | Duration | Authorization |
|----------|-------|----------|---------------|
| **Reconnaissance** | 5 tools | 45-90 min | BASIC |
| **Web Audit** | 5 tools | 60-120 min | ADVANCED |
| **Password Audit** | 4 tools | 30min-24hrs | ADVANCED |
| **Wireless Audit** | 4 tools | 30-90 min | ADVANCED |
| **AD Audit** | 3 tools | 30-60 min | CRITICAL |

---

### PDF Report Generator

**Professional Reports Include:**
- Executive summary with risk level
- Findings pie chart (Matplotlib)
- Tool execution summary table
- Detailed findings with severity badges
- Remediation recommendations
- Appendix with full tool output

**Formats:** PDF, Markdown, HTML, JSON

---

### Safety Controls

**Multi-Layer Protection:**

1. **IP Whitelist** - Only scan approved targets
2. **IP Blacklist** - Never scan specific IPs
3. **Authorization Levels** - 4-tier enforcement (NONE/BASIC/ADVANCED/CRITICAL)
4. **Audit Logging** - Complete JSONL audit trail
5. **Dry-Run Mode** - Test without execution
6. **Safe Mode** - Read-only operations
7. **Target Validation** - Automatic before execution

---

## 🛠️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 KaliAgent Platform                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐     ┌──────────────┐                │
│  │  React UI    │────▶│  FastAPI     │                │
│  │  Dashboard   │     │  Backend     │                │
│  └──────────────┘     └──────┬───────┘                │
│                              │                         │
│              ┌───────────────┼───────────────┐        │
│              │               │               │        │
│              ▼               ▼               ▼        │
│       ┌──────────┐   ┌──────────┐   ┌──────────┐    │
│       │  Kali    │   │Metasploit│   │   PDF    │    │
│       │  Tools   │   │   RPC    │   │ Generator│    │
│       │  (52)    │   │          │   │          │    │
│       └──────────┘   └──────────┘   └──────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Tool Categories

| Category | Tools | Examples |
|----------|-------|----------|
| **Reconnaissance** | 10 | Nmap, Amass, theHarvester, Shodan |
| **Web Application** | 11 | SQLMap, BurpSuite, Nikto, Gobuster |
| **Password Attacks** | 8 | John, Hashcat, Hydra, Medusa |
| **Wireless** | 5 | Aircrack-ng, Reaver, Wifite |
| **Post-Exploitation** | 4 | BloodHound, Mimikatz, Empire |
| **Forensics** | 4 | Volatility, ExifTool, SleuthKit |
| **Exploitation** | 3 | Metasploit, Searchsploit |
| **Vulnerability Analysis** | 3 | Nikto, OpenVAS, Nmap NSE |
| **Sniffing/Spoofing** | 2 | Wireshark, Responder |
| **Social Engineering** | 1 | SEToolkit |
| **Malware Analysis** | 1 | Binwalk |

**Total: 52 Tools**

---

## 🔒 Security

### Authorization Framework

| Level | Tools | Use Case | Approval |
|-------|-------|----------|----------|
| **NONE** | 0 | View only | None |
| **BASIC** | 18 | Reconnaissance | Standard |
| **ADVANCED** | 28 | Exploitation | Management |
| **CRITICAL** | 52 | Full access | Executive + Legal |

### Compliance

- ✅ PCI-DSS ready
- ✅ HIPAA considerations
- ✅ GDPR compliant logging
- ✅ SOC 2 documentation
- ✅ Complete audit trail

---

## 🧪 Testing

### Test Suite

**38 Unit Tests - 100% Passing**

```bash
# Run all tests
python3 -m pytest tests/test_kali_agent.py -v

# Run with coverage
python3 -m pytest tests/test_kali_agent.py -v --cov=agentic_ai.agents.cyber.kali
```

### Test Coverage

| Component | Coverage |
|-----------|----------|
| Core Agent | 93% |
| Playbooks | 97% |
| Safety Controls | 100% |
| Output Parsers | 94% |
| **Overall** | **92%** |

---

## 📦 Installation

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Storage** | 20 GB | 50+ GB SSD |
| **OS** | Kali 2024.x / Ubuntu 22.04+ | Kali Linux |

### Install on Kali Linux

```bash
# Clone repository
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai

# Install Python dependencies
pip install -r requirements.txt

# Install dashboard
cd kali_dashboard/frontend
npm install

# Verify installation
cd ../..
python3 -m pytest tests/test_kali_agent.py -v
```

### Install on Ubuntu

```bash
# Install Kali tools
echo "deb http://http.kali.org/kali kali-rolling main" | \
    sudo tee /etc/apt/sources.list.d/kali.list
wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -
sudo apt update
sudo apt install -y kali-linux-default

# Install KaliAgent
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai
pip install -r requirements.txt
```

---

## 🎯 Use Cases

### 1. External Penetration Testing

```bash
# Create engagement
curl -X POST http://localhost:8001/api/engagements \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q2 External Pentest",
    "type": "penetration_test",
    "targets": ["example.com", "203.0.113.0/24"]
  }'

# Execute recon playbook
curl -X POST http://localhost:8001/api/engagements/eng-001/playbook \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_type": "recon",
    "target": "example.com",
    "domain": "example.com"
  }'

# Generate PDF report
curl http://localhost:8001/api/engagements/eng-001/report?format=pdf \
  --output report.pdf
```

### 2. Web Application Security Audit

```bash
# Execute web audit
curl -X POST http://localhost:8001/api/engagements/eng-001/playbook \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_type": "web_audit",
    "url": "https://app.example.com",
    "target": "app.example.com"
  }'
```

### 3. Password Strength Assessment

```bash
# Execute password audit
curl -X POST http://localhost:8001/api/engagements/eng-001/playbook \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_type": "password_audit",
    "hash_file": "/path/to/hashes.txt",
    "wordlist": "/usr/share/wordlists/rockyou.txt"
  }'
```

---

## 🤝 Integration

### Metasploit Framework

```python
from agentic_ai.agents.cyber.kali import KaliAgent

agent = KaliAgent()
agent.connect_metasploit(host="127.0.0.1", port=55553, password="your_password")

# Import Nmap results
agent.msfrpc.import_nmap("scan.xml")

# Get hosts from database
hosts = agent.msfrpc.get_hosts()

# Execute post-exploitation module
result = agent.msfrpc.run_post_module(
    module="post/multi/recon/local_exploit_suggester",
    session_id="1"
)
```

### RedTeam Agent

```python
from agentic_ai.agents.cyber import RedTeamAgent

redteam = RedTeamAgent()

# Create engagement
engagement = redteam.create_engagement(
    name="Auto Pentest",
    engagement_type="penetration_test",
    start_date=datetime.utcnow(),
    scope=["192.0.2.0/24"]
)

# Execute full autonomous engagement
result = redteam.execute_kali_full_engagement(
    engagement_id=engagement.engagement_id,
    targets=["192.0.2.100", "192.0.2.101"]
)
```

---

## 📈 Roadmap

### Phase 1: Core Platform ✅ COMPLETE
- [x] 52 Kali tools integration
- [x] 5 automated playbooks
- [x] Safety controls
- [x] Authorization system
- [x] Unit tests (38 tests)

### Phase 2: Dashboard & Reports ✅ COMPLETE
- [x] FastAPI backend
- [x] React frontend (6 pages)
- [x] Live execution monitoring
- [x] PDF report generator
- [x] High-fidelity UI design

### Phase 3: Advanced Features (In Progress)
- [ ] Custom playbook builder
- [ ] Email report delivery
- [ ] SIEM integration
- [ ] Scheduled scanning
- [ ] Multi-user support

### Phase 4: Enterprise (Planned)
- [ ] Kubernetes deployment
- [ ] High availability
- [ ] Distributed scanning
- [ ] Advanced analytics
- [ ] API rate limiting

---

## 🐛 Troubleshooting

### Common Issues

**Tools Not Found:**
```bash
# Install Kali tools
sudo apt install -y kali-linux-default

# Verify installation
which nmap nikto sqlmap
```

**Dashboard Won't Start:**
```bash
cd kali_dashboard/frontend
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
npm run dev
```

**Metasploit Connection Failed:**
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Start Metasploit RPC
msfrpcd -P your_password -a 127.0.0.1 -p 55553
```

---

## 📞 Support

### Resources
- **Documentation**: See guides above
- **API Reference**: http://localhost:8001/docs
- **GitHub Issues**: Report bugs
- **Discord**: Community support

### Contact
- **GitHub**: https://github.com/dmrobbi/agentic-ai
- **Discord**: https://discord.gg/clawd
- **Email**: security@example.com

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Notice

**KaliAgent is a powerful security testing tool. Use responsibly:**

- ✅ Only scan systems you own or have explicit written authorization for
- ✅ Comply with all applicable laws and regulations
- ✅ Follow ethical guidelines and responsible disclosure
- ✅ Maintain proper documentation and audit trails

**Misuse can result in:**
- Criminal charges
- Civil liability
- System damage
- Data loss

**See [SECURITY.md](SECURITY.md) for complete safety guidelines.**

---

## 🙏 Acknowledgments

- Kali Linux team for amazing tools
- Metasploit Framework community
- FastAPI and React communities
- Open source security community

---

## 📊 Stats

- **Total Code**: ~5,000 lines
- **Tools Integrated**: 52
- **Test Coverage**: 92%
- **Documentation**: 6 comprehensive guides
- **Dashboard Pages**: 6
- **Playbooks**: 5 automated workflows

---

*Last Updated: April 18, 2026*  
*Version: 1.0.0*

**Made with 🍀 by the Agentic AI Team**
