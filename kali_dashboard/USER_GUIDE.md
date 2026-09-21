# KaliAgent User Guide

Comprehensive guide for using KaliAgent security automation platform.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Creating Engagements](#creating-engagements)
4. [Executing Playbooks](#executing-playbooks)
5. [Managing Tools](#managing-tools)
6. [Safety Controls](#safety-controls)
7. [Generating Reports](#generating-reports)
8. [Advanced Features](#advanced-features)
9. [Best Practices](#best-practices)

---

## Getting Started

### First Login

1. Open dashboard: http://localhost:5173
2. You'll see the **Dashboard** homepage with:
   - Statistics overview
   - Recent engagements
   - Tool categories
   - Quick actions

### Initial Configuration

**Before your first scan:**

1. Go to **Settings** → **Safety Controls**
2. Configure IP whitelist (required targets)
3. Configure IP blacklist (never scan)
4. Set authorization level to BASIC initially
5. Enable audit logging

---

## Dashboard Overview

### Main Dashboard

**Stats Cards:**
- **Total Tools**: Number of available Kali tools (52)
- **Active Engagements**: Currently running assessments
- **Findings**: Total vulnerabilities discovered
- **Reports Generated**: Number of reports created

**Recent Engagements:**
- Shows last 5 engagements
- Progress bars for active engagements
- Status indicators (Planning, In Progress, Completed)

**Quick Actions:**
- New Recon Engagement
- Web Audit
- Password Crack
- Generate Report

---

## Creating Engagements

### New Engagement Wizard

**Step 1: Basic Information**
- **Name**: Descriptive name (e.g., "Q2 2026 External Pentest")
- **Type**: Select engagement type
  - Penetration Test
  - Red Team
  - Web Application Audit
  - Network Reconnaissance
  - Wireless Assessment

**Step 2: Scope Definition**
- **Targets**: IP addresses, domains, CIDR ranges
  ```
  192.0.2.0/24
  example.com
  198.51.100.100
  ```
- **Objectives**: What you want to achieve
  ```
  - Identify external vulnerabilities
  - Test web application security
  - Validate firewall rules
  ```

**Step 3: Rules of Engagement**
- **Time Window**: When scanning is allowed
- **Rate Limits**: Packets per second
- **Excluded Systems**: What NOT to scan
- **Emergency Contacts**: Who to call if issues arise

**Step 4: Review & Create**
- Review all settings
- Confirm authorization level
- Click **Create Engagement**

### Engagement Status

| Status | Description | Actions |
|--------|-------------|---------|
| **Planning** | Engagement created, not started | Edit, Delete, Start |
| **In Progress** | Actively executing playbooks | View, Pause, Stop |
| **Completed** | All playbooks finished | View Results, Generate Report |
| **Paused** | Temporarily stopped | Resume, Stop |

---

## Executing Playbooks

### Available Playbooks

#### 1. Comprehensive Reconnaissance

**Purpose**: External information gathering

**Tools Used**:
- Nmap (port scanning)
- theHarvester (email/subdomain harvest)
- Amass (subdomain enumeration)
- DNSrecon (DNS records)
- Nikto (web server scan)

**When to Use**:
- Initial assessment phase
- External attack surface mapping
- Pre-engagement intelligence

**Duration**: 45-90 minutes

**Authorization**: BASIC

---

#### 2. Web Application Security Audit

**Purpose**: Find web vulnerabilities

**Tools Used**:
- Gobuster (directory brute-force)
- Nikto (web vulnerabilities)
- WPScan (WordPress audit)
- SQLMap (SQL injection)
- SSLScan (TLS configuration)

**When to Use**:
- Web app security assessment
- Pre-deployment security testing
- Compliance requirements

**Duration**: 60-120 minutes

**Authorization**: ADVANCED

---

#### 3. Password Cracking Audit

**Purpose**: Test password strength

**Tools Used**:
- Hash-Identifier (identify hash types)
- John the Ripper (dictionary attack)
- Hashcat (GPU brute-force)
- Crunch (custom wordlist generation)

**When to Use**:
- Password policy validation
- Compromised credential analysis
- Security awareness training

**Duration**: 30 minutes - 24 hours

**Authorization**: ADVANCED

---

#### 4. Wireless Security Audit

**Purpose**: Assess WiFi security

**Tools Used**:
- Kismet (network detection)
- Wifite (automated audit)
- Aircrack-ng (WPA cracking)
- Reaver (WPS attack)

**When to Use**:
- WiFi security assessment
- Physical security testing
- Rogue AP detection

**Duration**: 30-90 minutes

**Authorization**: ADVANCED

---

#### 5. Active Directory Audit

**Purpose**: AD security posture assessment

**Tools Used**:
- BloodHound (AD mapping)
- Impacket (protocol analysis)
- LDAPSearch (directory queries)

**When to Use**:
- Internal network assessment
- AD security review
- Privilege escalation testing

**Duration**: 30-60 minutes

**Authorization**: CRITICAL

---

### Executing a Playbook

**Via Dashboard:**

1. Go to **Playbooks** tab
2. Select desired playbook
3. Review execution steps
4. Enter required parameters:
   - Target IP/Domain
   - Additional options
5. Click **Execute Playbook**
6. Monitor live execution on **Live Monitor** page

**Via API:**

```bash
curl -X POST http://localhost:8001/api/engagements/{id}/playbook \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_type": "recon",
    "target": "192.0.2.100",
    "domain": "example.com"
  }'
```

### Monitoring Execution

**Live Monitor Page Shows:**

- **Metrics Dashboard**:
  - Tools executed
  - Findings discovered
  - Elapsed time
  - Success rate

- **Execution Status**:
  - Current tool running
  - Progress bars
  - Queue of pending tools

- **Live Output**:
  - Real-time console output
  - Tool stdout/stderr
  - Error messages

- **Performance Chart**:
  - Tool execution times
  - Success/failure indicators

- **Findings Feed**:
  - Live vulnerability discoveries
  - Severity indicators
  - Timestamps

---

## Managing Tools

### Tool Catalog

**Browse Tools:**
1. Go to **Tools** tab
2. Filter by category:
   - Reconnaissance (10 tools)
   - Web Application (11 tools)
   - Password Attacks (8 tools)
   - Wireless (5 tools)
   - Post-Exploitation (4 tools)
   - Forensics (4 tools)
   - Exploitation (3 tools)
   - Vulnerability Analysis (3 tools)
   - Sniffing/Spoofing (2 tools)

**Search Tools:**
- Search by name
- Search by description
- Search by command

**Tool Details:**
- Description
- Authorization level required
- Command syntax
- Example usage
- Category

### Tool Authorization Levels

| Level | Color | Tools Available | Use Case |
|-------|-------|-----------------|----------|
| **NONE** | Gray | 0 | View only |
| **BASIC** | Blue | 18 | Reconnaissance |
| **ADVANCED** | Orange | 28 | Exploitation |
| **CRITICAL** | Red | 52 | Full access |

---

## Safety Controls

### IP Whitelist

**Purpose**: Only allow scanning of approved targets

**Configuration:**
```
192.0.2.0/24
198.51.100.0/8
203.0.113.0/12
example.com
```

**Behavior:**
- If whitelist is set, ONLY whitelisted IPs can be scanned
- Attempts to scan non-whitelisted IPs are blocked
- Error message: "Target not in whitelist"

### IP Blacklist

**Purpose**: Never scan specific IPs

**Configuration:**
```
8.8.8.8
1.1.1.1
192.0.2.1  # Gateway
```

**Behavior:**
- Blacklisted IPs are ALWAYS blocked
- Takes precedence over whitelist
- Error message: "Target is blacklisted"

### Authorization Levels

**Setting Level:**
1. Go to **Settings** → **Authorization**
2. Select desired level
3. Click **Save**

**Enforcement:**
- Tools check authorization before execution
- Insufficient authorization = execution denied
- Error message shows required level

### Audit Logging

**What's Logged:**
- Timestamp
- Tool name
- Command executed
- Arguments
- Exit code
- Duration
- Target
- User/Engagement ID

**Log Location:**
```
/tmp/kali-dashboard/logs/audit_log.jsonl
```

**Log Format:**
```json
{
  "timestamp": "2026-04-18T01:23:45.123Z",
  "tool_name": "nmap",
  "command": "nmap -sV -p 1-1000 192.0.2.100",
  "arguments": {"target": "192.0.2.100", "ports": "1-1000"},
  "exit_code": 0,
  "duration_seconds": 45.3,
  "engagement_id": "eng-2026041801"
}
```

---

## Generating Reports

### Report Types

#### PDF Report (Professional)

**Features:**
- Executive summary
- Severity pie chart
- Tool execution table
- Detailed findings
- Remediation recommendations
- Appendix with full output

**When to Use:**
- Executive presentations
- Client deliverables
- Compliance documentation
- Audit evidence

**Generate:**
```bash
curl -X POST http://localhost:8001/api/engagements/{id}/report \
  -H "Content-Type: application/json" \
  -d '{"format": "pdf"}' \
  --output report.pdf
```

#### Markdown Report

**Features:**
- Lightweight format
- Easy to edit
- Git-friendly
- Converts to HTML/PDF

**When to Use:**
- Internal documentation
- Quick sharing
- Version control
- Further processing

**Generate:**
```bash
curl http://localhost:8001/api/engagements/{id}/report?format=markdown \
  > report.md
```

#### JSON Report

**Features:**
- Machine-readable
- API integration
- Data analysis
- Automation

**When to Use:**
- SIEM integration
- Ticketing systems
- Custom dashboards
- Data processing

**Generate:**
```bash
curl http://localhost:8001/api/engagements/{id}/report?format=json \
  > report.json
```

### Report Sections

**1. Title Page**
- Engagement name
- Report date
- Classification

**2. Executive Summary**
- High-level overview
- Key findings
- Risk level
- Recommendations

**3. Findings Overview**
- Pie chart by severity
- Total findings count
- Critical/High/Medium/Low breakdown

**4. Tools Executed**
- Table of all tools
- Status (success/failure)
- Duration
- Exit codes

**5. Detailed Findings**
For each finding:
- Title
- Severity (color-coded)
- Description
- Evidence
- Remediation steps
- References

**6. Recommendations**
- Prioritized action items
- Timeline suggestions
- Resource requirements

**7. Appendix**
- Full tool output
- Command logs
- Technical details

---

## Advanced Features

### Metasploit Integration

**Setup:**
1. Go to **Settings** → **Metasploit DB**
2. Enter connection details:
   - Host: `127.0.0.1`
   - Port: `55553`
   - Password: (your msfrpcd password)
3. Click **Test Connection**
4. Click **Save**

**Features:**
- Import Nmap results
- View hosts/services/vulns
- Execute post-exploitation modules
- Generate payloads
- Manage sessions

### RedTeam Integration

**Autonomous Engagements:**
- Create engagement
- Execute `execute_kali_full_engagement()`
- System automatically:
  - Runs recon playbook
  - Discovers services
  - Adds findings
  - Generates report

**API Example:**
```python
from agentic_ai.agents.cyber import RedTeamAgent

redteam = RedTeamAgent()
engagement = redteam.create_engagement(
    name="Auto Pentest",
    engagement_type="penetration_test",
    start_date=datetime.utcnow(),
    scope=["192.0.2.0/24"],
    objectives=["Full assessment"]
)

result = redteam.execute_kali_full_engagement(
    engagement_id=engagement.engagement_id,
    targets=["192.0.2.100", "192.0.2.101"]
)
```

### Custom Playbooks

**Create Custom Workflow:**

```python
from agentic_ai.agents.cyber.kali import KaliAgent

agent = KaliAgent()
agent.set_authorization(AuthorizationLevel.ADVANCED)

# Custom sequence
results = {}
results['nmap'] = agent.nmap_scan('192.0.2.100', ports='1-65535')
results['nikto'] = agent.nikto_scan('192.0.2.100', port=80)
results['gobuster'] = agent.gobuster_scan('http://192.0.2.100')
results['sqlmap'] = agent.sqlmap_scan('http://192.0.2.100/login.php')

# Generate custom report
report = agent.generate_playbook_report(
    playbook_name="custom_web_audit",
    results=results
)
```

---

## Best Practices

### Before Scanning

✅ **DO:**
- Get written authorization
- Define clear scope
- Configure IP whitelist
- Set appropriate authorization level
- Enable audit logging
- Test with dry-run mode
- Notify stakeholders

❌ **DON'T:**
- Scan without authorization
- Scan production without approval
- Scan third-party systems
- Use CRITICAL level unnecessarily
- Disable safety controls

### During Scanning

✅ **DO:**
- Monitor live execution
- Watch for errors
- Check findings as they appear
- Be ready to stop if issues arise
- Document observations

❌ **DON'T:**
- Leave unattended for long periods
- Ignore error messages
- Scan outside scope
- Run multiple heavy scans simultaneously

### After Scanning

✅ **DO:**
- Review all findings
- Validate critical findings manually
- Generate professional report
- Share with stakeholders
- Document lessons learned
- Archive engagement data

❌ **DON'T:**
- Skip validation
- Share raw output without context
- Leave engagements open
- Forget to backup findings

### Authorization Guidelines

| Scenario | Recommended Level |
|----------|-------------------|
| External recon | BASIC |
| Internal recon | BASIC |
| Web app audit | ADVANCED |
| Password audit | ADVANCED |
| Wireless audit | ADVANCED |
| Metasploit exploitation | CRITICAL |
| Post-exploitation | CRITICAL |
| Production testing | BASIC (dry-run) |

### Safety Checklist

Before executing any playbook:

- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] IP whitelist configured
- [ ] IP blacklist configured
- [ ] Authorization level set appropriately
- [ ] Audit logging enabled
- [ ] Stakeholders notified
- [ ] Backup procedures in place
- [ ] Emergency contacts available
- [ ] Dry-run test completed

---

## Getting Help

### Documentation
- [Installation Guide](INSTALL.md)
- [Quick Start](QUICKSTART.md)
- [API Reference](http://localhost:8001/docs)
- [Security Guide](SECURITY.md)

### Support Channels
- GitHub Issues
- Discord Community
- Email Support

### Logs & Debugging
- API logs: `/tmp/kali-dashboard/logs/`
- Audit logs: `/tmp/kali-dashboard/logs/audit_log.jsonl`
- Frontend console: Browser DevTools

---

*Last Updated: April 18, 2026*
*Version: 1.0.0*
