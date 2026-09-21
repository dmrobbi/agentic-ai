# SecurityAgent - Security Scanning & Incident Response

**Version:** 1.0.0  
**Status:** Production Ready ✅

---

## Overview

The **SecurityAgent** provides comprehensive security scanning, vulnerability assessment, incident response, secrets management, and policy enforcement for your applications and infrastructure.

### Key Capabilities

- 🔍 **Vulnerability Scanning** - Detect SQL injection, XSS, path traversal, hardcoded secrets, and more
- 🚨 **Incident Response** - Automated detection, response, and lifecycle management
- 🔐 **Secrets Management** - Track, rotate, and generate secure secrets
- 📋 **Policy Enforcement** - Password complexity, rate limiting, session management
- 📊 **Security Reporting** - Compliance reports, metrics dashboards
- 🔗 **Lead Agent Integration** - Seamless orchestration with multi-agent workflows

---

## Quick Start

```python
from agentic_ai.agents.security import SecurityAgent

# Initialize
agent = SecurityAgent()

# Scan code for vulnerabilities
findings = agent.scan_code(code_string, "file.py")

# Create incident
incident = agent.create_incident(
    title="SQL Injection Detected",
    description="Vulnerable code in /api/users",
    severity=SeverityLevel.CRITICAL,
    threat_type=ThreatType.SQL_INJECTION,
)

# Validate password
is_valid, violations = agent.validate_password("SecureP@ssw0rd123!")
```

---

## Threat Detection

### Supported Threat Types (24)

| Category | Threat Types |
|----------|-------------|
| **Injection** | SQL, NoSQL, LDAP, XSS, XXE, Command, Code |
| **Network** | CSRF, SSRF, Path Traversal, Redirect |
| **Cryptography** | Weak Crypto, Insecure Random, Hardcoded Secrets |
| **Authentication** | Brute Force, Session Hijack/Fixation, Privilege Escalation |
| **Data** | Insecure Deserialization, Sensitive Data Exposure |
| **Configuration** | Debug Mode, Security Misconfiguration |

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| **CRITICAL** | Immediate threat, active exploitation | < 1 hour |
| **HIGH** | Severe vulnerability, potential exploitation | < 24 hours |
| **MEDIUM** | Moderate risk, should be addressed | < 1 week |
| **LOW** | Minor issue, best practice violation | < 1 month |
| **INFO** | Informational, no immediate action required | As needed |

---

## Vulnerability Scanning

### Scan Code

```python
from agentic_ai.agents.security import SecurityAgent

agent = SecurityAgent()

# Scan code string
code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    db.execute(query)
"""

findings = agent.scan_code(code, "auth.py")

for finding in findings:
    print(f"Severity: {finding.severity.value}")
    print(f"Type: {finding.threat_type.value}")
    print(f"Title: {finding.title}")
    print(f"Location: {finding.location}:{finding.line_number}")
    print(f"CWE: {finding.cwe_id}")
    print(f"Fix: {finding.recommendation}")
```

### Scan File

```python
findings = agent.scan_file("/path/to/file.py")
```

### Scan Directory

```python
# Scan Python files recursively
findings = agent.scan_directory(
    "./src",
    extensions=['.py', '.js', '.ts']
)

print(f"Found {len(findings)} vulnerabilities")
```

### Detection Patterns

#### Secrets (20+ Providers)
- **Cloud:** AWS, Google Cloud
- **Development:** GitHub, GitLab
- **Communication:** Slack, Twilio, SendGrid
- **Payments:** Stripe, Square
- **Platforms:** Heroku
- **Generic:** API keys, passwords, private keys, JWT, encryption keys, database URLs

#### SQL Injection
- Classic: `SELECT...FROM...WHERE...OR`, `UNION SELECT`
- Comments: `--`, `/* */`, `#`
- String concatenation: `query = "SELECT" + user_input`
- Time-based: `SLEEP()`, `BENCHMARK()`, `WAITFOR`
- NoSQL: `$where`, `$ne`, `$gt`, `$lt`

#### XSS (Cross-Site Scripting)
- Script tags, event handlers
- Protocols: `javascript:`, `vbscript:`
- DOM manipulation: `innerHTML`, `document.write`
- Elements: `<iframe>`, `<object>`, `<svg>`

#### Path Traversal
- Basic: `../`, `..\`
- Encoded: `%2e%2e%2f`, `%252e%252e%252f`
- File operations with concatenation

#### Command Injection
- Operators: `;`, `&`, `|`, backticks
- Functions: `exec()`, `system()`, `shell_exec()`, `eval()`

#### SSRF
- Internal IPs: `127.0.0.1`, `10.x.x.x`, `192.168.x.x`
- Protocols: `file://`, `gopher://`, `dict://`

---

## Incident Response

### Create Incident

```python
from agentic_ai.agents.security import SeverityLevel, ThreatType

incident = agent.create_incident(
    title="Brute Force Attack Detected",
    description="Multiple failed login attempts from 192.0.2.100",
    severity=SeverityLevel.HIGH,
    threat_type=ThreatType.BRUTE_FORCE,
    source_ip="192.0.2.100",
    target_resource="/api/login",
    user_id="attacker",
)

print(f"Incident ID: {incident.incident_id}")
print(f"Status: {incident.status}")
print(f"Auto-Response Actions: {incident.response_actions}")
```

### Auto-Response

Critical and High severity incidents trigger automatic response:

| Threat Type | Auto-Response Actions |
|-------------|----------------------|
| **Brute Force** | Block IP, force password reset, enable lockout |
| **SQL Injection** | Block at WAF, review logs, patch endpoint |
| **Session Hijack** | Invalidate sessions, force re-auth |
| **Critical** | Alert team, enhanced logging, consider isolation |

### Update Incident Status

```python
# Update status
agent.update_incident_status(
    incident_id="incident-20260416-abc123",
    status="contained",  # detected, investigating, contained, resolved
    response_actions=["Blocked IP", "Notified team"],
)

# Resolve incident
agent.update_incident_status(
    incident_id="incident-20260416-abc123",
    status="resolved",
    resolved_by="security-team",
    response_actions=["Permanent block", "Policy updated"],
)
```

### Get Incidents

```python
# All incidents
incidents = agent.get_incidents()

# Filter by status
open_incidents = agent.get_incidents(status="investigating")

# Filter by severity
critical = agent.get_incidents(severity=SeverityLevel.CRITICAL)

# Filter by threat type
sqli = agent.get_incidents(threat_type=ThreatType.SQL_INJECTION)

# Limit results
recent = agent.get_incidents(limit=10)
```

---

## Secrets Management

### Register Secret for Rotation

```python
rotation = agent.register_secret(
    secret_name="STRIPE_API_KEY",
    secret_type="api_key",  # api_key, password, token, certificate
    rotation_days=90,
)

print(f"Next rotation: {rotation.next_rotation}")
```

### Rotate Secret

```python
# Generate new secret
new_secret = agent.generate_secure_secret("api_key", length=32)

# Perform rotation
success = agent.rotate_secret(
    rotation_id="rotation-20260416-abc123",
    new_secret_value=new_secret,
)
```

### Check Secrets Due for Rotation

```python
# Get secrets due in next 7 days
due = agent.get_secrets_due_for_rotation(days_ahead=7)

for rotation in due:
    print(f"{rotation.secret_name} - Overdue by {rotation.days_overdue} days")
```

### Generate Secure Secrets

```python
api_key = agent.generate_secure_secret("api_key", length=32)
password = agent.generate_secure_secret("password", length=16)
token = agent.generate_secure_secret("token", length=32)
```

---

## Policy Enforcement

### Password Validation

```python
is_valid, violations = agent.validate_password("SecureP@ssw0rd123!")

if not is_valid:
    for violation in violations:
        print(f"Policy violation: {violation}")
```

**Default Requirements:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Rate Limiting

```python
# Check if action is allowed
allowed, remaining = agent.check_rate_limit(
    identifier="user123",
    action="login",
    window_minutes=15,
)

if not allowed:
    print(f"Rate limit exceeded. Try again later.")
else:
    print(f"{remaining} attempts remaining")
```

**Default Limits:**
- 5 attempts per 15 minutes
- 1 hour lockout on exceed

### Update Policies

```python
# Enable/disable policy
agent.update_policy('password-complexity', enabled=True)

# Change enforcement level
agent.update_policy(
    'rate-limiting',
    enabled=True,
    enforcement_level='block',  # audit, warn, block
)
```

---

## Access Log Analysis

### Log Access Events

```python
agent.log_access(
    user_id="alice",
    resource="/api/users",
    action="delete",
    source_ip="198.51.100.1",
    success=True,
    metadata={'user_agent': 'Mozilla/5.0'},
)
```

### Detect Anomalies

```python
anomalies = agent.detect_anomalies(window_hours=24)

for anomaly in anomalies:
    print(f"Type: {anomaly['type']}")
    print(f"User: {anomaly['user_id']}")
    print(f"Severity: {anomaly['severity']}")
```

**Detected Anomalies:**
- High failure rate (10+ failed logins)
- Unusual time access (2-5 AM for sensitive actions)
- Suspicious patterns

---

## Security Reporting

### Generate Report

```python
report = agent.generate_security_report(period_days=30)

print(f"Period: {report['period_days']} days")
print(f"Generated: {report['generated_at']}")

# Findings
print(f"Total Findings: {report['findings']['total']}")
print(f"Open Findings: {report['findings']['open']}")
print(f"By Severity: {report['findings']['by_severity']}")

# Incidents
print(f"Total Incidents: {report['incidents']['total']}")
print(f"Critical: {report['incidents']['critical']}")
print(f"By Status: {report['incidents']['by_status']}")

# Secrets
print(f"Secrets Tracked: {report['secrets']['total_tracked']}")
print(f"Due for Rotation: {report['secrets']['due_for_rotation']}")

# Compliance
print(f"Policies Enabled: {report['policies']['enabled']}/{report['policies']['total']}")
```

### Get Agent State

```python
state = agent.get_state()

print(f"Agent ID: {state['agent_id']}")
print(f"Findings: {state['findings_count']}")
print(f"Incidents: {state['incidents_count']}")
print(f"Critical Open: {state['open_critical_incidents']}")
print(f"Secrets Tracked: {state['secrets_tracked']}")
```

---

## CI/CD Integration

### Security Gate

```python
def security_gate(code, filename):
    """CI/CD security gate."""
    agent = SecurityAgent()
    findings = agent.scan_code(code, filename)
    
    critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
    high = [f for f in findings if f.severity == SeverityLevel.HIGH]
    
    if critical or high:
        report = {
            'passed': False,
            'critical_count': len(critical),
            'high_count': len(high),
            'blocking_issues': [f.title for f in critical + high],
        }
        return report
    
    return {'passed': True, 'findings_count': len(findings)}

# Usage in CI/CD
result = security_gate(new_code, "feature.py")
if not result['passed']:
    print("Security gate failed!")
    for issue in result['blocking_issues']:
        print(f"  - {issue}")
    exit(1)
```

### GitLab CI Example

```yaml
security-scan:
  stage: test
  script:
    - python -c "
from agentic_ai.agents.security import SecurityAgent, SeverityLevel;
agent = SecurityAgent();
findings = agent.scan_directory('./src');
critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL];
exit(1) if critical else exit(0)
"
  allow_failure: false
```

---

## Lead Agent Integration

### Capabilities Export

```python
from agentic_ai.agents.security import get_capabilities

caps = get_capabilities()

# {
#   'agent_type': 'security',
#   'version': '1.0.0',
#   'capabilities': [
#     'scan_code', 'scan_file', 'scan_directory',
#     'create_incident', 'update_incident_status', 'get_incidents',
#     'register_secret', 'rotate_secret', 'generate_secure_secret',
#     'validate_password', 'check_rate_limit',
#     'log_access', 'detect_anomalies',
#     'generate_security_report',
#   ],
#   'threat_types': ['sql_injection', 'xss', ...],
#   'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
# }
```

### Task Delegation

```python
# Lead Agent delegates security scan
security_agent = SecurityAgent()
findings = security_agent.scan_code(code, "file.py")

# Escalate critical findings to Lead Agent
for finding in findings:
    if finding.severity == SeverityLevel.CRITICAL:
        lead_agent.notify_security_finding(finding)
```

---

## Best Practices

### 1. Regular Scanning

```python
# Schedule daily scans
agent.scan_directory("./src", extensions=['.py', '.js', '.ts'])
```

### 2. Automated Secret Rotation

```python
# Check weekly for secrets due for rotation
due = agent.get_secrets_due_for_rotation(days_ahead=14)
for rotation in due:
    # Rotate secret
    new_secret = agent.generate_secure_secret(rotation.secret_type)
    agent.rotate_secret(rotation.rotation_id, new_secret)
```

### 3. Incident Response Runbook

```python
# Critical incident workflow
incident = agent.create_incident(...)

# Auto-response handles immediate actions
# Security team reviews and updates status
agent.update_incident_status(incident.incident_id, "contained")
agent.update_incident_status(incident.incident_id, "resolved")
```

### 4. Compliance Reporting

```python
# Generate monthly compliance report
report = agent.generate_security_report(period_days=30)

# Send to security team
send_report(report)
```

---

## Examples

See `examples/security_scanning.py` for comprehensive examples:

```bash
cd ~/agentic-ai/agentic_ai
PYTHONPATH=. ./venv/bin/python examples/security_scanning.py
```

**Examples Include:**
1. Vulnerability scanning
2. Incident response workflow
3. Secrets management
4. Policy enforcement
5. Security reporting
6. Directory scanning

---

## Testing

```bash
# Run unit tests
pytest tests/test_security_agent.py -v

# Run integration tests
pytest tests/test_security_integration.py -v
```

**Test Coverage:**
- Vulnerability scanning (7 tests)
- Incident response (5 tests)
- Secrets management (4 tests)
- Policy enforcement (7 tests)
- Access log analysis (4 tests)
- Security reporting (2 tests)
- Integration workflows (13 tests)

---

## Troubleshooting

### False Positives

If you encounter false positives:
1. Review the finding details
2. Check code context
3. Update finding status to `false_positive`
4. Consider adding exclusion patterns

### Performance

For large codebases:
1. Scan in batches
2. Use parallel processing
3. Cache results between scans
4. Exclude vendor directories

---

## Support

- **Documentation:** `docs/SECURITY.md`
- **Examples:** `examples/security_scanning.py`
- **Tests:** `tests/test_security_agent.py`, `tests/test_security_integration.py`
- **Issues:** https://github.com/openclaw/openclaw/issues

---

**SecurityAgent v1.0.0 - Production Ready** 🔐
