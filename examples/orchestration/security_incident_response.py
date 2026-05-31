"""
Security Incident Response - Multi-Agent Orchestration Example
===============================================================

Demonstrates coordinated response to a security incident across multiple agents:
- SOC Agent: Detects and triages security threats
- DevOps Agent: Isolates affected systems, deploys fixes
- Communications Agent: Sends notifications to stakeholders
- Legal Agent: Documents for compliance and regulatory requirements
- VendorRisk Agent: Checks if vendor-related
- CloudSecurity Agent: Reviews cloud security posture

This example shows how agents collaborate following incident response playbooks.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from agentic_ai.infrastructure.utils import utcnow

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agentic_ai.agents.cyber.soc import SOCAgent
from agentic_ai.agents.devops import DevOpsAgent
from agentic_ai.agents.communications import CommunicationsAgent
from agentic_ai.agents.legal import LegalAgent
from agentic_ai.agents.vendor_risk import VendorRiskAgent, VendorTier
from agentic_ai.agents.cloud_security import CloudSecurityAgent, CloudProvider, Severity


def format_timestamp(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def run_security_incident_response():
    """Execute security incident response workflow."""
    
    print("=" * 80)
    print("SECURITY INCIDENT RESPONSE - Multi-Agent Orchestration")
    print("=" * 80)
    print()
    
    # Initialize all agents
    soc = SOCAgent()
    devops = DevOpsAgent()
    comms = CommunicationsAgent()
    legal = LegalAgent()
    vendor_risk = VendorRiskAgent()
    cloud_sec = CloudSecurityAgent()
    
    # ========================================================================
    # PHASE 1: DETECTION & TRIAGE
    # ========================================================================
    print("\n📍 PHASE 1: DETECTION & TRIAGE")
    print("-" * 80)
    
    # SOC Agent detects potential security incident
    print("\n[SOC Agent] Detecting security incident...")
    
    incident = soc.report_security_incident(
        title="Suspicious API Access from Unusual Location",
        description="Multiple failed authentication attempts followed by successful login from IP 185.220.101.45 (Russia). User accessed sensitive customer data endpoint.",
        severity="high",
        incident_type="unauthorized_access",
        affected_systems=["api-gateway", "customer-database"],
        detected_by="siem_correlation",
        source_ip="185.220.101.45",
        target_user="admin@example.com",
    )
    
    print(f"  ✓ Incident created: {incident.incident_id}")
    print(f"  ✓ Severity: {incident.severity}")
    print(f"  ✓ Affected systems: {', '.join(incident.affected_systems)}")
    
    # Enrich incident with threat intelligence
    print("\n[SOC Agent] Enriching with threat intelligence...")
    
    threat_intel = soc.get_threat_intelligence(ioc_type="ip", ioc_value="185.220.101.45")
    print(f"  ✓ IP reputation: {threat_intel.get('reputation', 'unknown')}")
    print(f"  ✓ Associated campaigns: {threat_intel.get('campaigns', 0)}")
    
    # Check if related to known vulnerabilities
    vuln_check = soc.search_vulnerabilities(query="authentication bypass")
    if vuln_check:
        print(f"  ✓ Related vulnerabilities found: {len(vuln_check)}")
    
    # ========================================================================
    # PHASE 2: CONTAINMENT
    # ========================================================================
    print("\n\n🔒 PHASE 2: CONTAINMENT")
    print("-" * 80)
    
    # DevOps Agent isolates affected systems
    print("\n[DevOps Agent] Implementing containment measures...")
    
    # Create incident ticket in incident management system
    incident_ticket = devops.create_incident(
        title=f"SEC-INCIDENT: {incident.title}",
        description=incident.description,
        severity="P1",
        affected_services=["api-gateway", "customer-database"],
        detected_at=utcnow(),
    )
    print(f"  ✓ Incident ticket created: {incident_ticket.incident_id}")
    
    # Isolate affected instances
    print("\n[DevOps Agent] Isolating compromised instances...")
    
    # Simulate isolating EC2 instances
    isolation_result = devops.run_command(
        target="api-gateway-prod",
        command="aws ec2 modify-instance-attribute --instance-id i-1234567890 --no-network-interface-attach",
        description="Detach network interface from potentially compromised instance",
    )
    print(f"  ✓ Isolation command executed: {isolation_result.get('status', 'success')}")
    
    # Rotate credentials
    print("\n[DevOps Agent] Rotating compromised credentials...")
    
    credential_rotation = devops.run_command(
        target="secrets-manager",
        command="aws secretsmanager rotate-secret --secret-id admin-api-key",
        description="Rotate API keys for compromised admin account",
    )
    print(f"  ✓ Credential rotation initiated: {credential_rotation.get('status', 'success')}")
    
    # Block malicious IP at WAF
    print("\n[DevOps Agent] Blocking malicious IP at WAF...")
    
    waf_block = devops.run_command(
        target="waf",
        command="aws wafv2 create-ip-set --name block-malicious-ip --addresses 185.220.101.45/32",
        description="Add attacker IP to WAF block list",
    )
    print(f"  ✓ WAF rule created: {waf_block.get('status', 'success')}")
    
    # ========================================================================
    # PHASE 3: COMMUNICATION
    # ========================================================================
    print("\n\n📢 PHASE 3: COMMUNICATION")
    print("-" * 80)
    
    # Communications Agent sends notifications
    print("\n[Communications Agent] Sending stakeholder notifications...")
    
    # Internal security team notification
    security_alert = comms.send_email(
        to=["security-team@example.com", "ciso@example.com"],
        subject="🚨 SECURITY INCIDENT: Unauthorized Access Detected",
        body=f"""
SECURITY INCIDENT ALERT

Incident ID: {incident.incident_id}
Severity: {incident.severity.upper()}
Detected: {format_timestamp(incident.detected_at)}

SUMMARY:
{incident.description}

AFFECTED SYSTEMS:
{', '.join(incident.affected_systems)}

CONTAINMENT STATUS:
- Affected instances isolated ✓
- Credentials rotated ✓
- Malicious IP blocked at WAF ✓

NEXT STEPS:
- Forensic analysis in progress
- Legal review initiated
- Customer notification assessment underway

Respond to this email for updates.
        """,
        priority="high",
    )
    print(f"  ✓ Security team notified: {security_alert.get('message_id', 'sent')}")
    
    # Executive summary for leadership
    exec_summary = comms.send_email(
        to=["ceo@example.com", "cto@example.com"],
        subject="Security Incident - Executive Summary",
        body=f"""
EXECUTIVE SUMMARY - Security Incident

INCIDENT: Unauthorized API Access
SEVERITY: High
STATUS: Contained

WHAT HAPPENED:
An attacker gained unauthorized access to our API from an IP address in Russia. The attacker accessed customer data endpoints.

IMMEDIATE ACTIONS TAKEN:
✓ Compromised instances isolated
✓ Credentials rotated
✓ Attacker IP blocked
✓ Security team engaged

BUSINESS IMPACT:
- Potential customer data exposure (assessing scope)
- No service disruption
- No financial impact identified yet

NEXT UPDATE: 2 hours

Questions: security-team@example.com
        """,
        priority="high",
    )
    print(f"  ✓ Executive team notified: {exec_summary.get('message_id', 'sent')}")
    
    # Prepare customer communication template
    customer_template = comms.create_message_template(
        name="security_incident_customer_notification",
        template_type="email",
        subject="Important Security Notice",
        body="""
Dear Valued Customer,

We are writing to inform you of a security incident that may have affected your data.

WHAT HAPPENED:
On [DATE], we detected unauthorized access to our API systems. We immediately took steps to secure our systems and launched an investigation.

WHAT INFORMATION WAS INVOLVED:
Our investigation is ongoing, but we believe [SPECIFIC DATA TYPES] may have been accessed.

WHAT WE ARE DOING:
We have implemented additional security measures and are working with leading cybersecurity experts to enhance our systems.

WHAT YOU CAN DO:
[RECOMMENDATIONS]

We sincerely apologize for this incident and any concern it may cause.

Sincerely,
[COMPANY] Security Team
        """,
    )
    print(f"  ✓ Customer notification template prepared: {customer_template.get('template_id')}")
    
    # ========================================================================
    # PHASE 4: LEGAL & COMPLIANCE
    # ========================================================================
    print("\n\n⚖️ PHASE 4: LEGAL & COMPLIANCE")
    print("-" * 80)
    
    # Legal Agent documents incident for compliance
    print("\n[Legal Agent] Documenting incident for regulatory compliance...")
    
    # Create legal matter
    legal_matter = legal.create_legal_matter(
        title=f"Security Incident {incident.incident_id} - Regulatory Compliance",
        matter_type="data_breach",
        description=f"Unauthorized access incident requiring regulatory notification assessment",
        priority="urgent",
        related_matters=[],
    )
    print(f"  ✓ Legal matter created: {legal_matter.matter_id}")
    
    # Check notification requirements
    print("\n[Legal Agent] Assessing regulatory notification requirements...")
    
    # GDPR assessment (if EU customers affected)
    gdpr_check = legal.check_gdpr_compliance(
        processing_type="customer_data_access",
        data_categories=["personal_data", "contact_information"],
        breach_detected=True,
    )
    print(f"  ✓ GDPR assessment: {gdpr_check.get('notification_required', 'assessing')}")
    print(f"    - Notification deadline: {gdpr_check.get('notification_deadline', '72 hours')}")
    
    # CCPA assessment (if California residents affected)
    ccpa_check = legal.check_ccpa_compliance(
        consumer_data_accessed=True,
        data_sold=False,
    )
    print(f"  ✓ CCPA assessment: {ccpa_check.get('notification_required', 'assessing')}")
    
    # Create regulatory notification timeline
    print("\n[Legal Agent] Creating regulatory notification timeline...")
    
    timeline = legal.create_compliance_timeline(
        matter_id=legal_matter.matter_id,
        events=[
            {
                'event': 'Incident detected',
                'deadline': incident.detected_at,
                'status': 'completed',
            },
            {
                'event': 'Initial assessment complete',
                'deadline': incident.detected_at + timedelta(hours=4),
                'status': 'in_progress',
            },
            {
                'event': 'GDPR notification (if required)',
                'deadline': incident.detected_at + timedelta(hours=72),
                'status': 'pending',
            },
            {
                'event': 'Customer notification',
                'deadline': incident.detected_at + timedelta(days=7),
                'status': 'pending',
            },
        ],
    )
    print(f"  ✓ Compliance timeline created with {len(timeline.get('events', []))} events")
    
    # Preserve evidence for potential litigation
    print("\n[Legal Agent] Initiating legal hold...")
    
    legal_hold = legal.create_legal_hold(
        matter_id=legal_matter.matter_id,
        title=f"Security Incident {incident.incident_id} - Evidence Preservation",
        custodians=["admin@example.com", "security-team@example.com"],
        data_sources=["email", "slack", "aws-cloudtrail", "siem-logs"],
        description="Preserve all evidence related to security incident investigation",
    )
    print(f"  ✓ Legal hold created: {legal_hold.hold_id}")
    print(f"    - Custodians: {len(legal_hold.custodians)}")
    print(f"    - Data sources: {', '.join(legal_hold.data_sources)}")
    
    # ========================================================================
    # PHASE 5: VENDOR RISK ASSESSMENT
    # ========================================================================
    print("\n\n🏢 PHASE 5: VENDOR RISK ASSESSMENT")
    print("-" * 80)
    
    # Check if incident involves third-party vendor
    print("\n[VendorRisk Agent] Assessing vendor involvement...")
    
    # Add the API gateway vendor (hypothetical)
    api_vendor = vendor_risk.add_vendor(
        name="API Gateway Provider",
        legal_name="API Gateway Inc",
        tier=VendorTier.TIER_1,
        category="cloud",
        relationship_type="vendor",
        contract_start=utcnow() - timedelta(days=365),
        contract_value=250000.0,
        primary_contact="support@apigateway.com",
        security_contact="security@apigateway.com",
        risk_owner="cto@example.com",
    )
    print(f"  ✓ Vendor registered: {api_vendor.name}")
    
    # Create vendor-related incident
    vendor_incident = vendor_risk.create_alert(
        vendor_id=api_vendor.vendor_id,
        alert_type="security_incident",
        severity="high",
        title="Security Incident Involving API Gateway",
        description=f"Unauthorized access incident may involve API Gateway security controls. Incident ID: {incident.incident_id}",
        source="internal_detection",
    )
    print(f"  ✓ Vendor alert created: {vendor_incident.alert_id}")
    
    # Request vendor security assessment
    print("\n[VendorRisk Agent] Requesting vendor security assessment...")
    
    vendor_assessment = vendor_risk.create_assessment(
        vendor_id=api_vendor.vendor_id,
        assessment_type="event_driven",
        assessor="security-team@example.com",
    )
    print(f"  ✓ Vendor assessment initiated: {vendor_assessment.assessment_id}")
    
    # ========================================================================
    # PHASE 6: CLOUD SECURITY POSTURE REVIEW
    # ========================================================================
    print("\n\n☁️ PHASE 6: CLOUD SECURITY POSTURE REVIEW")
    print("-" * 80)
    
    # CloudSecurity Agent reviews security posture
    print("\n[CloudSecurity Agent] Reviewing cloud security posture...")
    
    # Add AWS account
    aws_account = cloud_sec.add_account(
        account_id="123456789012",
        provider=CloudProvider.AWS,
        name="Production AWS",
        environment="production",
        owner="cloud-security@example.com",
    )
    print(f"  ✓ AWS account registered: {aws_account.account_id}")
    
    # Check for security findings related to the incident
    print("\n[CloudSecurity Agent] Checking for related security findings...")
    
    # Create finding for weak authentication
    auth_finding = cloud_sec.create_finding(
        title="MFA Not Enforced for Admin Users",
        description="Admin account compromised in incident did not have MFA enabled",
        severity=Severity.HIGH,
        resource_id="iam-user-admin",
        account_id=aws_account.account_id,
        remediation="Enable MFA for all admin users immediately",
    )
    print(f"  ✓ Security finding created: {auth_finding.finding_id}")
    print(f"    - Severity: {auth_finding.severity.value}")
    print(f"    - Resource: {auth_finding.resource_id}")
    
    # Check S3 bucket policies (potential data exposure)
    s3_finding = cloud_sec.create_finding(
        title="S3 Bucket with Overly Permissive Policy",
        description="Customer data bucket allows access from any IP",
        severity=Severity.CRITICAL,
        resource_id="s3-customer-data-bucket",
        account_id=aws_account.account_id,
        remediation="Restrict bucket policy to specific VPC endpoints",
    )
    print(f"  ✓ S3 security finding created: {s3_finding.finding_id}")
    print(f"    - Severity: {s3_finding.severity.value}")
    
    # Get compliance score
    print("\n[CloudSecurity Agent] Calculating compliance score...")
    
    compliance_score = cloud_sec.get_compliance_score("cis_aws")
    print(f"  ✓ CIS AWS Compliance Score: {compliance_score.get('score', 0):.1f}%")
    print(f"    - Total controls: {compliance_score.get('total_controls', 0)}")
    print(f"    - Open findings: {compliance_score.get('open_findings', 0)}")
    
    # ========================================================================
    # PHASE 7: RESOLUTION & LESSONS LEARNED
    # ========================================================================
    print("\n\n✅ PHASE 7: RESOLUTION & LESSONS LEARNED")
    print("-" * 80)
    
    # SOC Agent updates incident status
    print("\n[SOC Agent] Updating incident status...")
    
    soc.update_incident_status(incident.incident_id, "contained")
    soc.update_incident_status(incident.incident_id, "resolved")
    
    # Add lessons learned
    soc.add_incident_note(
        incident.incident_id,
        note="Root cause: MFA not enforced for admin accounts",
        author="security-lead@example.com",
    )
    
    soc.add_incident_note(
        incident.incident_id,
        note="Gap: S3 bucket policies too permissive",
        author="cloud-security@example.com",
    )
    
    print("  ✓ Incident resolved")
    print("  ✓ Lessons learned documented")
    
    # DevOps Agent creates remediation tasks
    print("\n[DevOps Agent] Creating remediation tasks...")
    
    remediation_tasks = [
        devops.create_task(
            title="Enforce MFA for all admin users",
            description="Implement mandatory MFA for all IAM users with admin privileges",
            priority="critical",
            assignee="identity-team@example.com",
            due_date=utcnow() + timedelta(days=7),
        ),
        devops.create_task(
            title="Restrict S3 bucket policies",
            description="Update all S3 buckets to deny access from non-VPC endpoints",
            priority="critical",
            assignee="cloud-team@example.com",
            due_date=utcnow() + timedelta(days=3),
        ),
        devops.create_task(
            title="Implement anomaly detection",
            description="Deploy ML-based anomaly detection for API access patterns",
            priority="high",
            assignee="security-team@example.com",
            due_date=utcnow() + timedelta(days=30),
        ),
    ]
    print(f"  ✓ Created {len(remediation_tasks)} remediation tasks")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n\n" + "=" * 80)
    print("INCIDENT RESPONSE SUMMARY")
    print("=" * 80)
    
    print(f"""
INCIDENT: {incident.title}
INCIDENT ID: {incident.incident_id}
SEVERITY: {incident.severity.upper()}
DURATION: {format_timestamp(incident.detected_at)} - {format_timestamp(utcnow())}

AGENTS INVOLVED:
  ✓ SOC Agent - Detection, triage, threat intelligence
  ✓ DevOps Agent - Containment, isolation, remediation
  ✓ Communications Agent - Stakeholder notifications
  ✓ Legal Agent - Compliance assessment, legal hold
  ✓ VendorRisk Agent - Vendor involvement assessment
  ✓ CloudSecurity Agent - Security posture review

CONTAINMENT ACTIONS:
  ✓ Compromised instances isolated
  ✓ Credentials rotated
  ✓ Malicious IP blocked at WAF
  ✓ Legal hold initiated
  ✓ Regulatory assessment complete

REMEDIATION:
  ✓ {len(remediation_tasks)} tasks created
  ✓ MFA enforcement (7 days)
  ✓ S3 policy restrictions (3 days)
  ✓ Anomaly detection (30 days)

COMPLIANCE:
  ✓ GDPR assessment complete
  ✓ CCPA assessment complete
  ✓ Notification timeline established
""")
    
    # Get final state from all agents
    print("\nAGENT STATES:")
    print(f"  SOC Agent: {soc.get_state()}")
    print(f"  DevOps Agent: {devops.get_state()}")
    print(f"  Communications Agent: {comms.get_state()}")
    print(f"  Legal Agent: {legal.get_state()}")
    print(f"  VendorRisk Agent: {vendor_risk.get_state()}")
    print(f"  CloudSecurity Agent: {cloud_sec.get_state()}")
    
    print("\n" + "=" * 80)
    print("✅ SECURITY INCIDENT RESPONSE WORKFLOW COMPLETE")
    print("=" * 80)
    
    return {
        'incident': incident,
        'agents': {
            'soc': soc.get_state(),
            'devops': devops.get_state(),
            'comms': comms.get_state(),
            'legal': legal.get_state(),
            'vendor_risk': vendor_risk.get_state(),
            'cloud_sec': cloud_sec.get_state(),
        },
    }


if __name__ == "__main__":
    result = run_security_incident_response()
    print("\n📊 Workflow execution successful!")
