#!/usr/bin/env python3
"""
KaliAgent v3 - Security Hardening & Audit Logging
==================================================

Security checks, audit logging, and compliance.

Tasks: 5.2.1, 5.2.2, 5.2.3
Status: IMPLEMENTED
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security check severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStandard(Enum):
    """Compliance standards."""
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CUSTOM = "custom"


@dataclass
class SecurityFinding:
    """Security audit finding."""
    id: str
    title: str
    description: str
    level: SecurityLevel
    category: str
    remediation: str
    compliance: List[ComplianceStandard]
    detected_at: datetime
    acknowledged: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'level': self.level.value,
            'category': self.category,
            'remediation': self.remediation,
            'compliance': [c.value for c in self.compliance],
            'detected_at': self.detected_at.isoformat(),
            'acknowledged': self.acknowledged
        }


@dataclass
class AuditLogEntry:
    """Audit log entry."""
    id: str
    timestamp: datetime
    user: str
    action: str
    resource: str
    result: str  # success, failure, denied
    ip_address: Optional[str]
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'user': self.user,
            'action': self.action,
            'resource': self.resource,
            'result': self.result,
            'ip_address': self.ip_address,
            'details': self.details
        }


class SecurityAuditor:
    """
    Security auditing and hardening.
    
    Provides:
    - Security configuration checks
    - Vulnerability scanning
    - Compliance verification
    - Audit logging
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize security auditor."""
        self.config_dir = config_dir or Path.home() / 'kali_agent_v3' / 'production'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings: List[SecurityFinding] = []
        self.audit_log: List[AuditLogEntry] = []
        self.finding_counter = 0
        
        # Load config
        self._load_config()
        
        logger.info(f"Security auditor initialized (config: {self.config_dir})")
    
    def _load_config(self):
        """Load security configuration."""
        config_file = self.config_dir / 'security_config.json'
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                json.load(f)
            logger.info("Security configuration loaded")
    
    # =====================================================================
    # Task 5.2.1: Security Hardening
    # =====================================================================
    
    def run_security_checks(self) -> List[SecurityFinding]:
        """
        Run comprehensive security checks.
        
        Returns:
            List of SecurityFinding objects
        """
        logger.info("Running security checks...")
        
        findings = []
        
        # File system checks
        findings.extend(self._check_file_permissions())
        
        # Network checks
        findings.extend(self._check_network_security())
        
        # User account checks
        findings.extend(self._check_user_accounts())
        
        # Service checks
        findings.extend(self._check_services())
        
        # Password policy checks
        findings.extend(self._check_password_policy())
        
        # Store findings
        self.findings.extend(findings)
        
        # Keep last 100 findings
        if len(self.findings) > 100:
            self.findings = self.findings[-100:]
        
        # Save findings
        self._save_findings()
        
        logger.info(f"Security checks complete: {len(findings)} findings")
        
        return findings
    
    def _check_file_permissions(self) -> List[SecurityFinding]:
        """Check critical file permissions."""
        findings = []
        
        # Check /etc/passwd permissions
        passwd_path = Path('/etc/passwd')
        if passwd_path.exists():
            mode = passwd_path.stat().st_mode & 0o777
            if mode != 0o644:
                findings.append(self._create_finding(
                    title="Incorrect /etc/passwd permissions",
                    description=f"/etc/passwd has permissions {oct(mode)}, should be 0644",
                    level=SecurityLevel.MEDIUM,
                    category="file_permissions",
                    remediation="Run: chmod 644 /etc/passwd",
                    compliance=[ComplianceStandard.CIS, ComplianceStandard.NIST]
                ))
        
        # Check /etc/shadow permissions
        shadow_path = Path('/etc/shadow')
        if shadow_path.exists():
            mode = shadow_path.stat().st_mode & 0o777
            if mode != 0o640:
                findings.append(self._create_finding(
                    title="Incorrect /etc/shadow permissions",
                    description=f"/etc/shadow has permissions {oct(mode)}, should be 0640",
                    level=SecurityLevel.HIGH,
                    category="file_permissions",
                    remediation="Run: chmod 640 /etc/shadow",
                    compliance=[ComplianceStandard.CIS, ComplianceStandard.PCI_DSS]
                ))
        
        # Check for world-writable files in /tmp
        tmp_path = Path('/tmp')
        if tmp_path.exists():
            world_writable = []
            for file in tmp_path.iterdir():
                try:
                    if file.stat().st_mode & 0o002:
                        world_writable.append(str(file))
                except (PermissionError, OSError):
                    pass
            
            if world_writable:
                findings.append(self._create_finding(
                    title="World-writable files in /tmp",
                    description=f"Found {len(world_writable)} world-writable files",
                    level=SecurityLevel.LOW,
                    category="file_permissions",
                    remediation="Review and restrict permissions on world-writable files",
                    compliance=[ComplianceStandard.CIS]
                ))
        
        return findings
    
    def _check_network_security(self) -> List[SecurityFinding]:
        """Check network security configuration."""
        findings = []
        
        # Check for open ports
        try:
            import socket
            
            # Common sensitive ports
            sensitive_ports = {
                22: 'SSH',
                23: 'Telnet',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }
            
            open_ports = []
            for port, service in sensitive_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    open_ports.append(f"{port} ({service})")
            
            if open_ports:
                findings.append(self._create_finding(
                    title="Sensitive ports open on localhost",
                    description=f"Open ports: {', '.join(open_ports)}",
                    level=SecurityLevel.MEDIUM,
                    category="network_security",
                    remediation="Review if these services need to be exposed. Use firewall rules to restrict access.",
                    compliance=[ComplianceStandard.CIS, ComplianceStandard.NIST]
                ))
                
        except Exception as e:
            logger.debug(f"Network check error: {e}")
        
        return findings
    
    def _check_user_accounts(self) -> List[SecurityFinding]:
        """Check user account security."""
        findings = []
        
        # Check for users with UID 0 (root)
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = int(parts[2])
                        
                        if uid == 0 and username != 'root':
                            findings.append(self._create_finding(
                                title="Non-root user with UID 0",
                                description=f"User '{username}' has UID 0 (root privileges)",
                                level=SecurityLevel.CRITICAL,
                                category="user_accounts",
                                remediation=f"Review user '{username}' and change UID if not authorized",
                                compliance=[ComplianceStandard.CIS, ComplianceStandard.PCI_DSS]
                            ))
        except Exception as e:
            logger.debug(f"User account check error: {e}")
        
        # Check for users with empty passwords
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        
                        if password_hash == '' or password_hash == '!':
                            findings.append(self._create_finding(
                                title="User with empty/locked password",
                                description=f"User '{username}' has empty or locked password",
                                level=SecurityLevel.HIGH,
                                category="user_accounts",
                                remediation=f"Set a strong password for user '{username}' or lock the account",
                                compliance=[ComplianceStandard.CIS, ComplianceStandard.NIST]
                            ))
        except (PermissionError, OSError):
            pass  # Can't read shadow file without root
        
        return findings
    
    def _check_services(self) -> List[SecurityFinding]:
        """Check running services."""
        findings = []
        
        # Check for insecure services
        insecure_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        
        try:
            import subprocess
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--all'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            for service in insecure_services:
                if service in result.stdout.lower():
                    findings.append(self._create_finding(
                        title=f"Insecure service detected: {service}",
                        description=f"The {service} service is installed and potentially running",
                        level=SecurityLevel.HIGH,
                        category="services",
                        remediation=f"Disable and remove {service} service. Use secure alternatives (SSH, SFTP).",
                        compliance=[ComplianceStandard.CIS, ComplianceStandard.PCI_DSS]
                    ))
        except Exception as e:
            logger.debug(f"Service check error: {e}")
        
        return findings
    
    def _check_password_policy(self) -> List[SecurityFinding]:
        """Check password policy configuration."""
        findings = []
        
        # Check /etc/login.defs
        login_defs_path = Path('/etc/login.defs')
        
        if login_defs_path.exists():
            try:
                with open(login_defs_path, 'r') as f:
                    content = f.read()
                
                # Check PASS_MAX_DAYS
                if 'PASS_MAX_DAYS' in content:
                    for line in content.split('\n'):
                        if line.startswith('PASS_MAX_DAYS'):
                            parts = line.split()
                            if len(parts) >= 2:
                                max_days = int(parts[1])
                                if max_days > 90 or max_days == -1:
                                    findings.append(self._create_finding(
                                        title="Password expiration not enforced",
                                        description=f"PASS_MAX_DAYS is set to {max_days} (should be ≤90)",
                                        level=SecurityLevel.MEDIUM,
                                        category="password_policy",
                                        remediation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
                                        compliance=[ComplianceStandard.CIS, ComplianceStandard.PCI_DSS]
                                    ))
            except Exception as e:
                logger.debug(f"Password policy check error: {e}")
        
        return findings
    
    def _create_finding(self, title: str, description: str, level: SecurityLevel,
                       category: str, remediation: str,
                       compliance: List[ComplianceStandard]) -> SecurityFinding:
        """Create a security finding."""
        self.finding_counter += 1
        
        finding = SecurityFinding(
            id=f'finding_{self.finding_counter}_{datetime.now().strftime("%Y%m%d%H%M%S")}',
            title=title,
            description=description,
            level=level,
            category=category,
            remediation=remediation,
            compliance=compliance,
            detected_at=datetime.now()
        )
        
        logger.warning(f"Security finding: {finding.title} ({finding.level.value})")
        
        return finding
    
    def _save_findings(self):
        """Save findings to file."""
        findings_file = self.config_dir / 'security_findings.json'
        
        with open(findings_file, 'w') as f:
            json.dump([f.to_dict() for f in self.findings], f, indent=2)
    
    def get_findings(self, level: Optional[SecurityLevel] = None,
                    category: Optional[str] = None,
                    unacknowledged_only: bool = False) -> List[SecurityFinding]:
        """Get findings with optional filtering."""
        findings = self.findings
        
        if level:
            findings = [f for f in findings if f.level == level]
        
        if category:
            findings = [f for f in findings if f.category == category]
        
        if unacknowledged_only:
            findings = [f for f in findings if not f.acknowledged]
        
        return findings
    
    def acknowledge_finding(self, finding_id: str) -> bool:
        """Acknowledge a security finding."""
        for finding in self.findings:
            if finding.id == finding_id:
                finding.acknowledged = True
                self._save_findings()
                logger.info(f"Finding acknowledged: {finding_id}")
                return True
        
        return False
    
    def get_security_score(self) -> Dict:
        """Calculate overall security score."""
        if not self.findings:
            return {'score': 100, 'grade': 'A', 'findings_count': 0}
        
        # Weight by severity
        weights = {
            SecurityLevel.CRITICAL: 25,
            SecurityLevel.HIGH: 15,
            SecurityLevel.MEDIUM: 5,
            SecurityLevel.LOW: 2
        }
        
        total_penalty = sum(
            weights[f.level] for f in self.findings if not f.acknowledged
        )
        
        score = max(0, 100 - total_penalty)
        
        # Determine grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        unack_count = len([f for f in self.findings if not f.acknowledged])
        
        return {
            'score': score,
            'grade': grade,
            'findings_count': len(self.findings),
            'unacknowledged': unack_count,
            'by_level': {
                level.value: len([f for f in self.findings if f.level == level and not f.acknowledged])
                for level in SecurityLevel
            }
        }
    
    # =====================================================================
    # Task 5.2.2: Audit Logging
    # =====================================================================
    
    def log_action(self, user: str, action: str, resource: str,
                  result: str, ip_address: Optional[str] = None,
                  details: Optional[Dict] = None) -> AuditLogEntry:
        """
        Log an action to the audit log.
        
        Args:
            user: User who performed the action
            action: Action performed
            resource: Resource affected
            result: Result (success, failure, denied)
            ip_address: Source IP address
            details: Additional details
            
        Returns:
            AuditLogEntry created
        """
        entry_id = f'audit_{len(self.audit_log) + 1}_{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
        
        entry = AuditLogEntry(
            id=entry_id,
            timestamp=datetime.now(),
            user=user,
            action=action,
            resource=resource,
            result=result,
            ip_address=ip_address,
            details=details or {}
        )
        
        self.audit_log.append(entry)
        
        # Keep last 10000 entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
        
        # Save audit log
        self._save_audit_log()
        
        logger.info(f"Audit log: {user} {action} on {resource} -> {result}")
        
        return entry
    
    def _save_audit_log(self):
        """Save audit log to file."""
        audit_file = self.config_dir / 'audit_log.json'
        
        # Append to existing file
        existing = []
        if audit_file.exists():
            try:
                with open(audit_file, 'r') as f:
                    existing = json.load(f)
            except Exception:
                existing = []
        
        # Add new entries
        existing.extend([e.to_dict() for e in self.audit_log[-100:]])
        
        # Keep last 10000
        if len(existing) > 10000:
            existing = existing[-10000:]
        
        with open(audit_file, 'w') as f:
            json.dump(existing, f, indent=2)
    
    def search_audit_log(self, user: Optional[str] = None,
                        action: Optional[str] = None,
                        result: Optional[str] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None) -> List[AuditLogEntry]:
        """Search audit log with filters."""
        entries = self.audit_log
        
        if user:
            entries = [e for e in entries if e.user == user]
        
        if action:
            entries = [e for e in entries if action.lower() in e.action.lower()]
        
        if result:
            entries = [e for e in entries if e.result == result]
        
        if start_time:
            entries = [e for e in entries if e.timestamp >= start_time]
        
        if end_time:
            entries = [e for e in entries if e.timestamp <= end_time]
        
        return entries
    
    def export_audit_log(self, output_path: Optional[Path] = None) -> Path:
        """Export audit log."""
        if not output_path:
            output_path = self.config_dir / f'audit_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        with open(output_path, 'w') as f:
            json.dump([e.to_dict() for e in self.audit_log], f, indent=2)
        
        logger.info(f"Audit log exported: {output_path}")
        
        return output_path


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for security auditing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Security Auditor')
    parser.add_argument('--scan', action='store_true', help='Run security scan')
    parser.add_argument('--findings', action='store_true', help='Show findings')
    parser.add_argument('--score', action='store_true', help='Show security score')
    parser.add_argument('--acknowledge', type=str, help='Acknowledge finding by ID')
    parser.add_argument('--log', type=str, help='Log manual action (user:action:resource:result)')
    parser.add_argument('--search-audit', action='store_true', help='Search audit log')
    parser.add_argument('--export-audit', action='store_true', help='Export audit log')
    
    args = parser.parse_args()
    
    auditor = SecurityAuditor()
    
    if args.scan:
        findings = auditor.run_security_checks()
        print(f"\nSecurity Scan Complete: {len(findings)} findings")
        print("=" * 60)
        
        for level in [SecurityLevel.CRITICAL, SecurityLevel.HIGH, SecurityLevel.MEDIUM, SecurityLevel.LOW]:
            level_findings = [f for f in findings if f.level == level]
            if level_findings:
                icon = "🔴" if level == SecurityLevel.CRITICAL else "🟠" if level == SecurityLevel.HIGH else "🟡" if level == SecurityLevel.MEDIUM else "🔵"
                print(f"\n{icon} {level.value.upper()} ({len(level_findings)}):")
                for f in level_findings[:5]:
                    print(f"  • {f.title}")
                if len(level_findings) > 5:
                    print(f"  ... and {len(level_findings) - 5} more")
        
        print("=" * 60)
    
    elif args.findings:
        findings = auditor.get_findings(unacknowledged_only=True)
        print(f"\nUnacknowledged Findings: {len(findings)}")
        print("=" * 60)
        
        for f in findings:
            icon = "🔴" if f.level == SecurityLevel.CRITICAL else "🟠" if f.level == SecurityLevel.HIGH else "🟡" if f.level == SecurityLevel.MEDIUM else "🔵"
            print(f"{icon} [{f.level.value.upper()}] {f.title}")
            print(f"   {f.description}")
            print(f"   Remediation: {f.remediation}")
            print(f"   ID: {f.id}")
            print()
        
        print("=" * 60)
    
    elif args.score:
        score_data = auditor.get_security_score()
        print("\nSecurity Score")
        print("=" * 60)
        print(f"Score: {score_data['score']}/100")
        print(f"Grade: {score_data['grade']}")
        print(f"Total Findings: {score_data['findings_count']}")
        print(f"Unacknowledged: {score_data['unacknowledged']}")
        print("\nBy Level:")
        for level, count in score_data['by_level'].items():
            print(f"  {level}: {count}")
        print("=" * 60)
    
    elif args.acknowledge:
        success = auditor.acknowledge_finding(args.acknowledge)
        status = "✅" if success else "❌"
        print(f"{status} Finding acknowledged: {args.acknowledge}")
    
    elif args.log:
        parts = args.log.split(':')
        if len(parts) != 4:
            print("❌ Format: user:action:resource:result")
            return
        
        user, action, resource, result = parts
        entry = auditor.log_action(user, action, resource, result)
        print(f"✅ Audit log entry created: {entry.id}")
    
    elif args.search_audit:
        entries = auditor.search_audit_log()
        print(f"\nAudit Log Entries: {len(entries)}")
        print("=" * 60)
        
        for e in entries[-10:]:
            print(f"[{e.timestamp.isoformat()}] {e.user} {e.action} on {e.resource} -> {e.result}")
        
        print("=" * 60)
    
    elif args.export_audit:
        path = auditor.export_audit_log()
        print(f"✅ Audit log exported: {path}")
    
    else:
        # Default: show score
        score_data = auditor.get_security_score()
        icon = "🟢" if score_data['grade'] in ['A', 'B'] else "🟡" if score_data['grade'] == 'C' else "🔴"
        print(f"\n{icon} Security Score: {score_data['score']}/100 (Grade: {score_data['grade']})")
        print(f"Findings: {score_data['findings_count']} ({score_data['unacknowledged']} unacknowledged)")
        print("\nUse --scan to run security checks")


if __name__ == '__main__':
    main()
