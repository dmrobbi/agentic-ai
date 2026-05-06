#!/usr/bin/env python3
"""KaliAgent v3 - Security Audit Demo"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from production.security_audit import SecurityAuditor
from production.monitoring import SystemMonitor
from datetime import datetime

print("="*70)
print("  KaliAgent v3 - Security Audit & Monitoring")
print("  Production-Ready Security Posture")
print("="*70)
print()

# Security Audit
print("🛡️  Security Audit")
print()
auditor = SecurityAuditor(config_dir=Path('/tmp/audit_demo'))

print("   Running Security Checks...")
findings = auditor.run_security_checks()
print(f"   Findings: {len(findings)}")
print()

for i, finding in enumerate(findings[:3], 1):
    finding_dict = finding.to_dict() if hasattr(finding, 'to_dict') else finding
    severity = finding_dict.get('severity', 'INFO')
    icon = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🔵'
    print(f"   {icon} Finding {i}: {finding_dict.get('category', 'Unknown')}")
    print(f"      Issue: {str(finding_dict.get('issue', 'N/A'))[:60]}")
    print(f"      Recommendation: {str(finding_dict.get('recommendation', 'N/A'))[:50]}")
    print()

score_data = auditor.get_security_score()
print("   Security Score:")
print(f"      Score: {score_data['score']}/100")
print(f"      Grade: {score_data['grade']}")
print()

# System Monitoring
print("📊 System Monitoring")
print()
monitor = SystemMonitor(config_dir=Path('/tmp/monitor_demo'))

metrics = monitor.check_resources()
health = monitor.get_health_status()

print(f"   System Health: {health.status.upper()}")
print(f"      CPU Usage:    {health.cpu_usage:.1f}%")
print(f"      Memory Usage: {health.memory_usage:.1f}%")
print(f"      Disk Usage:   {health.disk_usage:.1f}%")
print()

alerts = monitor.get_alerts()
print(f"   Active Alerts: {len(alerts)}")
if alerts:
    for alert in alerts[:2]:
        print(f"      • {alert.get('message', 'Unknown')}")
print()

# Audit Logging
print("📝 Audit Logging")
auditor.log_action('admin', 'security_scan', 'system', 'success')
auditor.log_action('admin', 'view_findings', 'dashboard', 'success')
log_entries = auditor.search_audit_log(user='admin')
print(f"   Logged Actions: {len(log_entries)}")
print(f"   Export: audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
print()

print("="*70)
print(f"  Demo completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
