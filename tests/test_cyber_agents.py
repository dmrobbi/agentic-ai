"""
Cyber Division Tests
====================

Unit tests for SecurityOperationsAgent, VulnerabilityManagementAgent, and RedTeamAgent.
"""

import pytest
from datetime import datetime, timedelta

from agentic_ai.agents.cyber.soc import (
    SecurityOperationsAgent,
    AlertSeverity,
    AlertStatus,
    IncidentSeverity,
    IncidentStatus,
    ThreatActor,
)
from agentic_ai.agents.integration import WebhookEvent
from agentic_ai.agents.cyber.vulnman import (
    VulnerabilityManagementAgent,
    Severity,
    VulnerabilityStatus,
    AssetType,
)
from agentic_ai.agents.cyber.redteam import (
    RedTeamAgent,
    EngagementType,
    EngagementStatus,
    TargetType,
    FindingSeverity,
)
from agentic_ai.infrastructure.utils import utcnow


class TestSecurityOperationsAgent:
    """Test SecurityOperationsAgent (SOC)."""
    
    @pytest.fixture
    def soc(self):
        """Create SOC agent instance."""
        return SecurityOperationsAgent()
    
    def test_create_alert(self, soc):
        """Test creating security alert."""
        alert = soc.create_alert(
            title="Brute Force Attack",
            description="Multiple failed logins from 192.0.2.100",
            severity=AlertSeverity.MEDIUM,
            source="SIEM",
            rule_name="brute_force",
            affected_asset="auth-server-01",
            source_ip="192.0.2.100",
            user="admin",
        )
        
        assert alert.alert_id.startswith("alert-")
        assert alert.status == AlertStatus.NEW
        assert alert.severity == AlertSeverity.MEDIUM
    
    def test_triage_alert(self, soc):
        """Test alert triage."""
        alert = soc.create_alert(
            "Test Alert",
            "Description",
            AlertSeverity.LOW,
            "SIEM",
            "test_rule",
            "server-01",
        )
        
        result = soc.triage_alert(
            alert.alert_id,
            AlertStatus.INVESTIGATING,
            assigned_to="analyst@soc.com",
            notes="Initial triage complete",
        )
        
        assert result is True
        assert alert.status == AlertStatus.INVESTIGATING
        assert alert.assigned_to == "analyst@soc.com"
    
    def test_create_incident(self, soc):
        """Test creating security incident."""
        incident = soc.create_incident(
            title="Ransomware Infection",
            severity=IncidentSeverity.CRITICAL,
            category="malware",
            threat_actor=ThreatActor.CYBERCRIMINAL,
            affected_systems=["workstation-42", "file-server-01"],
        )
        
        assert incident.incident_id.startswith("inc-")
        assert incident.status == IncidentStatus.DETECTED
        assert incident.severity == IncidentSeverity.CRITICAL
    
    def test_update_incident_status(self, soc):
        """Test incident status updates."""
        incident = soc.create_incident(
            "Test Incident",
            IncidentSeverity.HIGH,
            "unauthorized_access",
        )
        
        soc.update_incident_status(incident.incident_id, IncidentStatus.TRIAGE)
        soc.update_incident_status(incident.incident_id, IncidentStatus.INVESTIGATION)
        soc.update_incident_status(incident.incident_id, IncidentStatus.CONTAINMENT)
        
        assert incident.status == IncidentStatus.CONTAINMENT
        assert incident.contained_at is not None
    
    def test_add_ioc(self, soc):
        """Test adding IOC to incident."""
        incident = soc.create_incident(
            "Test",
            IncidentSeverity.HIGH,
            "malware",
        )
        
        result = soc.add_ioc(
            incident.incident_id,
            ioc_type="hash",
            ioc_value="abc123def456",
            context="Ransomware payload",
        )
        
        assert result is True
        assert 'hash' in incident.ioc
    
    def test_add_timeline_entry(self, soc):
        """Test adding timeline entries."""
        incident = soc.create_incident(
            "Test",
            IncidentSeverity.HIGH,
            "malware",
        )
        
        result = soc.add_timeline_entry(
            incident.incident_id,
            "detection",
            "EDR detected suspicious process",
            actor="EDR",
        )
        
        assert result is True
        assert len(incident.timeline) == 1
    
    def test_close_incident(self, soc):
        """Test closing incident with documentation."""
        incident = soc.create_incident(
            "Test",
            IncidentSeverity.MEDIUM,
            "phishing",
        )
        
        result = soc.close_incident(
            incident.incident_id,
            root_cause="User clicked phishing link",
            remediation_steps=["Reset password", "Scan workstation", "User training"],
            lessons_learned=["Need more phishing training"],
        )
        
        assert result is True
        assert incident.status == IncidentStatus.CLOSED
        assert incident.resolved_at is not None
    
    def test_add_threat_intel(self, soc):
        """Test adding threat intelligence."""
        intel = soc.add_threat_intel(
            indicator_type="ip",
            value="198.51.100.99",
            threat_type="c2_server",
            confidence="high",
            source="internal",
            tags=['ransomware', 'apt'],
        )
        
        assert intel.indicator_id.startswith("intel-")
        assert intel.confidence == "high"
    
    def test_search_threat_intel(self, soc):
        """Test searching threat intel."""
        soc.add_threat_intel("ip", "198.51.100.99", "c2", "high", "internal")
        soc.add_threat_intel("ip", "198.51.100.100", "c2", "medium", "internal")
        
        results = soc.search_threat_intel("198.51.100")
        
        assert len(results) == 2
    
    def test_create_hunt(self, soc):
        """Test creating threat hunt."""
        hunt = soc.create_hunt(
            name="Hunt for Lateral Movement",
            hypothesis="Attacker using compromised credentials",
            query="EventID=4624 | stats count by src_ip",
            data_source="windows_events",
            created_by="hunter@soc.com",
        )
        
        assert hunt.hunt_id.startswith("hunt-")
        assert hunt.status == "planned"
    
    def test_execute_hunt(self, soc):
        """Test executing threat hunt."""
        hunt = soc.create_hunt(
            "Test Hunt",
            "Hypothesis",
            "query",
            "events",
        )
        
        result = soc.execute_hunt(
            hunt.hunt_id,
            findings=[{'src_ip': '198.51.100.1', 'count': 500}],
        )
        
        assert result is True
        assert hunt.status == "completed"
        assert len(hunt.findings) == 1
    
    def test_get_soc_metrics(self, soc):
        """Test SOC metrics."""
        soc.create_alert("Alert 1", "Desc", AlertSeverity.HIGH, "SIEM", "rule", "asset")
        soc.create_alert("Alert 2", "Desc", AlertSeverity.MEDIUM, "SIEM", "rule", "asset")
        
        metrics = soc.get_soc_metrics(period_hours=24)
        
        assert 'alerts' in metrics
        assert 'incidents' in metrics
        assert 'response' in metrics
        assert 'mttr_hours' in metrics['response']
    
    def test_get_attack_mapping(self, soc):
        """Test MITRE ATT&CK mapping."""
        incident = soc.create_incident(
            "Test",
            IncidentSeverity.HIGH,
            "malware",
        )
        
        mapping = soc.get_attack_mapping(incident.incident_id)
        
        assert 'tactics' in mapping
        assert len(mapping['tactics']) > 0


class TestVulnerabilityManagementAgent:
    """Test VulnerabilityManagementAgent."""
    
    @pytest.fixture
    def vulnman(self):
        """Create VulnMan agent instance."""
        return VulnerabilityManagementAgent()
    
    def test_add_asset(self, vulnman):
        """Test adding asset."""
        asset = vulnman.add_asset(
            name="web-server-01",
            asset_type=AssetType.SERVER,
            ip_address="198.51.100.10",
            hostname="web01.example.com",
            os="Ubuntu 22.04",
            owner="ops@example.com",
            criticality="high",
        )
        
        assert asset.asset_id.startswith("asset-")
        assert asset.asset_type == AssetType.SERVER
        assert asset.criticality == "high"
    
    def test_get_assets_by_type(self, vulnman):
        """Test filtering assets by type."""
        vulnman.add_asset("Server", AssetType.SERVER, "198.51.100.10")
        vulnman.add_asset("Workstation", AssetType.WORKSTATION, "198.51.100.20")
        vulnman.add_asset("DB", AssetType.DATABASE, "198.51.100.50")
        
        servers = vulnman.get_assets(asset_type=AssetType.SERVER)
        
        assert len(servers) == 1
    
    def test_add_vulnerability(self, vulnman):
        """Test adding vulnerability."""
        asset = vulnman.add_asset("Server", AssetType.SERVER, "198.51.100.10")
        
        vuln = vulnman.add_vulnerability(
            cve_id="CVE-2024-1234",
            title="Remote Code Execution",
            description="Critical RCE in Apache",
            cvss_score=9.8,
            asset_id=asset.asset_id,
            scanner="nessus",
            remediation="Upgrade Apache",
            exploit_available=True,
        )
        
        assert vuln.vuln_id.startswith("vuln-")
        assert vuln.severity == Severity.CRITICAL
        assert vuln.exploit_available is True
    
    def test_update_vulnerability_status(self, vulnman):
        """Test updating vulnerability status."""
        asset = vulnman.add_asset("Server", AssetType.SERVER)
        vuln = vulnman.add_vulnerability(
            None,
            "Test Vuln",
            "Desc",
            7.5,
            asset.asset_id,
            "scanner",
        )
        
        result = vulnman.update_vulnerability_status(
            vuln.vuln_id,
            VulnerabilityStatus.IN_REMEDIATION,
            assigned_to="security@example.com",
            due_date=utcnow() + timedelta(days=14),
        )
        
        assert result is True
        assert vuln.status == VulnerabilityStatus.IN_REMEDIATION
    
    def test_get_overdue_vulnerabilities(self, vulnman):
        """Test getting overdue vulnerabilities."""
        asset = vulnman.add_asset("Server", AssetType.SERVER)
        vuln = vulnman.add_vulnerability(
            None,
            "Test",
            "Desc",
            5.0,
            asset.asset_id,
            "scanner",
        )
        
        vulnman.update_vulnerability_status(
            vuln.vuln_id,
            VulnerabilityStatus.IN_REMEDIATION,
            due_date=utcnow() - timedelta(days=1),
        )
        
        overdue = vulnman.get_overdue_vulnerabilities()
        
        assert len(overdue) == 1
    
    def test_create_scan(self, vulnman):
        """Test creating vulnerability scan."""
        scan = vulnman.create_scan(
            name="Weekly Scan",
            scanner="nessus",
            target_type="network",
            targets=["198.51.100.0/24"],
            created_by="security@example.com",
        )
        
        assert scan.scan_id.startswith("scan-")
        assert scan.status == "running"
    
    def test_complete_scan(self, vulnman):
        """Test completing scan."""
        scan = vulnman.create_scan(
            "Test Scan",
            "nessus",
            "network",
            ["198.51.100.0/24"],
        )
        
        result = vulnman.complete_scan(
            scan.scan_id,
            vulnerabilities_found=25,
            critical=2,
            high=5,
            medium=10,
            low=8,
        )
        
        assert result is True
        assert scan.status == "completed"
        assert scan.vulnerabilities_found == 25
    
    def test_add_patch(self, vulnman):
        """Test adding patch."""
        patch = vulnman.add_patch(
            name="Apache Security Update",
            vendor="Apache",
            product="HTTP Server",
            severity=Severity.CRITICAL,
            kb_article="KB123456",
        )
        
        assert patch.patch_id.startswith("patch-")
        assert patch.severity == Severity.CRITICAL
    
    def test_deploy_patch(self, vulnman):
        """Test patch deployment."""
        patch = vulnman.add_patch("Test Patch", "Vendor", "Product", Severity.HIGH)
        
        result = vulnman.deploy_patch(
            patch.patch_id,
            ["asset-1", "asset-2", "asset-3"],
        )
        
        assert result['success'] is True
        assert 'deployed' in result
        assert 'failed' in result
    
    def test_get_vuln_metrics(self, vulnman):
        """Test vulnerability metrics."""
        asset = vulnman.add_asset("Server", AssetType.SERVER)
        vulnman.add_vulnerability(None, "Vuln 1", "Desc", 9.0, asset.asset_id, "nessus")
        vulnman.add_vulnerability(None, "Vuln 2", "Desc", 7.0, asset.asset_id, "nessus")
        vulnman.add_vulnerability(None, "Vuln 3", "Desc", 4.0, asset.asset_id, "nessus")
        
        metrics = vulnman.get_vuln_metrics()
        
        assert metrics['total_vulnerabilities'] == 3
        assert 'risk_score' in metrics
        assert 'by_severity' in metrics
    
    def test_get_asset_risk_profile(self, vulnman):
        """Test asset risk profile."""
        asset = vulnman.add_asset(
            "Critical Server",
            AssetType.SERVER,
            criticality="critical",
        )
        
        vulnman.add_vulnerability(None, "Critical Vuln", "Desc", 9.5, asset.asset_id, "nessus", exploit_available=True)
        
        profile = vulnman.get_asset_risk_profile(asset.asset_id)
        
        assert profile['asset_id'] == asset.asset_id
        assert 'risk_score' in profile
        assert profile['total_vulnerabilities'] == 1
    
    def test_get_remediation_priority(self, vulnman):
        """Test remediation prioritization."""
        asset1 = vulnman.add_asset("Server 1", AssetType.SERVER, criticality="critical")
        asset2 = vulnman.add_asset("Server 2", AssetType.SERVER, criticality="low")
        
        vulnman.add_vulnerability(None, "Critical on Critical", "Desc", 9.8, asset1.asset_id, "nessus", exploit_available=True)
        vulnman.add_vulnerability(None, "High on Low", "Desc", 7.5, asset2.asset_id, "nessus")
        
        priority = vulnman.get_remediation_priority()
        
        assert len(priority) == 2
        assert priority[0]['priority_score'] > priority[1]['priority_score']


class TestRedTeamAgent:
    """Test RedTeamAgent."""
    
    @pytest.fixture
    def redteam(self):
        """Create RedTeam agent instance."""
        return RedTeamAgent()
    
    def test_create_engagement(self, redteam):
        """Test creating engagement."""
        engagement = redteam.create_engagement(
            name="Q2 Red Team Exercise",
            engagement_type=EngagementType.RED_TEAM,
            start_date=utcnow(),
            scope=["198.51.100.0/24", "example.com"],
            objectives=["Gain domain admin", "Access sensitive data"],
            rules_of_engagement=["No production impact"],
            team_members=["red1", "red2"],
        )
        
        assert engagement.engagement_id.startswith("eng-")
        assert engagement.engagement_type == EngagementType.RED_TEAM
        assert engagement.status == EngagementStatus.PLANNING
    
    def test_update_engagement_status(self, redteam):
        """Test engagement status updates."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.PENETRATION_TEST,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        redteam.update_engagement_status(engagement.engagement_id, EngagementStatus.RECON)
        redteam.update_engagement_status(engagement.engagement_id, EngagementStatus.EXPLOITATION)
        
        assert engagement.status == EngagementStatus.EXPLOITATION
    
    def test_add_target(self, redteam):
        """Test adding target."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        target = redteam.add_target(
            name="Web Server",
            target_type=TargetType.WEB_APP,
            ip_address="198.51.100.10",
            domain="web.example.com",
            os="Ubuntu 22.04",
            engagement_id=engagement.engagement_id,
        )
        
        assert target.target_id.startswith("tgt-")
        assert target.target_type == TargetType.WEB_APP
    
    def test_mark_target_compromised(self, redteam):
        """Test marking target compromised."""
        target = redteam.add_target(
            "Test Target",
            TargetType.NETWORK,
            ip_address="198.51.100.1",
        )
        
        result = redteam.mark_target_compromised(target.target_id)
        
        assert result is True
        assert target.accessed is True
        assert target.compromised_at is not None
    
    def test_add_service_to_target(self, redteam):
        """Test adding service to target."""
        target = redteam.add_target("Server", TargetType.SERVER, "198.51.100.1")
        
        result = redteam.add_service_to_target(
            target.target_id,
            "nginx",
            80,
            "1.18.0",
            vulnerable=True,
        )
        
        assert result is True
        assert len(target.services) == 1
    
    def test_add_finding(self, redteam):
        """Test adding finding."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        finding = redteam.add_finding(
            title="SQL Injection",
            description="Auth bypass via SQLi",
            severity=FindingSeverity.CRITICAL,
            engagement_id=engagement.engagement_id,
            category="initial_access",
            mitre_attack=['T1190', 'T1059'],
            remediation="Use parameterized queries",
        )
        
        assert finding.finding_id.startswith("find-")
        assert finding.severity == FindingSeverity.CRITICAL
        assert engagement.findings_count == 1
    
    def test_add_credential(self, redteam):
        """Test adding discovered credential."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        cred = redteam.add_credential(
            username="admin",
            password="Password123!",
            source="phishing",
            engagement_id=engagement.engagement_id,
            privileges=['local_admin'],
        )
        
        assert cred.credential_id.startswith("cred-")
        assert cred.username == "admin"
    
    def test_test_credential(self, redteam):
        """Test credential validation."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        cred = redteam.add_credential(
            "admin",
            "source",
            password="test",
            engagement_id=engagement.engagement_id,
        )
        
        result = redteam.test_credential(cred.credential_id, valid=True)
        
        assert result is True
        assert cred.valid is True
        assert cred.tested_at is not None
    
    def test_create_attack_path(self, redteam):
        """Test creating attack path."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        path = redteam.create_attack_path(
            name="Web to Domain Admin",
            engagement_id=engagement.engagement_id,
            start_point="External Web Server",
            end_point="Domain Admin",
            steps=[
                {'action': 'SQL Injection', 'time_minutes': 15},
                {'action': 'Credential Dump', 'time_minutes': 10},
                {'action': 'Lateral Movement', 'time_minutes': 30},
            ],
            mitre_attack=['T1190', 'T1003', 'T1021'],
        )
        
        assert path.path_id.startswith("path-")
        assert path.time_to_exploit == 55  # 15+10+30
        assert path.severity == FindingSeverity.CRITICAL
    
    def test_generate_engagement_report(self, redteam):
        """Test engagement report generation."""
        engagement = redteam.create_engagement(
            "Test Engagement",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        target = redteam.add_target(
            "Web Server",
            TargetType.WEB_APP,
            "198.51.100.10",
            engagement_id=engagement.engagement_id,
        )
        
        redteam.add_finding(
            "SQL Injection",
            "Desc",
            FindingSeverity.CRITICAL,
            engagement.engagement_id,
            target.target_id,
        )
        
        redteam.mark_target_compromised(target.target_id)
        
        report = redteam.generate_engagement_report(engagement.engagement_id)
        
        assert 'engagement' in report
        assert 'summary' in report
        assert 'mitre_coverage' in report
        assert 'recommendations' in report
        assert report['summary']['compromised_targets'] == 1
    
    def test_get_engagements_by_type(self, redteam):
        """Test filtering engagements by type."""
        redteam.create_engagement("Pen Test", EngagementType.PENETRATION_TEST, utcnow(), ["scope"], ["obj"])
        redteam.create_engagement("Red Team", EngagementType.RED_TEAM, utcnow(), ["scope"], ["obj"])
        redteam.create_engagement("Emulation", EngagementType.ADVERSARY_EMULATION, utcnow(), ["scope"], ["obj"])
        
        red_team = redteam.get_engagements(engagement_type=EngagementType.RED_TEAM)
        
        assert len(red_team) == 1
    
    def test_get_findings_by_severity(self, redteam):
        """Test filtering findings by severity."""
        engagement = redteam.create_engagement(
            "Test",
            EngagementType.RED_TEAM,
            utcnow(),
            ["scope"],
            ["obj"],
        )
        
        redteam.add_finding("Critical", "Desc", FindingSeverity.CRITICAL, engagement.engagement_id)
        redteam.add_finding("High", "Desc", FindingSeverity.HIGH, engagement.engagement_id)
        redteam.add_finding("Medium", "Desc", FindingSeverity.MEDIUM, engagement.engagement_id)
        
        critical = redteam.get_findings(severity=FindingSeverity.CRITICAL)
        
        assert len(critical) == 1


class TestCyberCapabilities:
    """Test capabilities export for cyber agents."""
    
    def test_soc_capabilities(self):
        """Test SOC capabilities."""
        from agentic_ai.agents.cyber.soc import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'soc'
        assert len(caps['capabilities']) >= 18
        assert 'create_alert' in caps['capabilities']
        assert 'create_incident' in caps['capabilities']
    
    def test_vulnman_capabilities(self):
        """Test VulnMan capabilities."""
        from agentic_ai.agents.cyber.vulnman import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'vulnerability_management'
        assert len(caps['capabilities']) >= 15
        assert 'add_asset' in caps['capabilities']
        assert 'add_vulnerability' in caps['capabilities']
    
    def test_redteam_capabilities(self):
        """Test RedTeam capabilities."""
        from agentic_ai.agents.cyber.redteam import get_capabilities
        caps = get_capabilities()
        
        assert caps['agent_type'] == 'redteam'
        assert len(caps['capabilities']) >= 17
        assert 'create_engagement' in caps['capabilities']
        assert 'add_finding' in caps['capabilities']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
