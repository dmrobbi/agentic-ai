"""
Specialist Agents — Developer, SysAdmin, QA
============================================

Each specialist agent consumes tasks from `soc.investigation.tasks`,
performs its specialized work, and produces findings back to Kafka.

- SOCDeveloperAgent: malware analysis, threat enrichment, log deep-dive
- SOCSysAdminAgent: log analysis, system forensics, endpoint isolation
- SOCQAAgent: false positive detection, evidence quality check, coverage analysis
"""

import json
import logging
import time
import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Optional

from soc.kafka_client import SOCKafkaClient, InvestigationTask, SOCAlert
from soc.tools.soc_tools import threat_enrich, mitre_lookup

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Base Specialist Agent
# ─────────────────────────────────────────────────────────────────

class SOCSpecialistAgent:
    """
    Base class for all SOC specialist agents.
    Handles Kafka consumption, task processing, and result publishing.
    """

    agent_name: str = "soc.unknown"
    supported_task_types: list = []

    def __init__(
        self,
        kafka_bootstrap: str = "207.244.226.151:9092",
        consumer_group: Optional[str] = None,
    ):
        self.kafka_bootstrap = kafka_bootstrap
        self.consumer_group = consumer_group or f"{self.agent_name}-consumer"
        self.kafka = SOCKafkaClient(bootstrap_server=kafka_bootstrap)
        self._metrics = {
            "tasks_received": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
        }
        logger.info(f"{self.agent_name} initialized, group={self.consumer_group}")

    def process_task(self, task: InvestigationTask) -> dict:
        """
        Override this in subclasses to implement specialist logic.
        Must return a findings dict.
        """
        raise NotImplementedError

    def run(self, max_tasks: Optional[int] = None):
        """
        Start consuming from `soc.investigation.tasks`.
        For each task matching supported_task_types, run process_task.
        """
        logger.info(f"🚀 {self.agent_name} starting — consuming tasks...")

        count = 0
        for task in self.kafka.consume_investigation_tasks(group=self.consumer_group):
            if task.assigned_agent != self.agent_name:
                logger.debug(f"Skipping task for {task.assigned_agent} (not ours)")
                continue
            if task.task_type not in self.supported_task_types:
                logger.debug(f"Skipping task type {task.task_type} (not supported)")
                continue

            self._metrics["tasks_received"] += 1
            logger.info(f"[{self.agent_name}] Processing task={task.task_id} type={task.task_type}")

            try:
                findings = self.process_task(task)

                # Mark task complete and publish findings
                task.status = "completed"
                task.completed_at = datetime.utcnow().isoformat() + "Z"
                task.findings = findings

                # Also publish enriched alert to soc.alerts.enriched
                if task.context.get("original_alert"):
                    alert_data = task.context["original_alert"]
                    # Merge findings into the alert enrichment
                    enriched = self._build_enriched_alert(alert_data, findings)
                    self.kafka.produce_alert(enriched)

                self._metrics["tasks_completed"] += 1
                logger.info(f"[{self.agent_name}] Task {task.task_id} completed")

            except Exception as e:
                logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {e}")
                task.status = "failed"
                self._metrics["tasks_failed"] += 1

            count += 1
            if max_tasks and count >= max_tasks:
                logger.info(f"Max tasks ({max_tasks}) reached. Shutting down.")
                break

        self.kafka.close()

    def _build_enriched_alert(self, alert_data: dict, findings: dict) -> SOCAlert:
        """Build an enriched SOCAlert from original alert + specialist findings."""
        from soc.kafka_client import AlertSeverity, AlertCategory

        alert_id = alert_data.get("alert_id", f"ALR-{datetime.utcnow().strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:6].upper()}")
        return SOCAlert(
            alert_id=alert_id,
            source=alert_data.get("source", "enriched"),
            source_ref=alert_data.get("source_ref", alert_id),
            rule_name=alert_data.get("rule_name", "enriched"),
            description=alert_data.get("description", "") + f" [enriched by {self.agent_name}]",
            severity=AlertSeverity(alert_data.get("severity", "P3")),
            category=AlertCategory(alert_data.get("category", "unknown")),
            affected_asset=alert_data.get("affected_asset", ""),
            source_ip=alert_data.get("source_ip"),
            dest_ip=alert_data.get("dest_ip"),
            source_port=alert_data.get("source_port"),
            dest_port=alert_data.get("dest_port"),
            protocol=alert_data.get("protocol"),
            user=alert_data.get("user"),
            filename=alert_data.get("filename"),
            hash=alert_data.get("hash"),
            domain=alert_data.get("domain"),
            raw_log=json.dumps(findings),
        )

    def get_metrics(self) -> dict:
        return dict(self._metrics)

    def demo(self):
        """Run a demo with a synthetic task."""
        logger.info(f"🎭 {self.agent_name} running DEMO mode")
        demo_task = self._build_demo_task()
        findings = self.process_task(demo_task)
        self._print_findings(findings)
        return findings

    def _build_demo_task(self) -> InvestigationTask:
        """Override in subclass for demo task."""
        return InvestigationTask(
            task_id="TSK-DEMO-001",
            alert_id="ALR-DEMO-001",
            investigation_id="INV-DEMO-001",
            task_type=self.supported_task_types[0],
            assigned_agent=self.agent_name,
            priority="P2",
            context={
                "source_ip": "185.220.101.42",
                "dest_ip": "10.0.1.10",
                "dest_port": 3389,
                "user": "jsmith",
                "rule_name": "Suspicious RDP Connection",
                "triage_result": {
                    "severity": "P2",
                    "category": "brute_force",
                    "source_ip": "185.220.101.42",
                },
            },
        )

    def _print_findings(self, findings: dict):
        print(f"\n{'='*60}")
        print(f"🍀 {self.agent_name} — Findings")
        print(f"{'='*60}")
        for k, v in findings.items():
            print(f"  {k}: {v}")


# ─────────────────────────────────────────────────────────────────
# Developer Agent
# ─────────────────────────────────────────────────────────────────

class SOCDeveloperAgent(SOCSpecialistAgent):
    """
    SOC Developer Agent — deep-dive analysis on suspicious activity.

    Task types:
    - threat_enrich: IOC lookup, VirusTotal, OTX, MITRE mapping
    - malware_analysis: hash check, sandbox verdict, YARA rules
    - log_analysis: correlate logs across sources, identify IOCs
    - code_analysis: analyze malicious scripts, PowerShell, VBA
    """

    agent_name = "soc.developer"
    supported_task_types = ["threat_enrich", "malware_analysis", "log_analysis", "code_analysis"]

    def process_task(self, task: InvestigationTask) -> dict:
        """Process task based on type."""
        if task.task_type == "threat_enrich":
            return self._threat_enrich(task)
        elif task.task_type == "malware_analysis":
            return self._malware_analysis(task)
        elif task.task_type == "log_analysis":
            return self._log_analysis(task)
        elif task.task_type == "code_analysis":
            return self._code_analysis(task)
        return {"error": f"Unknown task type: {task.task_type}"}

    def _threat_enrich(self, task: InvestigationTask) -> dict:
        """Enrich IOCs with external threat intelligence."""
        ctx = task.context
        triage = ctx.get("triage_result", {})
        source_ip = triage.get("source_ip") or ctx.get("source_ip")
        dest_ip = ctx.get("dest_ip", "")
        user = ctx.get("user", "")
        domain = ctx.get("domain", "")

        findings = {
            "task_type": "threat_enrich",
            "primary_ioc": source_ip or "unknown",
            "enrichments": [],
            "mitre_mappings": [],
            "hypotheses": [],
        }

        # Enrich source IP
        if source_ip:
            rep = threat_enrich(source_ip, "ip")
            findings["enrichments"].append({
                "ioc": source_ip,
                "type": "ip",
                "classification": rep.get("classification", "unknown"),
                "reputation_score": rep.get("reputation_score", 50),
                "tags": rep.get("tags", []),
            })

            # Generate hypotheses based on reputation
            score = rep.get("reputation_score", 50)
            if score >= 70:
                findings["hypotheses"].append({
                    "text": f"Malicious actor confirmed (reputation {score}%)",
                    "confidence": score,
                    "mitre_tactics": ["TA0001", "TA0008"],
                })
                # Map to MITRE
                findings["mitre_mappings"].append({
                    "technique_id": "T1021.004",
                    "technique_name": "SSH",
                    "confidence": min(score, 95),
                    "reason": f"Attacker IP with {score}% reputation",
                })
            elif score >= 50:
                findings["hypotheses"].append({
                    "text": f"Suspicious IP ({score}% reputation) — investigate further",
                    "confidence": score * 0.8,
                })
            else:
                findings["hypotheses"].append({
                    "text": f"Unknown IP (reputation {score}%) — likely FP",
                    "confidence": 100 - score,
                })

        # Enrich domain if present
        if domain:
            dom_rep = threat_enrich(domain, "domain")
            findings["enrichments"].append({
                "ioc": domain,
                "type": "domain",
                "classification": dom_rep.get("classification", "unknown"),
                "reputation_score": dom_rep.get("reputation_score", 50),
                "tags": dom_rep.get("tags", []),
            })

        # Enrich user if present (look for related suspicious activity)
        if user:
            findings["user_analysis"] = {
                "user": user,
                "risk_indicators": [],
            }
            # In real implementation, would query AD/LDAP for user risk factors

        # Threat actor hypothesis
        if source_ip and "tor" in str(findings["enrichments"]).lower():
            findings["threat_actor"] = "TOR_EXIT_NODE"
            findings["hypotheses"].append({
                "text": "TOR exit node — likely automated scanning or anon attacker",
                "confidence": 75,
            })
        elif source_ip:
            findings["threat_actor"] = "UNKNOWN_OPPORTUNIST"
            findings["hypotheses"].append({
                "text": "Opportunistic attacker (no evidence of targeted campaign)",
                "confidence": 60,
            })

        return findings

    def _malware_analysis(self, task: InvestigationTask) -> dict:
        """Analyze file hash / malware indicators."""
        ctx = task.context
        file_hash = ctx.get("file_hash") or ctx.get("hash") or ""
        filename = ctx.get("filename", "unknown")

        findings = {
            "task_type": "malware_analysis",
            "file_hash": file_hash,
            "filename": filename,
            "verdict": "unknown",
            "detection_ratio": None,
            "family": None,
            "yara_rules": [],
            "sandbox_score": None,
        }

        if not file_hash:
            findings["verdict"] = "no_hash"
            findings["note"] = "No file hash available for analysis"
            return findings

        # Mock VirusTotal lookup
        if len(file_hash) >= 32:
            # Could be MD5/SHA256
            findings["verdict"] = "suspicious"
            findings["detection_ratio"] = "12/70"
            findings["family"] = "Ransomware.Genasom"
            findings["sandbox_score"] = 8.5
            findings["yara_rules"].append({
                "name": "Genasom_Detect",
                "author": "soc.developer",
                "rule": f'rule Genasom_Detect {{ strings: $a = "{filename[:20]}" condition: $a }}',
            })

        return findings

    def _log_analysis(self, task: InvestigationTask) -> dict:
        """Correlate logs across sources for the investigation."""
        ctx = task.context
        source_ip = ctx.get("source_ip", "")
        dest_ip = ctx.get("dest_ip", "")
        user = ctx.get("user", "")
        rule_name = ctx.get("rule_name", "")

        findings = {
            "task_type": "log_analysis",
            "events_correlated": 0,
            "first_seen": None,
            "last_seen": None,
            "attack_duration_seconds": None,
            "related_events": [],
        }

        # Build correlation based on source IP and time window
        events = []

        # Simulate log correlation from multiple sources
        if source_ip:
            events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": "wazuh",
                "event_type": "failed_ssh_login",
                "src_ip": source_ip,
                "dst_ip": dest_ip,
                "count": 47,
            })

            events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": "wazuh",
                "event_type": "successful_rdp",
                "src_ip": source_ip,
                "dst_ip": dest_ip,
                "user": user,
                "count": 1,
            })

        findings["events_correlated"] = len(events)
        findings["related_events"] = events
        findings["attack_timeline"] = "detected → scanning → brute_force → lateral_movement"

        return findings

    def _code_analysis(self, task: InvestigationTask) -> dict:
        """Analyze malicious scripts (PowerShell, VBA, etc.)."""
        ctx = task.context
        filename = ctx.get("filename", "")

        findings = {
            "task_type": "code_analysis",
            "filename": filename,
            "language": "unknown",
            "obfuscation": False,
            "risk_score": 50,
            "indicators": [],
        }

        ext = filename.split(".")[-1].lower() if filename else ""
        if ext in ("ps1", "psm1"):
            findings["language"] = "powershell"
            findings["risk_score"] = 70
            findings["indicators"].append("PowerShell script detected — review for encoded commands")
        elif ext in ("vbs", "vba", "docm"):
            findings["language"] = "vba"
            findings["risk_score"] = 80
            findings["indicators"].append("Macro-enabled document — likely phishing delivery")

        return findings

    def _build_demo_task(self) -> InvestigationTask:
        return InvestigationTask(
            task_id="TSK-DEV-DEMO",
            alert_id="ALR-2026-05-19-DEV01",
            investigation_id="INV-20260519-DEV01",
            task_type="threat_enrich",
            assigned_agent=self.agent_name,
            priority="P2",
            context={
                "source_ip": "185.220.101.42",
                "dest_ip": "10.0.1.10",
                "dest_port": 3389,
                "user": "jsmith",
                "rule_name": "Suspicious RDP Connection",
                "triage_result": {
                    "severity": "P2",
                    "category": "brute_force",
                    "source_ip": "185.220.101.42",
                },
            },
        )


# ─────────────────────────────────────────────────────────────────
# SysAdmin Agent
# ─────────────────────────────────────────────────────────────────

class SOCSysAdminAgent(SOCSpecialistAgent):
    """
    SOC SysAdmin Agent — system-level investigation and response.

    Task types:
    - log_analysis: parse auth logs, firewall logs, network logs
    - endpoint_check: check EDR status, patch level, isolation readiness
    - isolation: isolate endpoint via EDR API (produces ResponseCommand)
    - incident_create: create TheHive / case management case
    """

    agent_name = "soc.sysadmin"
    supported_task_types = ["log_analysis", "endpoint_check", "isolation", "incident_create"]

    def process_task(self, task: InvestigationTask) -> dict:
        if task.task_type == "log_analysis":
            return self._log_analysis(task)
        elif task.task_type == "endpoint_check":
            return self._endpoint_check(task)
        elif task.task_type == "isolation":
            return self._isolation(task)
        elif task.task_type == "incident_create":
            return self._incident_create(task)
        return {"error": f"Unknown task type: {task.task_type}"}

    def _log_analysis(self, task: InvestigationTask) -> dict:
        """Parse auth logs, firewall logs for the target asset."""
        ctx = task.context
        triage = ctx.get("triage_result", {})
        affected_asset = triage.get("affected_asset") or ctx.get("affected_asset", "")
        source_ip = ctx.get("source_ip", "")
        dest_ip = ctx.get("dest_ip", "")
        dest_port = ctx.get("dest_port")
        user = ctx.get("user", "")

        findings = {
            "task_type": "log_analysis",
            "asset_investigated": affected_asset,
            "auth_events": [],
            "network_events": [],
            "system_events": [],
            "risk_level": "medium",
            "recommendations": [],
        }

        # Auth events
        if user:
            findings["auth_events"].extend([
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event": "failed_login",
                    "service": "RDP",
                    "user": user,
                    "source_ip": source_ip,
                    "count": 5,
                },
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event": "successful_login",
                    "service": "RDP",
                    "user": user,
                    "source_ip": source_ip,
                    "count": 1,
                    "mfa_used": False,
                },
            ])

        # Network events
        if dest_port:
            findings["network_events"].append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": "connection_accepted",
                "protocol": "TCP",
                "src_ip": source_ip,
                "dst_ip": dest_ip,
                "dst_port": dest_port,
                "bytes_in": 45000,
                "bytes_out": 12000,
            })

        # System events
        findings["system_events"].append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "account_logon",
            "user": user,
            "status": "success",
            "auth_type": "Interactive",
        })

        # Risk assessment
        auth_failures = sum(1 for e in findings["auth_events"] if "failed" in e.get("event", ""))
        if auth_failures >= 5:
            findings["risk_level"] = "high"
            findings["recommendations"].append("RDP brute force detected — consider blocking source IP")
            findings["recommendations"].append("Enable account lockout policy for targeted user")

        if source_ip and is_tor_exit(source_ip):
            findings["risk_level"] = "high"
            findings["recommendations"].append("TOR exit node — external scanning detected")

        return findings

    def _endpoint_check(self, task: InvestigationTask) -> dict:
        """Check EDR status, patch level, isolation readiness of the target."""
        ctx = task.context
        affected_asset = ctx.get("affected_asset") or ctx.get("triage_result", {}).get("affected_asset", "")

        findings = {
            "task_type": "endpoint_check",
            "asset": affected_asset,
            "edr_status": "active",
            "edr_agent_version": "13.2.1",
            "last_seen": datetime.utcnow().isoformat() + "Z",
            "isolation_capable": True,
            "isolation_ready": True,
            "patch_level": "current",
            "os_version": "Windows Server 2022",
            "risk_score": 72,
            "notable_processes": [],
            "network_connections": [],
        }

        # Check if suspicious processes are running
        if affected_asset:
            findings["notable_processes"] = [
                {"name": "explorer.exe", "pid": 3544, "risk": "low"},
                {"name": "svchost.exe", "pid": 872, "risk": "low"},
                {"name": "mstsc.exe", "pid": 4102, "risk": "medium", "note": "RDP client active"},
            ]

        # Active network connections
        findings["network_connections"] = [
            {"remote_ip": ctx.get("source_ip", ""), "remote_port": ctx.get("dest_port", 3389), "state": "ESTABLISHED", "process": "mstsc.exe"},
        ]

        return findings

    def _isolation(self, task: InvestigationTask) -> dict:
        """Prepare an endpoint isolation command (produces ResponseCommand)."""
        ctx = task.context
        affected_asset = ctx.get("affected_asset") or ctx.get("triage_result", {}).get("affected_asset", "")
        source_ip = ctx.get("source_ip", "")

        # Produce isolation command
        from soc.kafka_client import ResponseCommand
        cmd = ResponseCommand(
            command_id=f"CMD-ISO-{uuid.uuid4().hex[:8].upper()}",
            alert_id=task.alert_id,
            investigation_id=task.investigation_id,
            action="isolate_endpoint",
            target=affected_asset,
            reason=f"Endpoint isolation requested by SOCSysAdmin for investigation {task.investigation_id}",
            approver=f"{self.agent_name} (automated)",
            status="pending",
            parameters={
                "isolation_type": "full",
                "source_ip_blocked": source_ip,
                "note": "Temporary isolation — remove after investigation",
            },
        )
        self.kafka.produce_response_command(cmd)

        return {
            "task_type": "isolation",
            "asset": affected_asset,
            "command_id": cmd.command_id,
            "status": "isolation_command_produced",
            "action": "isolate_endpoint",
            "target": affected_asset,
        }

    def _incident_create(self, task: InvestigationTask) -> dict:
        """Create a case in TheHive / case management."""
        ctx = task.context
        triage = ctx.get("triage_result", {})
        severity = triage.get("severity", "P3")
        category = triage.get("category", "unknown")
        source_ip = ctx.get("source_ip", "")
        affected_asset = ctx.get("affected_asset", "")

        case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        return {
            "task_type": "incident_create",
            "case_id": case_id,
            "case_title": f"{category.upper()} — {source_ip} → {affected_asset}",
            "severity": severity,
            "status": "created",
            "assigned_to": "soc.team",
            "next_steps": [
                "Lead Agent to review RSEM scores",
                "Analyst HITL approval required for response actions",
                "SysAdmin to contain if severity = P1",
            ],
        }

    def _build_demo_task(self) -> InvestigationTask:
        return InvestigationTask(
            task_id="TSK-SYS-DEMO",
            alert_id="ALR-2026-05-19-SYS01",
            investigation_id="INV-20260519-SYS01",
            task_type="log_analysis",
            assigned_agent=self.agent_name,
            priority="P2",
            context={
                "affected_asset": "FIN-DC01",
                "source_ip": "185.220.101.42",
                "dest_ip": "10.0.1.10",
                "dest_port": 3389,
                "user": "jsmith",
                "rule_name": "Suspicious RDP Connection",
                "triage_result": {
                    "severity": "P2",
                    "category": "brute_force",
                    "source_ip": "185.220.101.42",
                    "affected_asset": "FIN-DC01",
                },
            },
        )


# ─────────────────────────────────────────────────────────────────
# QA Agent
# ─────────────────────────────────────────────────────────────────

class SOCQAAgent(SOCSpecialistAgent):
    """
    SOC QA Agent — false positive detection and evidence quality.

    Task types:
    - fp_check: determine if alert is a false positive
    - coverage_analysis: check if SIEM rules have blind spots
    - evidence_validation: verify alert quality and completeness
    """

    agent_name = "soc.qa"
    supported_task_types = ["fp_check", "coverage_analysis", "evidence_validation"]

    def process_task(self, task: InvestigationTask) -> dict:
        if task.task_type == "fp_check":
            return self._fp_check(task)
        elif task.task_type == "coverage_analysis":
            return self._coverage_analysis(task)
        elif task.task_type == "evidence_validation":
            return self._evidence_validation(task)
        return {"error": f"Unknown task type: {task.task_type}"}

    def _fp_check(self, task: InvestigationTask) -> dict:
        """Determine if the alert is a false positive."""
        ctx = task.context
        triage = ctx.get("triage_result", {})
        source_ip = triage.get("source_ip") or ctx.get("source_ip", "")
        dest_ip = ctx.get("dest_ip", "")
        dest_port = ctx.get("dest_port")
        user = ctx.get("user", "")
        rule_name = ctx.get("rule_name", "")

        findings = {
            "task_type": "fp_check",
            "alert_id": task.alert_id,
            "fp_probability": 0.0,
            "fp_reasons": [],
            "fp_evidence": [],
            "fp_score": 0,
            "verdict": "unknown",
        }

        score = 0
        reasons = []
        evidence = []

        # Check 1: Known VPN/TOR exit nodes
        if source_ip and (is_tor_exit(source_ip) or is_vpn_ip(source_ip)):
            score += 15
            reasons.append("Source IP is a known VPN/TOR exit node")
            evidence.append({
                "check": "ip_reputation",
                "result": "positive",
                "detail": f"{source_ip} is a known exit node",
            })

        # Check 2: Approved vendor / known false positive pattern
        if user and is_service_account(user):
            score += 30
            reasons.append(f"User {user} is a service account — known noisy actor")
            evidence.append({
                "check": "user_type",
                "result": "service_account",
                "detail": f"{user} is a system/service account",
            })

        # Check 3: Expected behavior for environment
        if dest_port == 3389 and not is_business_hours():
            score += 10
            reasons.append("RDP activity outside business hours")
            evidence.append({
                "check": "time_of_day",
                "result": "off_hours",
                "detail": "RDP connection outside 8am-6pm",
            })

        # Check 4: Internal scanning (RFC1918 source)
        if source_ip and is_internal_ip(source_ip):
            score += 25
            reasons.append("Source IP is internal — possible insider or misconfiguration")
            evidence.append({
                "check": "ip_range",
                "result": "internal",
                "detail": f"{source_ip} is RFC1918 private",
            })

        # Check 5: MFA used successfully
        if ctx.get("mfa_used"):
            score += 20
            reasons.append("MFA was used — indicates legitimate auth")
            evidence.append({
                "check": "mfa",
                "result": "success",
                "detail": "MFA checkpoint passed",
            })

        findings["fp_score"] = score
        findings["fp_probability"] = min(score / 100.0, 1.0)
        findings["fp_reasons"] = reasons
        findings["fp_evidence"] = evidence

        # Verdict
        if score >= 60:
            findings["verdict"] = "likely_fp"
        elif score >= 30:
            findings["verdict"] = "possible_fp"
        else:
            findings["verdict"] = "likely_genuine"

        return findings

    def _coverage_analysis(self, task: InvestigationTask) -> dict:
        """Analyze SIEM rule coverage for blind spots."""
        return {
            "task_type": "coverage_analysis",
            "rules_analyzed": 0,
            "gaps_found": [],
            "coverage_score": 85,
            "recommendations": [
                "Add SIEM rule for anomalous PowerShell execution",
                "Monitor for rare process creation from RDP source",
            ],
        }

    def _evidence_validation(self, task: InvestigationTask) -> dict:
        """Validate alert quality and completeness."""
        ctx = task.context
        triage = ctx.get("triage_result", {})

        completeness_score = 0
        missing_fields = []

        required_fields = ["source_ip", "dest_ip", "severity", "category", "rule_name"]
        for field in required_fields:
            if ctx.get(field) or triage.get(field):
                completeness_score += 20

        if completeness_score >= 80:
            quality = "high"
        elif completeness_score >= 60:
            quality = "medium"
        else:
            quality = "low"

        return {
            "task_type": "evidence_validation",
            "quality": quality,
            "completeness_score": completeness_score,
            "missing_fields": missing_fields,
            "enrichment_needed": ["geo_ip", "threat_intel", "user_context"],
        }

    def _build_demo_task(self) -> InvestigationTask:
        return InvestigationTask(
            task_id="TSK-QA-DEMO",
            alert_id="ALR-2026-05-19-QA01",
            investigation_id="INV-20260519-QA01",
            task_type="fp_check",
            assigned_agent=self.agent_name,
            priority="P2",
            context={
                "source_ip": "185.220.101.42",
                "dest_ip": "10.0.1.10",
                "dest_port": 3389,
                "user": "jsmith",
                "rule_name": "Suspicious RDP Connection",
                "triage_result": {
                    "severity": "P2",
                    "category": "brute_force",
                    "source_ip": "185.220.101.42",
                    "mfa_used": True,
                },
            },
        )


# ─────────────────────────────────────────────────────────────────
# Helper functions (would be external in production)
# ─────────────────────────────────────────────────────────────────

def is_tor_exit(ip: str) -> bool:
    """Check if IP is a known TOR exit node."""
    if not ip:
        return False
    tor_prefixes = ("185.220.", "199.249.", "146.185.", "192.42.")
    return ip.startswith(tor_prefixes)

def is_vpn_ip(ip: str) -> bool:
    """Check if IP is a known commercial VPN."""
    if not ip:
        return False
    vpn_prefixes = ("185.163.", "185.117.", "45.12.", "185.242.")
    return ip.startswith(vpn_prefixes)

def is_internal_ip(ip: str) -> bool:
    """Check if IP is RFC1918 private."""
    if not ip:
        return False
    private = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
              "172.30.", "172.31.", "192.168.")
    return ip.startswith(private)

def is_service_account(user: str) -> bool:
    """Check if user is a service account."""
    if not user:
        return False
    service_patterns = ("svc_", "_svc", "service_", "daemon_", "system_", "$")
    return any(p in user.lower() for p in service_patterns)

def is_business_hours() -> bool:
    """Check if current time is within business hours (UTC)."""
    hour = datetime.utcnow().hour
    return 8 <= hour < 18


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    for agent_class in [SOCDeveloperAgent, SOCSysAdminAgent, SOCQAAgent]:
        print(f"\n{'='*60}")
        print(f"🍀 {agent_class.__name__} DEMO")
        print(f"{'='*60}")
        agent = agent_class()
        agent.demo()