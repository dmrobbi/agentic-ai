"""
NCE — Narrative Counterfactual Engine
=======================================

SOCConversation's hypothesis generation engine.

NCE takes enriched alert data (triage + specialist findings) and generates
2-4 competing narratives explaining what happened / could happen.
Each hypothesis includes:
  - MITRE ATT&CK tactic + technique mapping
  - Evidence supporting the hypothesis
  - Counter-evidence / weaknesses
  - Confidence score (0-100%)
  - Estimated blast radius (if attack is real)
  - Recommended countermeasures

The engine works WITHOUT an LLM — it's a rule-based structured inference
engine that uses MITRE ATT&CK, threat intel patterns, and attack lifecycles
to generate high-quality hypotheses. In production, an LLM can be layered
on top for natural language hypothesis refinement.

Usage:
    nce = NCE()
    hypotheses = nce.generate(alert_context)
    for h in hypotheses:
        print(f"[{h.confidence:.0f}%] {h.narrative}")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# MITRE ATT&CK Reference (comprehensive)
# ─────────────────────────────────────────────────────────────────

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Defense Evasion",
    "TA0005": "Credential Access",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

MITRE_TECHNIQUES = {
    # Initial Access
    "T1566": {"name": "Phishing", "tactics": ["TA0001"], "prerequisites": [], "indicators": ["suspicious_email", "attachment"]},
    "T1566.001": {"name": "Spearphishing Attachment", "tactics": ["TA0001"], "prerequisites": [], "indicators": ["email_attachment"]},
    "T1133": {"name": "External Remote Services", "tactics": ["TA0001", "TA0008"], "prerequisites": [], "indicators": ["vpn", "rdp", "ssh"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["TA0001"], "prerequisites": ["web_service"], "indicators": ["web_exploit"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["TA0001", "TA0003", "TA0004", "TA0008"], "prerequisites": [], "indicators": ["legitimate_creds"]},
    "T1078.004": {"name": "Valid Accounts: Local Accounts", "tactics": ["TA0003", "TA0008"], "prerequisites": ["local_acct"], "indicators": ["local_admin"]},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"], "prerequisites": [], "indicators": ["powershell", "cmd", "bash"]},
    "T1059.001": {"name": "PowerShell", "tactics": ["TA0002"], "prerequisites": [], "indicators": ["powershell"]},
    "T1059.003": {"name": "Windows Command Shell", "tactics": ["TA0002"], "prerequisites": [], "indicators": ["cmd_exe"]},
    "T1053": {"name": "Scheduled Task/Job", "tactics": ["TA0002", "TA0003"], "prerequisites": [], "indicators": ["scheduled_task", "cron"]},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactics": ["TA0008"], "prerequisites": [], "indicators": ["rdp", "ssh", "winrm", "psexec"]},
    "T1021.003": {"name": "Remote Desktop Protocol", "tactics": ["TA0008"], "prerequisites": ["rdp_enabled"], "indicators": ["rdp", "mstsc"]},
    "T1021.004": {"name": "SSH", "tactics": ["TA0008"], "prerequisites": ["ssh_enabled"], "indicators": ["ssh"]},
    "T1021.006": {"name": "Windows Remote Management", "tactics": ["TA0008"], "prerequisites": ["winrm"], "indicators": ["winrm", "kerberos"]},
    "T1021.001": {"name": "Remote Services: SMB/Admin", "tactics": ["TA0008"], "prerequisites": ["smb"], "indicators": ["smb", "psexec"]},
    "T1210": {"name": "Exploitation of Remote Services", "tactics": ["TA0008"], "prerequisites": ["vulnerability"], "indicators": ["exploit", "ms17_010"]},
    # Credential Access
    "T1110": {"name": "Brute Force", "tactics": ["TA0006"], "prerequisites": [], "indicators": ["failed_login", "password_spray"]},
    "T1110.003": {"name": "Brute Force: SMB", "tactics": ["TA0006"], "prerequisites": ["smb"], "indicators": ["smb_brute"]},
    "T1110.004": {"name": "Brute Force: RDP", "tactics": ["TA0006"], "prerequisites": ["rdp"], "indicators": ["rdp_brute"]},
    "T1550": {"name": "Use Alternate Authentication Material", "tactics": ["TA0005", "TA0008"], "prerequisites": [], "indicators": ["pass_the_hash", "ticket"]},
    "T1003": {"name": "OS Credential Dumping", "tactics": ["TA0006"], "prerequisites": [], "indicators": ["lsass", "sam"]},
    "T1003.001": {"name": "LSASS", "tactics": ["TA0006"], "prerequisites": ["local_admin"], "indicators": ["lsass"]},
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactics": ["TA0007"], "prerequisites": [], "indicators": ["systeminfo", "hostname"]},
    "T1083": {"name": "File and Directory Discovery", "tactics": ["TA0007"], "prerequisites": [], "indicators": ["dir", "search"]},
    "T1018": {"name": "Remote System Discovery", "tactics": ["TA0007"], "prerequisites": [], "indicators": ["scan", "net"]},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactics": ["TA0011"], "prerequisites": [], "indicators": ["http", "https", "dns"]},
    "T1573": {"name": "Encrypted Channel", "tactics": ["TA0011"], "prerequisites": [], "indicators": ["tls", "ssl"]},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactics": ["TA0040"], "prerequisites": [], "indicators": ["ransomware", "encryption"]},
    "T1489": {"name": "Service Stop", "tactics": ["TA0040"], "prerequisites": [], "indicators": ["service_stop", "shutdown"]},
    "T1484": {"name": "Defacement", "tactics": ["TA0040"], "prerequisites": [], "indicators": ["web_deface"]},
}

# ─────────────────────────────────────────────────────────────────
# Threat Pattern → Hypothesis Template library
# ─────────────────────────────────────────────────────────────────

ATTACK_PATTERNS = {
    "brute_force": {
        "hypotheses": [
            {
                "id": "apt_brute",
                "label": "Targeted credential stuffing attack",
                "tactic": "TA0006",
                "techniques": ["T1110.004", "T1021.003"],
                "indicators": ["repeated_failed_logins", "tor_ip", "non_mfa_login"],
                "confidence_boost": 30,
                "narrative": "Attacker used leaked credential dump or password spray to gain initial access via RDP from anonymization infrastructure (TOR exit node). MFA was not enforced, enabling successful login.",
                "severity_boost": "high",
            },
            {
                "id": "insider_brute",
                "label": "Insider performing unauthorized access",
                "tactic": "TA0007",
                "techniques": ["T1082", "T1018"],
                "indicators": ["internal_ip", "after_hours", "privileged_user"],
                "confidence_boost": 20,
                "narrative": "Privileged user accessed sensitive systems outside normal working hours. Could indicate compromised service account or intentional data access.",
                "severity_boost": "medium",
            },
            {
                "id": "fp_brute",
                "label": "False positive — authorized maintenance",
                "tactic": None,
                "techniques": [],
                "indicators": ["service_account", "known_good_ip", "mfa_used"],
                "confidence_boost": 0,
                "narrative": "Service account performing routine RDP access. Failed logins are benign (password rotation) and successful login was preceded by MFA check.",
                "severity_boost": "low",
            },
        ],
    },
    "lateral_movement": {
        "hypotheses": [
            {
                "id": "apt_lm",
                "label": "Active intrusion — lateral movement in progress",
                "tactic": "TA0008",
                "techniques": ["T1021.003", "T1021.004"],
                "indicators": ["tor_ip", "internal_host", "new_session"],
                "confidence_boost": 35,
                "narrative": "Attacker established RDP session from anonymized infrastructure to internal server. Session shows data access patterns consistent with reconnaissance or credential harvesting.",
                "severity_boost": "critical",
            },
            {
                "id": "supply_chain_lm",
                "label": "Compromised vendor performing authorized access",
                "tactic": "TA0001",
                "techniques": ["T1078", "T1133"],
                "indicators": ["vendor_ip", "known_schedule", "service_account"],
                "confidence_boost": 15,
                "narrative": "Third-party vendor accessing network via permanent VPN for legitimate maintenance. Access follows known schedule and uses approved service account.",
                "severity_boost": "low",
            },
        ],
    },
    "malware": {
        "hypotheses": [
            {
                "id": "ransomware",
                "label": "Ransomware pre-attack reconnaissance",
                "tactic": "TA0040",
                "techniques": ["T1082", "T1083", "T1486"],
                "indicators": ["malware_signature", "file_encryption", "service_creation"],
                "confidence_boost": 40,
                "narrative": "Malware executing on endpoint performing system inventory (files, network config) in preparation for data encryption. Detected at pre-ransomware stage.",
                "severity_boost": "critical",
            },
            {
                "id": "trojan",
                "label": "Trojan downloader — stage 1 compromise",
                "tactic": "TA0002",
                "techniques": ["T1059.001", "T1105"],
                "indicators": ["suspicious_exe", "network_beacon", "script_dropper"],
                "confidence_boost": 30,
                "narrative": "User executed malicious attachment (Excel/Word with macro or OLE) which downloaded secondary payload. Initial RAT beacon detected to external C2.",
                "severity_boost": "high",
            },
        ],
    },
    "phishing": {
        "hypotheses": [
            {
                "id": "spear_phish",
                "label": "Spearphishing — credential harvesting",
                "tactic": "TA0001",
                "techniques": ["T1566.001", "T1078"],
                "indicators": ["phishing_email", "fake_login_page", "same_domain"],
                "confidence_boost": 35,
                "narrative": "Targeted email bypassed filtering and user clicked fake O365 login page. Credentials submitted to attacker infrastructure.",
                "severity_boost": "high",
            },
            {
                "id": "mal_doc",
                "label": "Malicious document — macro execution",
                "tactic": "TA0002",
                "techniques": ["T1059.001", "T1059.003"],
                "indicators": ["docm_file", "macro_enabled", "powershell_download"],
                "confidence_boost": 30,
                "narrative": "User opened macro-enabled document from phishing email. Macro executed PowerShell to download and run secondary payload.",
                "severity_boost": "high",
            },
        ],
    },
    "data_breach": {
        "hypotheses": [
            {
                "id": "data_exfil",
                "label": "Active data exfiltration",
                "tactic": "TA0010",
                "techniques": ["T1041", "T1567"],
                "indicators": ["large_upload", "unusual_dest", "encrypted_transfer"],
                "confidence_boost": 40,
                "narrative": "Attacker collected and exfiltrated sensitive data via encrypted channel to external cloud storage. Exfiltration staged over several hours to avoid detection.",
                "severity_boost": "critical",
            },
            {
                "id": "insider_data",
                "label": "Insider data theft",
                "tactic": "TA0010",
                "techniques": ["T1074", "T1537"],
                "indicators": ["bulk_download", "personal_drive", "after_hours"],
                "confidence_boost": 20,
                "narrative": "Privileged user accessed large volumes of records outside normal patterns. Data staged to personal cloud storage.",
                "severity_boost": "high",
            },
        ],
    },
    "unknown": {
        "hypotheses": [
            {
                "id": "targeted_attack",
                "label": "Targeted attack — investigate further",
                "tactic": "TA0001",
                "techniques": [],
                "indicators": ["anomalous_activity"],
                "confidence_boost": 25,
                "narrative": "Anomalous activity detected that doesn't match known patterns. Requires deeper investigation to determine intent and scope.",
                "severity_boost": "medium",
            },
            {
                "id": "fp_unknown",
                "label": "Likely false positive — benign anomaly",
                "tactic": None,
                "techniques": [],
                "indicators": ["single_event", "no_follow_up"],
                "confidence_boost": 0,
                "narrative": "Single anomalous event with no supporting evidence. Likely normal behavior misclassified by detection rule.",
                "severity_boost": "low",
            },
        ],
    },
}

# Threat actor reputation lookup
THREAT_ACTORS = {
    "TOR_EXIT_NODE": {
        "name": "TOR Exit Node",
        "risk_level": "high",
        "description": "Traffic from TOR exit nodes is anonymized — common for scanners, attackers, privacy-conscious users",
        "false_positive_rate": 0.15,
    },
    "VPN_EXIT_NODE": {
        "name": "Commercial VPN",
        "risk_level": "medium",
        "description": "Commercial VPN exit nodes — often used for privacy, sometimes for malicious",
        "false_positive_rate": 0.35,
    },
    "CLOUD_PROVIDER": {
        "name": "Cloud Provider",
        "risk_level": "medium",
        "description": "AWS/GCP/Azure — frequently used for scanning and attacks but also legitimate",
        "false_positive_rate": 0.40,
    },
    "KNOWN_MALICIOUS": {
        "name": "Known Malicious IP",
        "risk_level": "critical",
        "description": "IP appears in threat intelligence feeds as confirmed malicious",
        "false_positive_rate": 0.02,
    },
    "INTERNAL": {
        "name": "Internal Network",
        "risk_level": "low",
        "description": "Source is internal RFC1918 address — more likely insider threat or misconfiguration",
        "false_positive_rate": 0.25,
    },
}


# ─────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────

@dataclass
class Hypothesis:
    """
    A single hypothesis explaining an alert.
    """
    id: str
    label: str                      # Short label e.g. "Targeted credential stuffing attack"
    narrative: str                  # Full narrative explanation
    confidence: float              # 0.0 - 1.0
    confidence_reason: str         # Why this confidence level
    tactic_id: Optional[str]        # Primary MITRE tactic ID
    tactic_name: Optional[str]     # Human-readable tactic
    technique_ids: list[str]        # MITRE technique IDs
    technique_names: list[str]     # Human-readable techniques
    attack_phase: str              # "initial_access", "lateral_movement", "exfiltration", etc.
    evidence: list[str]            # Evidence supporting this hypothesis
    counter_evidence: list[str]    # Evidence against / weaknesses
    blast_radius: str              # What is at risk if this is real
    estimated_impact: str          # "critical", "high", "medium", "low"
    recommended_actions: list[str] # What to do about it
    is_false_positive: bool = False
    fp_reason: Optional[str] = None  # If FP, why was detection triggered?

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "narrative": self.narrative,
            "confidence": round(self.confidence * 100, 1),
            "confidence_reason": self.confidence_reason,
            "tactic": f"{self.tactic_id} ({self.tactic_name})" if self.tactic_id else "Unmapped",
            "techniques": [f"{t} ({n})" for t, n in zip(self.technique_ids, self.technique_names)],
            "attack_phase": self.attack_phase,
            "evidence": self.evidence,
            "counter_evidence": self.counter_evidence,
            "blast_radius": self.blast_radius,
            "estimated_impact": self.estimated_impact,
            "recommended_actions": self.recommended_actions,
            "is_fp": self.is_false_positive,
            "fp_reason": self.fp_reason,
        }


@dataclass
class NCEResult:
    """
    Output of NCE.generate().
    Contains ranked hypotheses plus overall assessment.
    """
    alert_id: str
    investigation_id: str
    generated_at: str
    category: str
    primary_hypothesis: Hypothesis
    alternative_hypotheses: list[Hypothesis]
    fp_hypothesis: Optional[Hypothesis]
    recommended_response_tier: str  # P1/P2/P3/P4 based on primary hypothesis
    recommended_immediate_actions: list[str]
    uncertainty_gaps: list[str]      # What we don't know and should find out

    def get_all_hypotheses(self) -> list[Hypothesis]:
        all_h = [self.primary_hypothesis] + self.alternative_hypotheses
        if self.fp_hypothesis:
            all_h.append(self.fp_hypothesis)
        return all_h

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "investigation_id": self.investigation_id,
            "category": self.category,
            "generated_at": self.generated_at,
            "primary_hypothesis": self.primary_hypothesis.to_dict(),
            "alternative_hypotheses": [h.to_dict() for h in self.alternative_hypotheses],
            "fp_hypothesis": self.fp_hypothesis.to_dict() if self.fp_hypothesis else None,
            "recommended_response_tier": self.recommended_response_tier,
            "recommended_immediate_actions": self.recommended_immediate_actions,
            "uncertainty_gaps": self.uncertainty_gaps,
        }


# ─────────────────────────────────────────────────────────────────
# NCE Engine
# ─────────────────────────────────────────────────────────────────

class NCE:
    """
    Narrative Counterfactual Engine.

    Takes alert + triage + specialist findings.
    Returns ranked hypotheses with MITRE mapping, evidence, and recommendations.
    """

    def __init__(self):
        logger.info("NCE (Narrative Counterfactual Engine) initialized")

    def generate(
        self,
        alert_id: str,
        investigation_id: str,
        category: str,
        severity: str,
        triage_result: dict,
        enrichment_result: Optional[dict] = None,
        specialist_findings: Optional[dict] = None,
    ) -> NCEResult:
        """
        Generate hypotheses for an alert.

        Args:
            alert_id: SOC alert ID
            investigation_id: Investigation ID
            category: Alert category (brute_force, lateral_movement, malware, etc.)
            severity: P1/P2/P3/P4
            triage_result: Output from soc_triage
            enrichment_result: Output from threat_enrich
            specialist_findings: Output from specialist agent(s)

        Returns:
            NCEResult with ranked hypotheses
        """
        logger.info(f"[NCE] Generating hypotheses for {alert_id} (category={category}, severity={severity})")

        # Start with base confidence from severity
        base_confidence = {
            "P1": 0.85, "P2": 0.65, "P3": 0.45, "P4": 0.25
        }.get(severity, 0.50)

        # Build evidence/indicator context
        ctx = self._build_context(triage_result, enrichment_result, specialist_findings)

        # Get pattern templates
        pattern = ATTACK_PATTERNS.get(category, ATTACK_PATTERNS["unknown"])

        hypotheses = []
        for tmpl in pattern["hypotheses"]:
            hyp = self._build_hypothesis(
                tmpl, base_confidence, ctx, triage_result, enrichment_result, specialist_findings
            )
            hypotheses.append(hyp)

        # Sort by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)

        # Separate FP hypothesis
        fp_hyp = next((h for h in hypotheses if h.is_false_positive), None)
        non_fp = [h for h in hypotheses if not h.is_false_positive]

        primary = non_fp[0] if non_fp else hypotheses[0]
        alternatives = non_fp[1:] if len(non_fp) > 1 else []

        # Determine response tier
        response_tier = self._determine_response_tier(primary, severity)

        # Recommended immediate actions
        immediate_actions = self._get_immediate_actions(primary, severity)

        # Identify uncertainty gaps
        uncertainty_gaps = self._identify_gaps(ctx, primary, specialist_findings)

        result = NCEResult(
            alert_id=alert_id,
            investigation_id=investigation_id,
            generated_at=datetime.utcnow().isoformat() + "Z",
            category=category,
            primary_hypothesis=primary,
            alternative_hypotheses=alternatives,
            fp_hypothesis=fp_hyp,
            recommended_response_tier=response_tier,
            recommended_immediate_actions=immediate_actions,
            uncertainty_gaps=uncertainty_gaps,
        )

        logger.info(
            f"[NCE] {alert_id} → {len(hypotheses)} hypotheses, "
            f"primary={primary.label[:50]} ({primary.confidence:.0%}), "
            f"tier={response_tier}"
        )

        return result

    def _build_context(
        self,
        triage_result: dict,
        enrichment_result: Optional[dict],
        specialist_findings: Optional[dict],
    ) -> dict:
        """Build indicator context from all sources."""
        ctx = {
            "source_ip": triage_result.get("source_ip"),
            "dest_ip": triage_result.get("dest_ip"),
            "dest_port": triage_result.get("dest_port"),
            "user": triage_result.get("user"),
            "affected_asset": triage_result.get("affected_asset"),
            "rule_name": triage_result.get("rule_name", ""),
            "is_tor": False,
            "is_vpn": False,
            "is_internal": False,
            "is_cloud": False,
            "ip_reputation_score": 50,
            "ip_classification": "unknown",
            "mfa_used": False,
            "failed_login_count": 0,
            "successful_login": False,
            "threat_actor": None,
            "mitre_tactics": [],
            "enrichment_done": False,
            "fp_score": 0,
        }

        # From enrichment
        if enrichment_result:
            ip_rep = enrichment_result.get("ip_reputation", {})
            ctx["ip_reputation_score"] = ip_rep.get("reputation_score", 50)
            ctx["ip_classification"] = ip_rep.get("classification", "unknown")
            ctx["threat_actor"] = enrichment_result.get("threat_actor")
            ctx["enrichment_done"] = True

            tags = ip_rep.get("tags", [])
            ctx["is_tor"] = "tor-exit-node" in tags
            ctx["is_vpn"] = "vpn-exit-node" in tags
            ctx["is_cloud"] = "cloud-provider" in tags

        # From specialist findings
        if specialist_findings:
            sf = specialist_findings
            if sf.get("auth_events"):
                for e in sf["auth_events"]:
                    if "failed" in e.get("event", ""):
                        ctx["failed_login_count"] += e.get("count", 1)
                    if e.get("event") == "successful_login":
                        ctx["successful_login"] = True
                        ctx["mfa_used"] = e.get("mfa_used", False)
            if sf.get("fp_score") is not None:
                ctx["fp_score"] = sf.get("fp_score", 0)
            if sf.get("mitre_mappings"):
                ctx["mitre_tactics"] = [m.get("technique_id") for m in sf["mitre_mappings"]]

        return ctx

    def _build_hypothesis(
        self,
        tmpl: dict,
        base_confidence: float,
        ctx: dict,
        triage_result: dict,
        enrichment_result: Optional[dict],
        specialist_findings: Optional[dict],
    ) -> Hypothesis:
        """Build a Hypothesis from a template + context."""
        hyp_id = tmpl["id"]

        # Start with base confidence + pattern boost
        conf = base_confidence + (tmpl.get("confidence_boost", 0) / 100.0)

        # Adjust confidence based on context indicators
        indicators = tmpl.get("indicators", [])
        evidence_for = []
        evidence_against = []

        for indicator in indicators:
            if self._indicator_matches(indicator, ctx):
                # Indicator is present — boosts confidence for attack, reduces FP
                if tmpl["id"] != "fp_brute":
                    conf += 0.05
                    evidence_for.append(f"Indicator '{indicator}' confirmed present")
                else:
                    conf += 0.10  # FP hypothesis gets bigger boost when indicators present
            else:
                # Indicator missing — weakens attack hypothesis
                if tmpl["id"] != "fp_brute":
                    conf -= 0.03
                    evidence_against.append(f"Expected indicator '{indicator}' NOT found")

        # Specific context adjustments
        if ctx["is_tor"] and hyp_id != "fp_brute":
            conf = min(conf + 0.20, 0.99)
            evidence_for.append("Source IP is TOR exit node — strong anonymization indicator")

        if ctx["is_vpn"] and hyp_id != "fp_brute":
            conf = min(conf + 0.08, 0.95)
            evidence_for.append("Source IP is commercial VPN exit node")

        if ctx["ip_classification"] == "malicious":
            conf = min(conf + 0.25, 0.99)
            evidence_for.append("IP confirmed malicious in threat intel")

        if ctx["ip_reputation_score"] >= 70:
            evidence_for.append(f"IP reputation score {ctx['ip_reputation_score']}/100 — high risk")

        if ctx["failed_login_count"] >= 5:
            evidence_for.append(f"{ctx['failed_login_count']} failed login attempts before success")

        if ctx["mfa_used"] and hyp_id != "fp_brute":
            conf = max(conf - 0.15, 0.05)
            evidence_against.append("MFA was used — reduces likelihood of credential-based attack")

        if not ctx["successful_login"] and hyp_id not in ("fp_brute",):
            evidence_against.append("No successful login observed — attack may be in progress")

        # Clamp confidence
        conf = max(0.01, min(0.99, conf))

        # Build narrative with context
        narrative = tmpl["narrative"]
        # Could inject specific IPs/users into narrative here

        # Get MITRE tactic/technique names
        tactic_id = tmpl.get("tactic")
        tactic_name = MITRE_TACTICS.get(tactic_id, "Unknown") if tactic_id else None
        tech_ids = tmpl.get("techniques", [])
        tech_names = [MITRE_TECHNIQUES.get(t, {}).get("name", t) for t in tech_ids]

        # Determine attack phase
        attack_phase_map = {
            "TA0001": "initial_access", "TA0002": "execution",
            "TA0003": "persistence", "TA0004": "defense_evasion",
            "TA0005": "credential_access", "TA0006": "credential_access",
            "TA0007": "discovery", "TA0008": "lateral_movement",
            "TA0009": "collection", "TA0010": "exfiltration",
            "TA0011": "command_and_control", "TA0040": "impact",
        }
        attack_phase = attack_phase_map.get(tactic_id, "unknown") if tactic_id else "unknown"

        # Build blast radius
        blast_radius = self._estimate_blast_radius(
            ctx, tactic_id, tech_ids, hyp_id
        )

        # Determine estimated impact
        sev_boost = tmpl.get("severity_boost", "medium")
        if ctx["is_tor"] and ctx["successful_login"]:
            estimated_impact = "critical"
        elif hyp_id == "fp_brute":
            estimated_impact = "low"
        else:
            estimated_impact = sev_boost

        # Recommended actions
        recommended_actions = self._get_hypothesis_actions(hyp_id, ctx)

        # Is this a FP hypothesis?
        is_fp = tmpl["id"].endswith("_fp") or tmpl["id"] in ("fp_brute", "fp_unknown")
        fp_reason = None
        if is_fp and conf < 0.30:
            fp_reason = "Alert matches known false positive pattern: service account, known VPN/TOR, no follow-on activity"

        return Hypothesis(
            id=hyp_id,
            label=tmpl["label"],
            narrative=narrative,
            confidence=conf,
            confidence_reason=f"Base {base_confidence:.0%} + pattern boost + contextual indicators",
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            technique_ids=tech_ids,
            technique_names=tech_names,
            attack_phase=attack_phase,
            evidence=evidence_for,
            counter_evidence=evidence_against,
            blast_radius=blast_radius,
            estimated_impact=estimated_impact,
            recommended_actions=recommended_actions,
            is_false_positive=is_fp,
            fp_reason=fp_reason,
        )

    def _indicator_matches(self, indicator: str, ctx: dict) -> bool:
        """Check if an expected indicator is present in the context."""
        indicator_map = {
            "tor_ip": ctx.get("is_tor", False),
            "vpn_ip": ctx.get("is_vpn", False),
            "internal_ip": ctx.get("is_internal", False),
            "repeated_failed_logins": ctx.get("failed_login_count", 0) >= 5,
            "non_mfa_login": ctx.get("successful_login") and not ctx.get("mfa_used"),
            "service_account": bool(ctx.get("user") and any(p in ctx["user"].lower() for p in ["svc_", "service", "daemon", "$"])),
            "known_good_ip": ctx.get("ip_reputation_score", 50) < 30,
            "mfa_used": ctx.get("mfa_used", False),
            "suspicious_email": "email" in ctx.get("rule_name", "").lower(),
            "attachment": "attachment" in ctx.get("rule_name", "").lower(),
            "after_hours": 22 <= datetime.utcnow().hour or datetime.utcnow().hour <= 6,
            "malware_signature": ctx.get("ip_classification") == "malicious",
            "single_event": ctx.get("failed_login_count", 1) <= 1,
            "no_follow_up": not ctx.get("successful_login", False),
        }
        return indicator_map.get(indicator, False)

    def _estimate_blast_radius(
        self,
        ctx: dict,
        tactic_id: Optional[str],
        tech_ids: list[str],
        hyp_id: str,
    ) -> str:
        """Estimate blast radius based on what's at risk."""
        asset = ctx.get("affected_asset") or "target system"
        source_ip = ctx.get("source_ip") or "unknown"
        user = ctx.get("user") or "unknown"

        if hyp_id in ("fp_brute", "fp_unknown"):
            return "No blast radius — alert is likely benign"
        if "T1021.003" in tech_ids:
            return f"Attacker can access {asset} via RDP. From there, could move to other domain hosts. Risk: lateral movement to critical systems."
        if "T1110" in tech_ids:
            return f"Credential stuffing could compromise {user}'s account. If MFA not enforced, all resources accessible. Risk: account takeover + lateral movement."
        if "T1486" in tech_ids:
            return f"ransomware detected at pre-execution stage on {asset}. Encryption could spread via SMB. Risk: total data loss on affected hosts."
        if tactic_id == "TA0010":
            return f"Large data transfer to external host ({source_ip}). Data loss risk depends on data classification. Risk: PII/IP exfiltration."
        if "T1021" in tech_ids:
            return f"Remote services access from {source_ip} to {asset}. Attacker can establish persistent access. Risk: persistent backdoor."
        return f"Attack vector from {source_ip} to {asset}. Blast radius depends on asset criticality and user privileges."

    def _get_hypothesis_actions(self, hyp_id: str, ctx: dict) -> list[str]:
        """Get recommended actions for a hypothesis."""
        asset = ctx.get("affected_asset", "target")
        user = ctx.get("user", "user")
        source_ip = ctx.get("source_ip", "source")

        actions_map = {
            "apt_brute": [
                f"Block {source_ip} at perimeter firewall immediately",
                f"Force password reset for {user}",
                f"Enable MFA for {user} if not already enforced",
                f"Isolate {asset} via EDR and conduct forensic analysis",
                "Review Azure AD / Entra sign-in logs for additional compromise indicators",
            ],
            "insider_brute": [
                f"Review {user}'s recent activity in SIEM",
                "Escalate to HR / Legal for policy review",
                "Monitor for additional anomalous access",
            ],
            "fp_brute": [
                "Mark alert as false positive after analyst review",
                "Add IP to allowlist if confirmed legitimate (vendor VPN)",
                "Document FP reason in case notes",
            ],
            "apt_lm": [
                f"Immediately isolate {asset} — attacker has access",
                f"Block {source_ip} at perimeter",
                f"Reset credentials for {user}",
                "Initiate incident response playbooks",
                "Scope scope: check other hosts for similar access patterns",
            ],
            "ransomware": [
                f"Isolate {asset} immediately — malware executing",
                "Block malware C2 domains at DNS sinkhole",
                "Kill malicious processes",
                "Initiate ransomware response playbook",
            ],
            "spear_phish": [
                "Reset credentials for affected user",
                "Review email gateway logs for additional phishing emails",
                "Check proxy logs for data exfiltration to attacker infrastructure",
            ],
            "data_exfil": [
                f"Block external destination IP",
                "Scope data loss: identify what was accessed",
                "Notify legal/compliance if PII involved",
                "Preserve forensic evidence",
            ],
        }
        return actions_map.get(hyp_id, ["Investigate further with lead agent", "Collect additional evidence"])

    def _determine_response_tier(self, primary: Hypothesis, original_severity: str) -> str:
        """Determine final response tier based on hypothesis + original severity."""
        if primary.is_false_positive:
            return "P4"
        if primary.estimated_impact == "critical" or "T1486" in primary.technique_ids:
            return "P1"
        if primary.estimated_impact == "high":
            return "P2"
        if primary.estimated_impact == "medium":
            return "P3"
        return original_severity

    def _get_immediate_actions(self, primary: Hypothesis, severity: str) -> list[str]:
        """Get immediate response actions based on primary hypothesis and severity."""
        if primary.is_false_positive:
            return ["Mark as false positive", "Document in case notes", "Close investigation"]

        tier = severity or "P3"
        asset = "target system"
        source_ip = "attacker IP"
        actions = []

        if tier in ("P1", "P2"):
            actions = [
                f"Block {source_ip} at perimeter immediately",
                "Isolate affected systems via EDR",
                "Initiate incident response playbook",
            ]
        elif tier == "P3":
            actions = [
                "Monitor for additional activity",
                "Collect forensic evidence",
                "Analyst review before action",
            ]
        else:
            actions = ["Log for review", "Schedule analyst review"]

        return actions

    def _identify_gaps(
        self,
        ctx: dict,
        primary: Hypothesis,
        specialist_findings: Optional[dict],
    ) -> list[str]:
        """Identify what we don't know and should find out."""
        gaps = []

        if not ctx["enrichment_done"]:
            gaps.append("No threat intelligence enrichment — run IP/reputation lookup")
        if not ctx["mfa_used"]:
            gaps.append("MFA status unclear — check if target user has MFA enabled")
        if ctx["failed_login_count"] > 0 and not ctx["successful_login"]:
            gaps.append("Failed logins observed but no successful session — determine if attack is ongoing")
        if ctx["failed_login_count"] == 0 and ctx["successful_login"]:
            gaps.append("Successful login from suspicious source — determine if session is still active")
        if not ctx.get("threat_actor"):
            gaps.append("Threat actor not identified — cross-reference with MITRE groups")
        if primary.estimated_impact in ("critical", "high"):
            gaps.append("High-impact alert — analyst must review before response actions execute")
        if not specialist_findings:
            gaps.append("No specialist agent findings yet — await Developer/SysAdmin analysis")

        return gaps


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # Demo with the same alert we used in Milestone 1
    nce = NCE()
    result = nce.generate(
        alert_id="ALR-2026-05-19-2215-C29D58",
        investigation_id="INV-202605192215-FB85F0",
        category="brute_force",
        severity="P2",
        triage_result={
            "alert_id": "ALR-2026-05-19-2215-C29D58",
            "investigation_id": "INV-202605192215-FB85F0",
            "severity": "P2",
            "category": "brute_force",
            "source_ip": "185.220.101.42",
            "dest_ip": "10.0.1.10",
            "dest_port": 3389,
            "user": "jsmith",
            "affected_asset": "FIN-DC01",
            "rule_name": "Suspicious RDP Lateral Movement to Finance DC",
            "is_false_positive": False,
        },
        enrichment_result={
            "ip_reputation": {
                "ioc": "185.220.101.42",
                "classification": "malicious",
                "reputation_score": 72,
                "tags": ["tor-exit-node", "anonymization"],
            },
            "hypotheses": [
                {"text": "Attacker from known suspicious IP (72% reputation)", "confidence": 72},
                {"text": "False positive — VPN exit node", "confidence": 28},
            ],
            "threat_actor": "TOR_EXIT_NODE",
        },
        specialist_findings={
            "auth_events": [
                {"event": "failed_login", "service": "RDP", "user": "jsmith", "source_ip": "185.220.101.42", "count": 5},
                {"event": "successful_login", "service": "RDP", "user": "jsmith", "source_ip": "185.220.101.42", "count": 1, "mfa_used": False},
            ],
            "fp_score": 25,
        },
    )

    print("\n" + "=" * 70)
    print("🍀 NCE — Narrative Counterfactual Engine Output")
    print("=" * 70)
    print(f"\n📊 PRIMARY HYPOTHESIS: {result.primary_hypothesis.label}")
    print(f"   Confidence: {result.primary_hypothesis.confidence:.0%}")
    print(f"   MITRE: {result.primary_hypothesis.tactic_id} / {result.primary_hypothesis.technique_ids}")
    print(f"   Impact: {result.primary_hypothesis.estimated_impact}")
    print(f"   Phase: {result.primary_hypothesis.attack_phase}")
    print(f"\n   Narrative: {result.primary_hypothesis.narrative}")
    print(f"\n   Evidence:")
    for e in result.primary_hypothesis.evidence:
        print(f"     ✓ {e}")
    if result.primary_hypothesis.counter_evidence:
        print(f"\n   Counter-evidence:")
        for e in result.primary_hypothesis.counter_evidence:
            print(f"     ✗ {e}")
    print(f"\n   Blast radius: {result.primary_hypothesis.blast_radius}")
    print(f"\n   Recommended actions:")
    for a in result.primary_hypothesis.recommended_actions[:3]:
        print(f"     → {a}")

    print(f"\n{'='*70}")
    print(f"📋 ALTERNATIVE HYPOTHESES ({len(result.alternative_hypotheses)})")
    print("=" * 70)
    for i, alt in enumerate(result.alternative_hypotheses, 1):
        print(f"  {i}. [{alt.confidence:.0%}] {alt.label} — {alt.narrative[:80]}...")

    if result.fp_hypothesis:
        print(f"\n{'='*70}")
        print(f"🔍 FP HYPOTHESIS")
        print("=" * 70)
        fp = result.fp_hypothesis
        print(f"  [{fp.confidence:.0%}] {fp.label} — {fp.narrative}")

    print(f"\n{'='*70}")
    print(f"🎯 RECOMMENDED RESPONSE TIER: {result.recommended_response_tier}")
    print(f"   Immediate actions: {result.recommended_immediate_actions[:2]}")
    print(f"   Uncertainty gaps: {result.uncertainty_gaps}")
    print("=" * 70)