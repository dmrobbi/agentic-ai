"""
SOC Tools — Triage, Dispatch, Enrichment, HITL, RSEM Scoring
==========================================================

Tools used by the SOC Lead Agent and specialist agents.
Each tool is a standalone function compatible with the agentic-ai tool calling interface.
"""

import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# MITRE ATT&CK Reference (subset for triage)
# ─────────────────────────────────────────────

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
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
    "T1566": {"name": "Phishing", "tactics": ["TA0001"]},
    "T1133": {"name": "External Remote Services", "tactics": ["TA0001"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["TA0001"]},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
    "T1053": {"name": "Scheduled Task/Job", "tactics": ["TA0002"]},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactics": ["TA0008"]},
    "T1021.003": {"name": "Remote Desktop Protocol", "tactics": ["TA0008"]},
    "T1021.004": {"name": "SSH", "tactics": ["TA0008"]},
    # Credential Access
    "T1110": {"name": "Brute Force", "tactics": ["TA0006"]},
    "T1110.003": {"name": "Brute Force - SMB", "tactics": ["TA0006"]},
    "T1110.004": {"name": "Brute Force - RDP", "tactics": ["TA0006"]},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactics": ["TA0040"]},
    "T1489": {"name": "Service Stop", "tactics": ["TA0040"]},
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactics": ["TA0007"]},
}

KNOWN_FP_PATTERNS = [
    "legitimate_vpn", " approved_vendor", " scheduled_backup",
    "patch Tuesday", "known_good_ip", "internal_scan",
]


# ─────────────────────────────────────────────
# Tool: soc_triage
# ─────────────────────────────────────────────

def soc_triage(alert: dict) -> dict:
    """
    Triage a raw SOCAlert dict:
    - Classify severity (P1–P4)
    - Classify category
    - Deduplicate against recent alerts (5-tuple hash)
    - Assign attack stage (MITRE tactic)
    - Check for known false positive patterns

    Returns triage result dict.
    """
    alert_id = alert.get("alert_id", "UNKNOWN")
    severity_raw = alert.get("severity", "P4")
    category_raw = alert.get("category", "unknown")
    rule_name = alert.get("rule_name", "")
    description = alert.get("description", "")
    source_ip = alert.get("source_ip")
    dest_ip = alert.get("dest_ip")
    dest_port = alert.get("dest_port")
    protocol = alert.get("protocol", "TCP")
    user = alert.get("user")
    raw_log = alert.get("raw_log", "")

    # ── 1. Severity mapping ──
    severity_map = {
        "P1": "P1", "CRITICAL": "P1",
        "P2": "P2", "HIGH": "P2",
        "P3": "P3", "MEDIUM": "P3",
        "P4": "P4", "LOW": "P4", "INFO": "P4",
    }
    if isinstance(severity_raw, str):
        severity = severity_map.get(severity_raw.upper(), "P4")
    else:
        severity = "P4"

    # ── 2. Category mapping ──
    category_keywords = {
        "malware": ["malware", "ransomware", "trojan", "virus", "cryptolocker"],
        "phishing": ["phishing", "spear phishing", "email", "smishing"],
        "brute_force": ["brute", "force", "rdp", "ssh", "failed_login", "failed_auth"],
        "lateral_movement": ["lateral", "movement", "rdp", "psexec", "wmi"],
        "data_breach": ["exfiltration", "data loss", "pii", "hipaa", "gdpr"],
        "unauthorized_access": ["unauthorized", "no_perm", "forbidden", "priv_esc"],
        "network": ["port_scan", "recon", "dos", "ddos", "flood"],
        "insider": ["insider", "data_theft", "policy_violation"],
        "compliance": ["compliance", "sox", "pci", "soc2", "iso27001"],
    }

    text_to_check = f"{description} {rule_name} {str(raw_log)}".lower()
    detected_category = "unknown"
    for cat, keywords in category_keywords.items():
        if any(kw in text_to_check for kw in keywords):
            detected_category = cat
            break

    category = detected_category if detected_category != "unknown" else category_raw

    # ── 3. Deduplication (5-tuple hash) ──
    dup_tuple = f"{source_ip or ''}|{dest_ip or ''}|{dest_port or ''}|{protocol or ''}|{category or ''}"
    dedup_hash = hashlib.sha256(dup_tuple.encode()).hexdigest()[:16]

    # ── 4. MITRE ATT&CK mapping ──
    mitre_tactics = []
    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        if tech_info["name"].lower() in text_to_check:
            tactic_ids = tech_info["tactics"]
            mitre_tactics.extend(
                {"id": tid, "name": MITRE_TACTICS.get(tid, "Unknown")}
                for tid in tactic_ids
            )
    mitre_tactics = mitre_tactics[:3]  # cap at 3

    # ── 5. FP check ──
    is_fp = False
    for pattern in KNOWN_FP_PATTERNS:
        if pattern in text_to_check:
            is_fp = True
            break

    # ── 6. Auto-classify severity upgrade ──
    if severity == "P4" and category in ["malware", "data_breach"]:
        severity = "P2"
    elif severity == "P4" and category in ["brute_force", "lateral_movement"]:
        severity = "P3"
    if source_ip and is_external_ip(source_ip):
        # External source IP is more concerning
        pass

    # ── 7. Investigation ID ──
    investigation_id = f"INV-{datetime.utcnow().strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:6].upper()}"

    # ── 8. Dispatch routing ──
    dispatch_targets = {
        "malware": ["soc.developer", "soc.qa"],
        "phishing": ["soc.developer", "soc.sysadmin"],
        "brute_force": ["soc.sysadmin", "soc.qa"],
        "lateral_movement": ["soc.developer", "soc.sysadmin", "soc.qa"],
        "data_breach": ["soc.developer", "soc.sysadmin"],
        "unauthorized_access": ["soc.sysadmin"],
        "network": ["soc.sysadmin"],
        "insider": ["soc.sysadmin", "soc.qa"],
        "compliance": ["soc.sysadmin"],
        "unknown": ["soc.sysadmin", "soc.developer"],
    }
    assigned_agents = dispatch_targets.get(category, ["soc.sysadmin"])

    result = {
        "alert_id": alert_id,
        "investigation_id": investigation_id,
        "dedup_hash": dedup_hash,
        "severity": severity,
        "category": category,
        "is_false_positive": is_fp,
        "mitre_tactics": mitre_tactics,
        "assigned_agents": assigned_agents,
        "triage_timestamp": datetime.utcnow().isoformat() + "Z",
        "rule_name": rule_name,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
    }

    logger.info(
        f"[soc_triage] {alert_id} → severity={severity} category={category} "
        f"is_fp={is_fp} dispatch={assigned_agents}"
    )
    return result


def is_external_ip(ip: Optional[str]) -> bool:
    """Check if an IP is external (not RFC1918 private)."""
    if not ip:
        return False
    # Very basic check — expand as needed
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.")
    return not ip.startswith(private_prefixes)


# ─────────────────────────────────────────────
# Tool: soc_dispatch
# ─────────────────────────────────────────────

def soc_dispatch(triage_result: dict, kafka_client=None) -> dict:
    """
    Dispatch investigation tasks to specialist agents via Kafka.
    For each assigned agent, publish a task to soc.investigation.tasks.

    Returns dispatch result with task IDs.
    """
    from soc.kafka_client import InvestigationTask

    alert_id = triage_result["alert_id"]
    investigation_id = triage_result["investigation_id"]
    assigned_agents = triage_result["assigned_agents"]
    priority = triage_result["severity"]
    category = triage_result["category"]

    # Map category to task types
    task_type_map = {
        "malware": "malware_analysis",
        "phishing": "threat_enrich",
        "brute_force": "log_analysis",
        "lateral_movement": "log_analysis",
        "data_breach": "log_analysis",
        "unauthorized_access": "log_analysis",
        "network": "log_analysis",
        "unknown": "log_analysis",
    }
    default_task_type = "threat_enrich"
    task_type = task_type_map.get(category, default_task_type)

    # Override task type per agent
    agent_task_map = {
        "soc.developer": "threat_enrich",
        "soc.sysadmin": "log_analysis",
        "soc.qa": "fp_check",
    }

    dispatched_tasks = []
    for agent in assigned_agents:
        task_id = f"TSK-{uuid.uuid4().hex[:8].upper()}"
        task = InvestigationTask(
            task_id=task_id,
            alert_id=alert_id,
            investigation_id=investigation_id,
            task_type=agent_task_map.get(agent, task_type),
            assigned_agent=agent,
            priority=priority,
            context={
                "triage_result": triage_result,
                "source_ip": triage_result.get("source_ip"),
                "dest_ip": triage_result.get("dest_ip"),
                "rule_name": triage_result.get("rule_name"),
            },
            status="pending",
        )

        if kafka_client:
            kafka_client.produce_investigation_task(task)

        dispatched_tasks.append({
            "task_id": task_id,
            "assigned_agent": agent,
            "task_type": agent_task_map.get(agent, task_type),
        })

        logger.info(f"[soc_dispatch] {alert_id} → {agent} (task={task_id})")

    return {
        "alert_id": alert_id,
        "investigation_id": investigation_id,
        "dispatched_tasks": dispatched_tasks,
        "dispatch_timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────
# Tool: soc_rsem_score
# ─────────────────────────────────────────────

def soc_rsem_score(
    options: list[dict],
    severity: str = "P3",
    category: str = "unknown",
) -> list[dict]:
    """
    Score response options using RSEM (Risk Scoring and Evaluation Module).

    Factors (weights):
      - containment_effectiveness: 0.35
      - business_impact: 0.30
      - execution_risk: 0.20
      - reversibility: 0.15

    Input options: [{"action": "block_ip", "target": "...", "description": "..."}]
    Returns scored options with: score, tier, reasoning.
    """
    weights = {
        "containment_effectiveness": 0.35,
        "business_impact": 0.30,
        "execution_risk": 0.20,
        "reversibility": 0.15,
    }

    # Action-specific factor presets
    action_factors = {
        "block_ip": {
            "containment_effectiveness": 0.9,
            "business_impact": 0.1,
            "execution_risk": 0.05,
            "reversibility": 0.95,
        },
        "isolate_endpoint": {
            "containment_effectiveness": 0.95,
            "business_impact": 0.4,
            "execution_risk": 0.1,
            "reversibility": 0.8,
        },
        "reset_password": {
            "containment_effectiveness": 0.6,
            "business_impact": 0.2,
            "execution_risk": 0.05,
            "reversibility": 0.9,
        },
        "force_mfa_reset": {
            "containment_effectiveness": 0.7,
            "business_impact": 0.15,
            "execution_risk": 0.05,
            "reversibility": 0.95,
        },
        "create_case": {
            "containment_effectiveness": 0.3,
            "business_impact": 0.0,
            "execution_risk": 0.0,
            "reversibility": 1.0,
        },
        "block_domain": {
            "containment_effectiveness": 0.8,
            "business_impact": 0.2,
            "execution_risk": 0.1,
            "reversibility": 0.9,
        },
        "no_action": {
            "containment_effectiveness": 0.0,
            "business_impact": 0.0,
            "execution_risk": 0.0,
            "reversibility": 1.0,
        },
    }

    # Severity multipliers (higher severity = higher base score needed for same action)
    severity_multiplier = {"P1": 1.2, "P2": 1.1, "P3": 1.0, "P4": 0.9}

    scored_options = []
    for option in options:
        action = option.get("action", "unknown")
        factors = action_factors.get(action, {
            "containment_effectiveness": 0.5,
            "business_impact": 0.3,
            "execution_risk": 0.2,
            "reversibility": 0.5,
        })

        raw_score = sum(
            factors[f] * weights[f]
            for f in weights
        ) * severity_multiplier.get(severity, 1.0)

        score = min(100.0, max(0.0, round(raw_score * 100, 1)))

        if score >= 80:
            tier = "P1"
        elif score >= 60:
            tier = "P2"
        elif score >= 40:
            tier = "P3"
        else:
            tier = "P4"

        blast_radius = _blast_radius(action, option.get("target", ""))
        reasoning = _rsem_reasoning(action, factors, severity, blast_radius)

        scored_options.append({
            "action": action,
            "target": option.get("target", ""),
            "description": option.get("description", ""),
            "score": score,
            "tier": tier,
            "factors": {k: round(v, 3) for k, v in factors.items()},
            "blast_radius": blast_radius,
            "reasoning": reasoning,
        })

    # Sort by score descending
    scored_options.sort(key=lambda x: x["score"], reverse=True)

    for i, opt in enumerate(scored_options):
        opt["rank"] = i + 1

    return scored_options


def _blast_radius(action: str, target: str) -> str:
    """Calculate blast radius description for an action."""
    radius_map = {
        "block_ip": f"Blocks {target}. No blast radius if IP is attacker-only.",
        "isolate_endpoint": f"Affects users on {target}. Temporary network isolation.",
        "reset_password": "User inconvenience only. Re-authentication required.",
        "force_mfa_reset": "User must re-enroll MFA. Low operational impact.",
        "create_case": "No operational impact. Creates tracking record.",
        "block_domain": f"Blocks {target}. May affect legitimate subdomain traffic.",
    }
    return radius_map.get(action, "Minimal operational impact.")


def _rsem_reasoning(action: str, factors: dict, severity: str, blast_radius: str) -> str:
    """Generate human-readable RSEM reasoning."""
    ce = factors.get("containment_effectiveness", 0)
    bi = factors.get("business_impact", 0)
    er = factors.get("execution_risk", 0)
    rev = factors.get("reversibility", 0)

    return (
        f"{action.replace('_', ' ')} at {severity} severity: "
        f"containment effectiveness {ce:.0%}, business impact {bi:.0%}, "
        f"execution risk {er:.0%}, reversibility {rev:.0%}. "
        f"{blast_radius}"
    )


# ─────────────────────────────────────────────
# Tool: soc_hitl_present
# ─────────────────────────────────────────────

def soc_hitl_present(
    triage_result: dict,
    enrichment_result: dict,
    scored_options: list[dict],
    analyst_name: str = "analyst",
) -> str:
    """
    Format a human-in-the-loop escalation prompt for the analyst.
    Returns a formatted markdown string ready to display or send.
    """
    alert_id = triage_result["alert_id"]
    severity = triage_result["severity"]
    category = triage_result["category"]
    source_ip = triage_result.get("source_ip", "unknown")
    dest_ip = triage_result.get("dest_ip", "unknown")
    rule_name = triage_result.get("rule_name", "")
    mitre_tactics = triage_result.get("mitre_tactics", [])

    investigation_id = triage_result["investigation_id"]

    # Build MITRE line
    mitre_line = ", ".join(
        f"{t['id']} ({t['name']})" for t in mitre_tactics
    ) if mitre_tactics else "Unmapped"

    # Build hypotheses from enrichment
    hypotheses = enrichment_result.get("hypotheses", [])
    if not hypotheses:
        hypotheses = [
            {"text": f"{category.upper()} attack pattern detected", "confidence": 75},
            {"text": "False positive — legitimate activity", "confidence": 25},
        ]

    # Build options string
    options_str = ""
    for i, opt in enumerate(scored_options[:5], 1):
        letter = chr(64 + i)  # A, B, C...
        options_str += (
            f"  [{letter}] **{opt['action'].replace('_', ' ').title()}** — "
            f"score {opt['score']:.0f}/100\n"
            f"      Blast radius: {opt['blast_radius']}\n"
        )

    panel = f"""🚨 INCIDENT: {rule_name or 'Security Alert'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Alert ID:** `{alert_id}` | **{severity}** | {category.upper()}
**Investigation:** `{investigation_id}`
**Affected:** {dest_ip} ← {source_ip}
**MITRE:** {mitre_line}

**Here's what I know:**
• Source: {source_ip} → Destination: {dest_ip}
• Rule: {rule_name}

**Here's what I think:**
"""
    for j, h in enumerate(hypotheses[:3], 1):
        panel += f"  {j}. {h['text']} (confidence: {h['confidence']}%)\n"

    panel += """
**Here's where I'm uncertain:**
• Whether this is targeted or opportunistic
• If any data was accessed before detection

**Recommended actions (RSEM scored):**
""" + options_str + f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What's your call? Type [A], [B], [C] or describe your own action.
_Analyst: {analyst_name} | {datetime.utcnow().strftime('%H:%M:%S')} UTC_
"""

    return panel


# ─────────────────────────────────────────────
# Tool: threat_enrich
# ─────────────────────────────────────────────

def threat_enrich(ioc: str, ioc_type: str = "ip") -> dict:
    """
    Enrich an IOC with threat intelligence.
    Returns a dict with classification, reputation, related campaigns.
    """
    # External API lookups would go here (VirusTotal, AbuseIPDB, MISP, OTX)
    # For now, return a structured mock result
    logger.info(f"[threat_enrich] Enriching {ioc_type}: {ioc}")

    # Basic checks for mock data
    is_tor = ioc.startswith(("185.220.", "199.249."))
    is_cloud = ioc.startswith(("3.", "35.", "52.", "54."))
    is_vpn = False  # Would check against known VPN exit node list

    if is_tor:
        classification = "malicious"
        reputation_score = 72
        tags = ["tor-exit-node", "anonymization"]
        campaigns = ["generic-tor-campaign"]
    elif is_cloud:
        classification = "unknown"
        reputation_score = 50
        tags = ["cloud-provider"]
        campaigns = []
    else:
        classification = "unknown"
        reputation_score = 50
        tags = []
        campaigns = []

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "classification": classification,
        "reputation_score": reputation_score,
        "tags": tags,
        "related_campaigns": campaigns,
        "enriched_at": datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────
# Tool: mitre_lookup
# ─────────────────────────────────────────────

def mitre_lookup(identifier: str) -> dict:
    """
    Look up a MITRE ATT&CK technique or tactic by ID or name.
    identifier: e.g. "T1059.003", "T1021", "Lateral Movement"
    Returns technique/tactic details.
    """
    identifier = identifier.strip().upper()

    # Check direct technique ID match
    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        if tech_id.replace(".", "") == identifier.replace(".", "").replace("T", "T"):
            tactics = [
                {"id": tid, "name": MITRE_TACTICS.get(tid, "Unknown")}
                for tid in tech_info["tactics"]
            ]
            return {
                "type": "technique",
                "id": tech_id,
                "name": tech_info["name"],
                "tactics": tactics,
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            }

    # Check tactic ID match
    for tactic_id, tactic_name in MITRE_TACTICS.items():
        if tactic_id == identifier or tactic_name.lower().replace(" ", "_") == identifier.lower().replace(" ", "_"):
            return {
                "type": "tactic",
                "id": tactic_id,
                "name": tactic_name,
                "techniques": [
                    {"id": tid, "name": info["name"]}
                    for tid, info in MITRE_TECHNIQUES.items()
                    if tactic_id in info["tactics"]
                ],
                "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
            }

    # Check name match
    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        if tech_info["name"].lower() == identifier.lower():
            return {
                "type": "technique",
                "id": tech_id,
                "name": tech_info["name"],
                "tactics": [{"id": t, "name": MITRE_TACTICS.get(t)} for t in tech_info["tactics"]],
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            }

    return {"error": f"MITRE '{identifier}' not found", "identifier": identifier}


# ─────────────────────────────────────────────
# Tool: kafka_produce
# ─────────────────────────────────────────────

def kafka_produce(topic: str, message: dict, kafka_client=None) -> dict:
    """
    Produce a generic message to a Kafka topic.
    If kafka_client is provided, use it. Otherwise try to create one.
    """
    if kafka_client is None:
        from soc.kafka_client import SOCKafkaClient
        kafka_client = SOCKafkaClient()

    try:
        if topic == SOCKafkaClient.TOPIC_ALERTS_RAW:
            from soc.kafka_client import SOCAlert
            alert = SOCAlert(**message)
            kafka_client.produce_alert(alert)
        elif topic == SOCKafkaClient.TOPIC_INVESTIGATION_TASKS:
            from soc.kafka_client import InvestigationTask
            task = InvestigationTask(**message)
            kafka_client.produce_investigation_task(task)
        elif topic == SOCKafkaClient.TOPIC_RESPONSE_COMMANDS:
            from soc.kafka_client import ResponseCommand
            cmd = ResponseCommand(**message)
            kafka_client.produce_response_command(cmd)
        else:
            kafka_client._get_producer().produce(
                topic=topic,
                key=message.get("id", ""),
                value=__import__("json").dumps(message),
            )
        kafka_client.flush()
        return {"success": True, "topic": topic, "message_id": message.get("id", "")}
    except Exception as e:
        logger.error(f"[kafka_produce] Failed to produce to {topic}: {e}")
        return {"success": False, "error": str(e), "topic": topic}