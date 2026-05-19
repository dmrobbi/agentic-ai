#!/usr/bin/env python3
"""
SOCConversation — Full Pipeline Demo
=====================================

Demonstrates the complete SOCConversation pipeline:
  1. Lead Agent receives alert (from Kafka or mock)
  2. soc_triage → PostgreSQL write → soc_dispatch
  3. Specialist agents process in parallel (mock findings)
  4. NCE generates ranked hypotheses (MITRE mapping + narrative)
  5. RSEM scores response options (effectiveness)
  6. SSE validates safety (blast radius + operational impact)
  7. Full HITL recommendation panel for analyst

Usage:
  python3 run_soc.py --demo              # Run demo with sample alert
  python3 run_soc.py --demo --category brute_force
  python3 run_soc.py --consumer         # Start consuming from Kafka
  python3 run_soc.py --consumer --max-alerts 10

For the live Kafka consumer, install confluent-kafka:
  pip install confluent-kafka
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime

sys.path.insert(0, ".")

from soc.kafka_client import SOCKafkaClient, SOCAlert, generate_alert_id, AlertSeverity, AlertCategory
from soc.db_client import SOCDBClient, DBConfig
from soc.nce import NCE
from soc.sse import SSE
from soc.rs_em import RSEM
from soc.tools.soc_tools import soc_triage, soc_dispatch, soc_hitl_present, threat_enrich

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Demo Scenarios
# ─────────────────────────────────────────────────────────────────

DEMO_SCENARIOS = {
    "brute_force": {
        "alert_id_override": "ALR-2026-05-19-DEMO01",
        "source": "wazuh",
        "source_ref": "WAZUH-DEMO-0001",
        "rule_name": "Suspicious RDP Lateral Movement — Finance Domain Controller",
        "description": "5 failed RDP logins from TOR exit node followed by successful connection with no MFA. Connection to FIN-DC01 (Windows Server 2022).",
        "severity": "P2",
        "category": "brute_force",
        "affected_asset": "FIN-DC01",
        "source_ip": "185.220.101.42",
        "dest_ip": "10.0.1.10",
        "dest_port": 3389,
        "protocol": "TCP",
        "user": "jsmith",
        "raw_log": json.dumps({
            "timestamp": "2026-05-19T22:30:00Z",
            "event_type": "rdp_login_sequence",
            "failed_attempts": 5,
            "source_ip": "185.220.101.42",
            "source_country": "Poland",
            "source_asn": "AS12345 Proton AG",
            "dest_ip": "10.0.1.10",
            "dest_host": "FIN-DC01",
            "dest_port": 3389,
            "user": "jsmith",
            "mfa_used": False,
            "session_duration_seconds": 1847,
            "bytes_in": 89432,
            "bytes_out": 12456,
        }),
    },
    "malware": {
        "alert_id_override": "ALR-2026-05-19-DEMO02",
        "source": "wazuh",
        "source_ref": "WAZUH-DEMO-0002",
        "rule_name": "Emotet Ransomware Dropper — Macro Execution",
        "description": "User opened macro-enabled Excel document from phishing email. PowerShell spawned to download second-stage payload from attacker C2.",
        "severity": "P1",
        "category": "malware",
        "affected_asset": "WORKSTATION-42",
        "source_ip": "10.0.3.15",
        "dest_ip": "185.220.101.99",
        "dest_port": 443,
        "protocol": "TCP",
        "user": "accounting",
        "filename": "Invoice_2026_05.xlsx",
        "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "raw_log": json.dumps({
            "timestamp": "2026-05-19T14:22:00Z",
            "event_type": "macro_execution",
            "file": "Invoice_2026_05.xlsx",
            "user": "accounting",
            "hostname": "WORKSTATION-42",
            "parent_process": "WINWORD.EXE",
            "child_process": "powershell.exe",
            "script_content": "... -NonInteractive -ExecutionPolicy Bypass ...",
            "c2_ip": "185.220.101.99",
            "c2_domain": None,
        }),
    },
    "phishing": {
        "alert_id_override": "ALR-2026-05-19-DEMO03",
        "source": "cortex",
        "source_ref": "CORTEX-DEMO-0003",
        "rule_name": "Spearphishing — Fake O365 Login Page",
        "description": "Employee clicked link in phishing email posing as Microsoft O365. Entered credentials on fake login page hosted on attacker infrastructure.",
        "severity": "P1",
        "category": "phishing",
        "affected_asset": "WORKSTATION-77",
        "source_ip": "10.0.3.77",
        "dest_ip": "203.0.113.42",
        "dest_port": 443,
        "protocol": "TCP",
        "user": "finance_manager",
        "domain": "login-microsoft365.attacker-c2.com",
        "raw_log": json.dumps({
            "timestamp": "2026-05-19T09:15:00Z",
            "event_type": "phishing_redirect",
            "user": "finance_manager",
            "source_ip": "10.0.3.77",
            "phishing_url": "https://login-microsoft365.attacker-c2.com/fake-oidc",
            "dest_ip": "203.0.113.42",
            "referrer": "https://mail.stsgym.com/attachment/1234",
            "form_data_captured": ["email", "password"],
        }),
    },
    "data_breach": {
        "alert_id_override": "ALR-2026-05-19-DEMO04",
        "source": "netskope",
        "source_ref": "NETSKOPE-DEMO-0004",
        "rule_name": "Anomalous Data Transfer — Cloud Storage Exfiltration",
        "description": "800MB upload from internal host to unauthorized personal cloud storage (Dropbox). Unusual time (02:30 UTC), user not normally active.",
        "severity": "P1",
        "category": "data_breach",
        "affected_asset": "WORKSTATION-19",
        "source_ip": "10.0.3.19",
        "dest_ip": "13.92.145.50",  # Dropbox
        "dest_port": 443,
        "protocol": "TCP",
        "user": "contractor_bob",
        "raw_log": json.dumps({
            "timestamp": "2026-05-19T02:30:00Z",
            "event_type": "large_upload",
            "user": "contractor_bob",
            "hostname": "WORKSTATION-19",
            "dest_domain": "dropbox.com",
            "bytes_uploaded": 838860800,
            "file_types": ["zip", "pdf", "docx"],
            "dest_ip": "13.92.145.50",
            "session_duration_minutes": 45,
        }),
    },
}


# ─────────────────────────────────────────────────────────────────
# Full Pipeline
# ─────────────────────────────────────────────────────────────────

class SOCPipeline:
    """
    Orchestrates the complete SOCConversation pipeline.

    Lead Agent → Triage → Dispatch → NCE → RSEM → SSE → HITL → ResponseCommand
    """

    def __init__(self, enable_postgres: bool = False, kafka_bootstrap: str = "207.244.226.151:9092"):
        self.kafka = SOCKafkaClient(bootstrap_server=kafka_bootstrap)
        self.nce = NCE()
        self.sse = SSE()
        self.rs_em = RSEM()

        if enable_postgres:
            try:
                self.db = SOCDBClient(config=DBConfig(
                    host="localhost", writer_port=5433, reader_port=5434,
                    database="postgres", user="postgres", password=""
                ))
                self.db.init_schema()
            except Exception as e:
                logger.warning(f"PostgreSQL not available: {e}. Continuing without DB.")
                self.db = None
        else:
            self.db = None

        logger.info("SOCPipeline initialized — NCE + SSE + RSEM ready")

    def run_full_pipeline(self, alert: SOCAlert) -> dict:
        """
        Run the complete pipeline for one alert.
        Returns final HITL panel + command decisions.
        """
        start = time.monotonic()
        steps = []

        # ── Step 1: Triage ──
        t0 = time.monotonic()
        triage = soc_triage(alert.to_kafka_message()["value"])
        triage_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "triage", "ms": round(triage_time, 1), "status": "done"})
        logger.info(f"[Pipeline] Triage done in {triage_time:.0f}ms → severity={triage['severity']}")

        # ── Step 2: Dispatch (mock) ──
        t0 = time.monotonic()
        dispatch_result = soc_dispatch(triage, kafka_client=None)  # mock — no Kafka needed
        dispatch_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "dispatch", "ms": round(dispatch_time, 1), "status": "done"})

        # ── Step 3: IP Enrichment ──
        t0 = time.monotonic()
        enrichment = {}
        if alert.source_ip:
            rep = threat_enrich(str(alert.source_ip), "ip")
            enrichment["ip_reputation"] = rep
            hypotheses_from_ip = []
            if rep.get("reputation_score", 50) >= 70:
                hypotheses_from_ip.append({
                    "text": f"Attacker from confirmed malicious IP ({rep['reputation_score']}%)",
                    "confidence": rep["reputation_score"]
                })
            elif rep.get("reputation_score", 50) >= 50:
                hypotheses_from_ip.append({
                    "text": f"Suspicious IP ({rep['reputation_score']}%) — investigate further",
                    "confidence": rep["reputation_score"] * 0.8,
                })
            else:
                hypotheses_from_ip.append({
                    "text": "Unknown IP — likely false positive",
                    "confidence": 100 - rep.get("reputation_score", 50),
                })
            enrichment["hypotheses"] = hypotheses_from_ip
            enrichment["threat_actor"] = "TOR_EXIT_NODE" if "tor" in str(rep.get("tags", [])).lower() else "UNKNOWN"
        enrich_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "enrichment", "ms": round(enrich_time, 1), "status": "done"})

        # ── Step 4: NCE — Hypothesis Generation ──
        t0 = time.monotonic()
        nce_result = self.nce.generate(
            alert_id=alert.alert_id,
            investigation_id=triage["investigation_id"],
            category=triage["category"],
            severity=triage["severity"],
            triage_result=triage,
            enrichment_result=enrichment,
            specialist_findings=self._mock_specialist_findings(alert, triage),
        )
        nce_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "nce", "ms": round(nce_time, 1), "status": "done"})
        logger.info(f"[Pipeline] NCE done in {nce_time:.0f}ms → {nce_result.primary_hypothesis.label[:60]}")

        # ── Step 5: RSEM — Score Response Options ──
        t0 = time.monotonic()
        options = self._build_response_options(alert, triage, nce_result)
        scored_options = self.rs_em.score_options(options, severity=triage["severity"])
        rsem_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "rsem", "ms": round(rsem_time, 1), "status": "done"})

        # ── Step 6: SSE — Safety Validation ──
        t0 = time.monotonic()
        sse_results = self.sse.validate_action_plan(
            options=[{"action": o["action"], "target": o["target"]} for o in scored_options],
            asset_name=triage.get("affected_asset", alert.affected_asset),
            context={
                "source_ip": alert.source_ip,
                "affected_asset": alert.affected_asset,
                "severity": triage["severity"],
            },
        )
        sse_time = (time.monotonic() - t0) * 1000
        steps.append({"step": "sse", "ms": round(sse_time, 1), "status": "done"})

        # Merge SSE safety into scored_options
        for i, sse_r in enumerate(sse_results):
            if i < len(scored_options):
                scored_options[i]["sse_verdict"] = sse_r.safety_verdict.verdict
                scored_options[i]["safety_impact_score"] = sse_r.safety_verdict.operational_impact_score
                scored_options[i]["safety_warnings"] = sse_r.safety_verdict.safety_reasons
                scored_options[i]["risk_exposure"] = sse_r.risk_exposure

        # ── Step 7: Build final HITL panel ──
        hitl_panel = self._build_hitl_panel(alert, triage, nce_result, scored_options, sse_results)

        total_ms = (time.monotonic() - start) * 1000
        logger.info(f"[Pipeline] Complete in {total_ms:.0f}ms")

        return {
            "alert_id": alert.alert_id,
            "investigation_id": triage["investigation_id"],
            "category": triage["category"],
            "severity": triage["severity"],
            "steps": steps,
            "total_ms": round(total_ms, 1),
            "triage": triage,
            "nce_result": nce_result,
            "scored_options": scored_options,
            "sse_results": sse_results,
            "hitl_panel": hitl_panel,
        }

    def _mock_specialist_findings(self, alert: SOCAlert, triage: dict) -> dict:
        """Generate mock specialist findings (would come from real agents)."""
        return {
            "auth_events": [
                {"event": "failed_login", "service": "RDP", "user": alert.user or "unknown", "source_ip": alert.source_ip, "count": 5},
                {"event": "successful_login", "service": "RDP", "user": alert.user or "unknown", "source_ip": alert.source_ip, "count": 1, "mfa_used": False},
            ] if triage["category"] in ("brute_force", "lateral_movement") else [],
            "fp_score": 25 if triage["category"] == "brute_force" else 0,
        }

    def _build_response_options(self, alert: SOCAlert, triage: dict, nce_result) -> list[dict]:
        """Build the response options for RSEM scoring."""
        options = [
            {"action": "block_ip", "target": alert.source_ip or "unknown", "description": f"Block {alert.source_ip} at perimeter firewall"},
            {"action": "isolate_endpoint", "target": alert.affected_asset, "description": f"Isolate {alert.affected_asset} via EDR network isolation"},
            {"action": "reset_password", "target": alert.user or "unknown", "description": f"Force password reset for {alert.user}"},
            {"action": "create_case", "target": alert.alert_id, "description": "Create TheHive case for investigation and documentation"},
        ]

        if nce_result.primary_hypothesis.technique_ids and "T1110" in nce_result.primary_hypothesis.technique_ids:
            options.append({
                "action": "force_mfa_reset",
                "target": alert.user or "unknown",
                "description": f"Force MFA re-enrollment for {alert.user} — prevent pass-the-hash reuse"
            })

        return options

    def _build_hitl_panel(
        self,
        alert: SOCAlert,
        triage: dict,
        nce_result,
        scored_options: list[dict],
        sse_results: list,
    ) -> str:
        """Build the full HITL recommendation panel."""
        primary = nce_result.primary_hypothesis
        severity = triage["severity"]

        # Count safe/executable options
        safe_count = sum(1 for s in sse_results if s.can_proceed)
        blocked_count = sum(1 for s in sse_results if not s.can_proceed)

        # Build options string
        options_str = ""
        letters = ["A", "B", "C", "D", "E", "F"]
        for i, opt in enumerate(scored_options[:5]):
            letter = letters[i] if i < len(letters) else str(i + 1)
            sse_v = opt.get("sse_verdict", "unknown")
            risk = opt.get("risk_exposure", "unknown")

            safety_indicator = {
                "EXECUTE": "✅",
                "CAUTION": "⚠️ ",
                "BLOCK": "❌",
            }.get(sse_v, "? ")

            options_str += f"  [{letter}] **{opt['action'].replace('_', ' ').title()}** on `{opt['target']}`\n"
            options_str += f"       RSEM: {opt['score']:.0f}/100 ({opt['tier']}) | SSE: {sse_v} ({opt.get('safety_impact_score', 0):.0f}/100 impact)\n"
            if opt.get("safety_warnings"):
                for w in opt["safety_warnings"][:2]:
                    options_str += f"       {w[:80]}\n"
            options_str += f"       Blast: {opt.get('safety_impact_score', 0):.0f}/100 | Risk: {risk}\n"

        # Build NCE summary
        nce_str = f"{primary.label} (MITRE: {primary.tactic_id or 'unmapped'}"
        if primary.technique_ids:
            nce_str += f" → {', '.join(primary.technique_ids[:2])}"
        nce_str += f") — {primary.confidence:.0%} confidence"

        # Build uncertainty gaps
        gaps = nce_result.uncertainty_gaps or []
        gaps_str = ", ".join(gaps[:3]) if gaps else "None identified"

        # Build action safety summary
        action_summary = f"{safe_count} safe to execute, {blocked_count} requires analyst review"

        panel = f"""
🚨 INCIDENT: {alert.rule_name}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Alert ID:** `{alert.alert_id}`  |  **{severity}**  |  {triage['category'].upper().replace('_', ' ')}
**Investigation:** `{triage['investigation_id']}`
**Affected:** `{alert.affected_asset}` ← `{alert.source_ip or 'unknown'}`
**User:** {alert.user or 'unknown'} | **MITRE:** {nce_str}
**NCE Primary:** {primary.label[:70]}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Here's what I know:**
• Source: `{alert.source_ip}` → `{alert.dest_ip or alert.affected_asset}`:{alert.dest_port}
• Rule: {alert.rule_name}
• Category: {triage['category']} | Dedup hash: {triage['dedup_hash'][:8]}

**Here's what I think (NCE):**
• Primary: {primary.narrative[:100]}...
• Evidence: {', '.join(primary.evidence[:3]) if primary.evidence else 'inconclusive'}
• Phase: {primary.attack_phase}

**Here's where I'm uncertain:**
• {gaps_str}

**Response options (RSEM scored + SSE safety-validated):**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{options_str}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Action safety summary: {action_summary}
🔒 All options require analyst HITL approval before execution

**What's your call?** Type [A], [B], [C], or describe your own action.
_Analyst review | {datetime.utcnow().strftime('%H:%M:%S')} UTC | Pipeline: {nce_result.generated_at[:19]}Z_
"""
        return panel.strip()


# ─────────────────────────────────────────────────────────────────
# Demo Runner
# ─────────────────────────────────────────────────────────────────

def run_demo(category: str = "brute_force"):
    """Run a full pipeline demo."""
    logger.info(f"🍀 SOCConversation — Full Pipeline Demo: {category}")

    scenario = DEMO_SCENARIOS.get(category, DEMO_SCENARIOS["brute_force"])

    alert = SOCAlert(
        alert_id=scenario["alert_id_override"],
        source=scenario["source"],
        source_ref=scenario["source_ref"],
        rule_name=scenario["rule_name"],
        description=scenario["description"],
        severity=AlertSeverity(scenario["severity"]),
        category=AlertCategory(scenario["category"]),
        affected_asset=scenario["affected_asset"],
        source_ip=scenario["source_ip"],
        dest_ip=scenario["dest_ip"],
        dest_port=scenario["dest_port"],
        protocol=scenario["protocol"],
        user=scenario.get("user"),
        filename=scenario.get("filename"),
        hash=scenario.get("hash"),
        domain=scenario.get("domain"),
        raw_log=scenario["raw_log"],
    )

    # Run pipeline
    pipeline = SOCPipeline(enable_postgres=False)
    result = pipeline.run_full_pipeline(alert)

    # Print results
    print("\n" + "=" * 70)
    print(f"🍀 SOCConversation — Full Pipeline Demo ({category.upper()})")
    print("=" * 70)

    print(f"\n📊 Pipeline Metrics")
    print(f"   Total time: {result['total_ms']:.0f}ms")
    for s in result["steps"]:
        print(f"   {s['step']:>12}: {s['ms']:>6.0f}ms")

    print(f"\n📋 NCE Result")
    primary = result["nce_result"].primary_hypothesis
    print(f"   Primary: [{primary.confidence:.0%}] {primary.label}")
    print(f"   MITRE: {primary.tactic_id or 'unmapped'} → {primary.technique_ids}")
    print(f"   Impact: {primary.estimated_impact}")
    print(f"   Response tier: {result['nce_result'].recommended_response_tier}")

    print(f"\n📊 RSEM + SSE Scored Options ({len(result['scored_options'])} options)")
    for i, opt in enumerate(result["scored_options"][:5], 1):
        print(f"   {i}. {opt['action']}: RSEM={opt['score']:.0f}/100 ({opt['tier']}) | SSE verdict={opt.get('sse_verdict', '?')}")

    print(f"\n{'='*70}")
    print("📋 HITL RECOMMENDATION PANEL")
    print("=" * 70)
    print(result["hitl_panel"])

    return result


def run_consumer(max_alerts: int = None):
    """Start the Lead Agent as a Kafka consumer."""
    logger.info("🚀 Starting SOCConversation as Kafka consumer...")
    from soc.agents.soc_lead_agent import SOCLeadAgent
    agent = SOCLeadAgent(
        enable_postgres=False,
        enable_kafka_consumer=True,
        analyst_name="SOCAnalyst",
    )
    agent.run(max_alerts=max_alerts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCConversation Pipeline")
    parser.add_argument("--demo", action="store_true", help="Run full pipeline demo")
    parser.add_argument("--category", default="brute_force",
                        choices=list(DEMO_SCENARIOS.keys()),
                        help="Demo scenario category")
    parser.add_argument("--consumer", action="store_true", help="Run as Kafka consumer")
    parser.add_argument("--max-alerts", type=int, default=None,
                        help="Max alerts to process (consumer mode)")

    args = parser.parse_args()

    if args.consumer:
        run_consumer(max_alerts=args.max_alerts)
    elif args.demo:
        run_demo(category=args.category)
    else:
        run_demo(category="brute_force")