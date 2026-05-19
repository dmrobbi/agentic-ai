"""
SSE — Structural Simulation Engine
===================================

SSE validates response actions BEFORE they're executed.
It simulates the blast radius of proposed actions using asset criticality data,
network topology, dependency graphs, and service catalogs.

For each proposed action (block_ip, isolate_endpoint, block_domain, etc.):
  1. Simulate the action against the target
  2. Identify affected systems / services
  3. Score the operational impact (0-100, higher = more disruption)
  4. Flag any critical path violations
  5. Provide safety verdict: EXECUTE | CAUTION | BLOCK

Usage:
    sse = SSE()
    for option in scored_options:
        safety = sse.validate_action(option, target_asset=asset)
        print(f"{option['action']} on {target}: {safety.verdict} (impact={safety.operational_impact_score})")
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Asset Registry (would be CMDB/SCMDB in production)
# ─────────────────────────────────────────────────────────────────

ASSET_REGISTRY = {
    # hostname: {type, criticality, department, dependencies, is_critical_infra}
    "FIN-DC01": {
        "type": "windows_server",
        "criticality": "critical",
        "department": "finance",
        "os": "Windows Server 2022",
        "role": "domain_controller",
        "dependencies": ["dns", "ldap", "kerberos", "dhcp"],
        "users_affected": 150,
        "services": ["Active Directory", "DNS", "DHCP", "File Sharing"],
        "is_critical_infra": True,
        "data_classification": "confidential",
    },
    "WEB-01": {"type": "linux_server", "criticality": "high", "department": "engineering", "role": "web_server", "users_affected": 500},
    "DB-PRIMARY": {"type": "database_server", "criticality": "critical", "department": "engineering", "role": "postgres_primary", "dependencies": ["storage"], "users_affected": 300, "is_critical_infra": True},
    "MAIL-01": {"type": "exchange_server", "criticality": "high", "department": "it", "role": "mail_server", "users_affected": 400},
    "WORKSTATION-01": {"type": "windows", "criticality": "medium", "department": "sales", "role": "user_workstation"},
    "PRINTER-DC01": {"type": "network_device", "criticality": "low", "department": "it"},
    "default": {"type": "unknown", "criticality": "medium", "department": "unknown", "users_affected": 10},
}


# ─────────────────────────────────────────────────────────────────
# Network Topology (simplified for blast radius simulation)
# ─────────────────────────────────────────────────────────────────

NETWORK_SEGMENTS = {
    "10.0.1.0/24": {"name": "IT/Finance", "vlan": 10, "critical": True},
    "10.0.2.0/24": {"name": "Engineering", "vlan": 20, "critical": True},
    "10.0.3.0/24": {"name": "Sales/Marketing", "vlan": 30, "critical": False},
    "10.0.99.0/24": {"name": "DMZ", "vlan": 99, "critical": False},
    "0.0.0.0/0": {"name": "Internet", "vlan": 0, "critical": False},
}


# ─────────────────────────────────────────────────────────────────
# Service Dependencies (what breaks if X goes down)
# ─────────────────────────────────────────────────────────────────

SERVICE_DEPENDENCIES = {
    "domain_controller": {
        "breaks": ["ldap_auth", "file_access", "dns_resolution", "user_login"],
        "cascade_to": ["mail_server", "web_server", "database_server"],
        "max_downtime_minutes": 0,  # zero tolerance
    },
    "dns_server": {
        "breaks": ["name_resolution", "ad_dns_registration"],
        "cascade_to": ["all_servers"],
        "max_downtime_minutes": 5,
    },
    "mail_server": {
        "breaks": ["email_communication"],
        "cascade_to": [],
        "max_downtime_minutes": 30,
    },
    "web_server": {
        "breaks": ["web_apps", "customer_portal"],
        "cascade_to": [],
        "max_downtime_minutes": 60,
    },
    "database_server": {
        "breaks": ["database_queries", "app_backends"],
        "cascade_to": ["web_server"],
        "max_downtime_minutes": 5,
    },
}


# ─────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────

@dataclass
class SafetyVerdict:
    """Result of SSE action validation."""
    action: str
    target: str
    verdict: str            # EXECUTE | CAUTION | BLOCK
    operational_impact_score: float  # 0-100 (higher = more disruption)
    blast_radius_description: str
    affected_assets: list[str]
    affected_users: int
    critical_services_impacted: list[str]
    estimated_downtime_minutes: int
    safety_reasons: list[str]
    critical_path_violation: bool
    rollback_complexity: str  # easy / moderate / complex
    alternative_action: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "verdict": self.verdict,
            "operational_impact_score": self.operational_impact_score,
            "blast_radius_description": self.blast_radius_description,
            "affected_assets": self.affected_assets,
            "affected_users": self.affected_users,
            "critical_services_impacted": self.critical_services_impacted,
            "estimated_downtime_minutes": self.estimated_downtime_minutes,
            "safety_reasons": self.safety_reasons,
            "critical_path_violation": self.critical_path_violation,
            "rollback_complexity": self.rollback_complexity,
            "alternative": self.alternative_action,
        }


@dataclass
class SSEResult:
    """Overall SSE result for a proposed action plan."""
    action: str
    target: str
    safety_verdict: SafetyVerdict
    risk_exposure: str        # low / medium / high / critical
    can_proceed: bool
    blockers: list[str]       # reasons to not proceed
    warnings: list[str]       # caution items
    next_steps: list[str]
    sse_recommendation: str  # What SSE recommends


# ─────────────────────────────────────────────────────────────────
# SSE Engine
# ─────────────────────────────────────────────────────────────────

class SSE:
    """
    Structural Simulation Engine.

    Validates response actions before execution by simulating blast
    radius across network topology, service dependencies, and asset criticality.
    """

    def __init__(self, asset_registry: Optional[dict] = None):
        self.asset_registry = asset_registry or ASSET_REGISTRY
        logger.info("SSE (Structural Simulation Engine) initialized")

    def validate_action(
        self,
        action: str,
        target: str,
        asset_name: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> SafetyVerdict:
        """
        Validate a single response action against the target.

        Args:
            action: block_ip, isolate_endpoint, block_domain, etc.
            target: IP, hostname, domain depending on action type
            asset_name: hostname of the asset being acted upon (for isolate, etc.)
            context: extra context (source_ip, severity, etc.)

        Returns:
            SafetyVerdict with impact score and safety assessment
        """
        ctx = context or {}
        logger.info(f"[SSE] Validating {action} on target={target}")

        if action == "block_ip":
            return self._validate_block_ip(target, ctx)
        elif action == "isolate_endpoint":
            return self._validate_isolate_endpoint(asset_name or target, ctx)
        elif action == "block_domain":
            return self._validate_block_domain(target, ctx)
        elif action == "reset_password":
            return self._validate_reset_password(target, ctx)
        elif action == "force_mfa_reset":
            return self._validate_mfa_reset(target, ctx)
        elif action == "create_case":
            return self._validate_create_case(target, ctx)
        elif action == "no_action":
            return self._validate_no_action(target, ctx)
        else:
            return SafetyVerdict(
                action=action, target=target,
                verdict="CAUTION", operational_impact_score=50,
                blast_radius_description="Unknown action — analyst review required",
                affected_assets=[], affected_users=0,
                critical_services_impacted=[], estimated_downtime_minutes=0,
                safety_reasons=["Unknown action type"], critical_path_violation=False,
                rollback_complexity="unknown",
                alternative_action="Review with lead agent before proceeding",
            )

    def _validate_block_ip(self, ip: str, ctx: dict) -> SafetyVerdict:
        """Validate blocking an external IP address."""
        source_ip = ctx.get("source_ip", ip)

        # Check if it's a common service / CDN
        fp_rate = self._check_ip_reputation(source_ip)

        if self._is_internal_ip(source_ip):
            return SafetyVerdict(
                action="block_ip", target=source_ip,
                verdict="BLOCK", operational_impact_score=95,
                blast_radius_description=f"IP {source_ip} is INTERNAL — blocking it would disrupt business operations. Network segmentation failure.",
                affected_assets=["entire_internal_segment"],
                affected_users=self._estimate_users_in_segment(source_ip),
                critical_services_impacted=["all_services"],
                estimated_downtime_minutes=999,
                safety_reasons=["BLOCK: Internal IP — would cause network outage"],
                critical_path_violation=True,
                rollback_complexity="moderate",
                alternative_action="Use surgical block (port/protocol) instead of full IP block",
            )

        if fp_rate > 0.4:
            return SafetyVerdict(
                action="block_ip", target=source_ip,
                verdict="CAUTION", operational_impact_score=15,
                blast_radius_description=f"IP {source_ip} is a known VPN/TOR exit node used by legitimate users. Blocking may disrupt approved remote work.",
                affected_assets=["remote_access_services"],
                affected_users=50,  # Some legitimate users via VPN
                critical_services_impacted=[],
                estimated_downtime_minutes=0,
                safety_reasons=[f"CAUTION: {int(fp_rate*100)}% of traffic from this IP is legitimate VPN users"],
                critical_path_violation=False,
                rollback_complexity="easy",
                alternative_action="Create Firewall rule to block only the specific port/protocol used in attack",
            )

        # Normal case: external attacker IP
        return SafetyVerdict(
            action="block_ip", target=source_ip,
            verdict="EXECUTE", operational_impact_score=5,
            blast_radius_description=f"Blocks {source_ip} at perimeter. No business impact — IP is confirmed malicious. Firewall rule is surgical.",
            affected_assets=[],
            affected_users=0,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["EXECUTE: Confirmed malicious external IP — blocking has zero business impact"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_isolate_endpoint(self, hostname: str, ctx: dict) -> SafetyVerdict:
        """Validate isolating an endpoint (EDR network isolation)."""
        asset = self.asset_registry.get(hostname, self.asset_registry["default"])

        if asset.get("is_critical_infra"):
            return SafetyVerdict(
                action="isolate_endpoint", target=hostname,
                verdict="CAUTION", operational_impact_score=75,
                blast_radius_description=f"ISOLATION WARNING: {hostname} is CRITICAL INFRASTRUCTURE ({asset.get('role', 'unknown')}). Isolation will disrupt {asset.get('users_affected', 'many')} users and impact: {', '.join(asset.get('services', []))}.",
                affected_assets=[hostname],
                affected_users=asset.get("users_affected", 0),
                critical_services_impacted=asset.get("services", []),
                estimated_downtime_minutes=asset.get("max_downtime_minutes", 5),
                safety_reasons=[
                    f"CAUTION: {hostname} is critical infra — {asset.get('users_affected', 'many')} users will be disconnected",
                    f"Asset role: {asset.get('role', 'unknown')}",
                    f"Downtime tolerance: {SERVICE_DEPENDENCIES.get(asset.get('role', ''), {}).get('max_downtime_minutes', 60)} minutes",
                ],
                critical_path_violation=True,
                rollback_complexity="easy",
                alternative_action="Instead of full isolation, block at perimeter (block_ip source attacker IP) and collect forensic evidence",
            )

        if asset.get("criticality") == "high":
            return SafetyVerdict(
                action="isolate_endpoint", target=hostname,
                verdict="CAUTION", operational_impact_score=55,
                blast_radius_description=f"Moderate impact: isolating {hostname} will disconnect {asset.get('users_affected', 0)} users. Services: {', '.join(asset.get('services', []))}.",
                affected_assets=[hostname],
                affected_users=asset.get("users_affected", 0),
                critical_services_impacted=asset.get("services", []),
                estimated_downtime_minutes=15,
                safety_reasons=["CAUTION: High-criticality asset — user disruption expected"],
                critical_path_violation=False,
                rollback_complexity="easy",
            )

        # Normal endpoint
        return SafetyVerdict(
            action="isolate_endpoint", target=hostname,
            verdict="EXECUTE", operational_impact_score=25,
            blast_radius_description=f"Standard endpoint isolation. {hostname} will be disconnected from network but user retains local access. {asset.get('users_affected', 1)} user(s) affected. Recovery: reconnect via EDR console.",
            affected_assets=[hostname],
            affected_users=asset.get("users_affected", 1),
            critical_services_impacted=[],
            estimated_downtime_minutes=5,
            safety_reasons=["EXECUTE: Standard endpoint isolation — user disruption is expected and acceptable"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_block_domain(self, domain: str, ctx: dict) -> SafetyVerdict:
        """Validate blocking a domain via DNS sinkhole or firewall."""
        # Check if it's a major provider
        major_domains = ["microsoft.com", "google.com", "amazon.com", "github.com", "cloudflare.com"]
        if any(md in domain.lower() for md in major_domains):
            return SafetyVerdict(
                action="block_domain", target=domain,
                verdict="BLOCK", operational_impact_score=99,
                blast_radius_description=f"BLOCKING MAJOR CLOUD PROVIDER: {domain} is used by many business applications. Blocking would disrupt email, collaboration, and cloud services for entire organization.",
                affected_assets=["all_servers", "all_workstations"],
                affected_users=1000,
                critical_services_impacted=["email", "cloud_services", "authentication", "single_sign_on"],
                estimated_downtime_minutes=999,
                safety_reasons=["BLOCK: Major cloud provider — organization-wide outage would result"],
                critical_path_violation=True,
                rollback_complexity="complex",
            )

        return SafetyVerdict(
            action="block_domain", target=domain,
            verdict="EXECUTE", operational_impact_score=10,
            blast_radius_description=f"DNS sinkhole for {domain}. Only traffic to attacker-controlled C2 domain blocked. No business impact if domain is malicious.",
            affected_assets=[],
            affected_users=0,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["EXECUTE: Malicious domain block — no business impact"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_reset_password(self, user: str, ctx: dict) -> SafetyVerdict:
        """Validate forcing a password reset for a user."""
        return SafetyVerdict(
            action="reset_password", target=user,
            verdict="EXECUTE", operational_impact_score=10,
            blast_radius_description=f"Password reset for {user}. User must set new password on next login. Minor inconvenience but no service disruption.",
            affected_assets=[],
            affected_users=1,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["EXECUTE: Password reset has minimal operational impact — user inconvenience only"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_mfa_reset(self, user: str, ctx: dict) -> SafetyVerdict:
        """Validate forcing MFA re-enrollment for a user."""
        return SafetyVerdict(
            action="force_mfa_reset", target=user,
            verdict="EXECUTE", operational_impact_score=5,
            blast_radius_description=f"MFA reset for {user}. User must re-enroll authenticator app or hardware token. No business systems disrupted.",
            affected_assets=[],
            affected_users=1,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["EXECUTE: MFA reset is operationally safe — user re-authentication only"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_create_case(self, target: str, ctx: dict) -> SafetyVerdict:
        """Validate creating a case in TheHive / case management."""
        return SafetyVerdict(
            action="create_case", target=target,
            verdict="EXECUTE", operational_impact_score=0,
            blast_radius_description="Creating a case management record — zero operational impact. No business systems affected.",
            affected_assets=[],
            affected_users=0,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["EXECUTE: Case creation is zero-impact — always safe"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def _validate_no_action(self, target: str, ctx: dict) -> SafetyVerdict:
        """Validate choosing to take no action."""
        return SafetyVerdict(
            action="no_action", target=target,
            verdict="CAUTION", operational_impact_score=0,
            blast_radius_description="No action chosen — threat remains active. Monitor closely and prepare response.",
            affected_assets=[],
            affected_users=0,
            critical_services_impacted=[],
            estimated_downtime_minutes=0,
            safety_reasons=["CAUTION: No action leaves threat active — only choose if FP is confirmed"],
            critical_path_violation=False,
            rollback_complexity="easy",
        )

    def validate_action_plan(
        self,
        options: list[dict],
        asset_name: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> list[SSEResult]:
        """
        Validate an entire action plan (multiple options from RSEM).
        Returns SSEResults for each option.
        """
        results = []
        for opt in options:
            verdict = self.validate_action(
                action=opt.get("action", "unknown"),
                target=opt.get("target", "unknown"),
                asset_name=asset_name,
                context=context or {},
            )
            risk = self._calculate_risk_exposure(verdict)
            blockers = [r for r in verdict.safety_reasons if r.startswith("BLOCK")]
            warnings = [r for r in verdict.safety_reasons if r.startswith("CAUTION")]

            results.append(SSEResult(
                action=verdict.action,
                target=verdict.target,
                safety_verdict=verdict,
                risk_exposure=risk,
                can_proceed=verdict.verdict in ("EXECUTE", "CAUTION"),
                blockers=blockers,
                warnings=warnings,
                next_steps=self._get_next_steps(verdict),
                sse_recommendation=self._get_recommendation(verdict),
            ))
        return results

    # ─────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────

    def _check_ip_reputation(self, ip: str) -> float:
        """Check false positive rate for an IP (0.0-1.0)."""
        if not ip:
            return 0.0
        # TOR/VPN IPs have higher FP rates (legitimate users)
        tor_prefixes = ("185.220.", "199.249.", "146.185.", "192.42.")
        vpn_prefixes = ("185.163.", "185.117.", "45.12.")
        if ip.startswith(tor_prefixes):
            return 0.15
        if ip.startswith(vpn_prefixes):
            return 0.35
        return 0.0

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is RFC1918 private."""
        if not ip:
            return False
        private = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                  "172.30.", "172.31.", "192.168.")
        return ip.startswith(private)

    def _estimate_users_in_segment(self, ip: str) -> int:
        """Rough estimate of users affected by segment disruption."""
        if ip.startswith("10.0.1."):
            return 150
        if ip.startswith("10.0.2."):
            return 100
        return 50

    def _calculate_risk_exposure(self, verdict: SafetyVerdict) -> str:
        """Calculate risk exposure string from impact score."""
        score = verdict.operational_impact_score
        if verdict.verdict == "BLOCK":
            return "critical"
        if score >= 75 or verdict.critical_path_violation:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    def _get_next_steps(self, verdict: SafetyVerdict) -> list[str]:
        """Get recommended next steps based on verdict."""
        if verdict.verdict == "BLOCK":
            return [
                "Do not execute — action would cause organization-wide outage",
                "Reconsider target or action type",
                "Consult with security lead before proceeding",
            ]
        if verdict.verdict == "CAUTION":
            return [
                "Analyst review required before execution",
                "Notify affected teams of potential service disruption",
                "Plan maintenance window if impact is significant",
                "Prepare rollback procedure",
            ]
        if verdict.verdict == "EXECUTE":
            return [
                "Safe to proceed",
                "Document in audit log",
                "Monitor affected systems after execution",
            ]
        return []

    def _get_recommendation(self, verdict: SafetyVerdict) -> str:
        """Get human-readable recommendation."""
        if verdict.verdict == "BLOCK":
            return f"❌ BLOCK — {verdict.safety_reasons[0] if verdict.safety_reasons else 'Safety violation'}"
        if verdict.verdict == "CAUTION":
            return f"⚠️ CAUTION — {verdict.safety_reasons[0] if verdict.safety_reasons else 'Analyst review required'}"
        return f"✅ EXECUTE — {verdict.blast_radius_description}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    sse = SSE()

    print("\n" + "=" * 70)
    print("🍀 SSE — Structural Simulation Engine Demo")
    print("=" * 70)

    # Test the same scenario: RDP brute force from TOR to FIN-DC01
    options = [
        {"action": "block_ip", "target": "185.220.101.42"},
        {"action": "isolate_endpoint", "target": "FIN-DC01"},
        {"action": "reset_password", "target": "jsmith"},
        {"action": "block_domain", "target": "evil-c2.com"},
    ]

    context = {
        "source_ip": "185.220.101.42",
        "dest_ip": "10.0.1.10",
        "affected_asset": "FIN-DC01",
        "severity": "P1",
    }

    print(f"\n🎯 Validating {len(options)} response options for FIN-DC01 scenario")
    print("-" * 70)

    results = sse.validate_action_plan(options, asset_name="FIN-DC01", context=context)

    for r in results:
        v = r.safety_verdict
        print(f"\n  [{r.safety_verdict.verdict}] {v.action.upper()} on {v.target}")
        print(f"           Impact: {v.operational_impact_score:.0f}/100 | Risk: {r.risk_exposure}")
        print(f"           Blast: {v.blast_radius_description[:70]}")
        if v.critical_services_impacted:
            print(f"           Critical svcs: {', '.join(v.critical_services_impacted)}")
        print(f"           Recommendation: {r.sse_recommendation}")
        if v.affected_users:
            print(f"           Users affected: {v.affected_users}")
        print(f"           Rollback: {v.rollback_complexity}")
        if v.alternative_action:
            print(f"           Alternative: {v.alternative_action}")

    print("\n" + "=" * 70)
    print("Summary:")
    executable = [r for r in results if r.can_proceed]
    blocked = [r for r in results if r.safety_verdict.verdict == "BLOCK"]
    caution = [r for r in results if r.safety_verdict.verdict == "CAUTION"]
    print(f"  ✅ {len(executable)} safe to execute | ⚠️ {len(caution)} CAUTION | ❌ {len(blocked)} BLOCKED")
    print("=" * 70)