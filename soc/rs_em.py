"""
RSEM — Risk Scoring and Evaluation Module
==========================================

RSEM scores response options based on four factors:
  - containment_effectiveness: 35% — Will the action actually stop the threat?
  - business_impact: 30% — What is the operational impact if action executes?
  - execution_risk: 20% — What can go wrong during execution?
  - reversibility: 15% — Can we easily undo this if it was a mistake?

Each option gets a 0-100 score. Options are ranked and tiered:
  - P1: 80-100 — Immediate action recommended
  - P2: 60-79 — Strong action candidate
  - P3: 40-59 — Consider action, may need planning
  - P4: 0-39 — Document and monitor only

RSEM is complementary to SSE:
  - RSEM scores effectiveness (how well does this stop the threat?)
  - SSE scores safety (what's the blast radius if we mess up?)
  Both must pass for an action to be auto-executable.
  For P1/P2, analyst HITL is always required regardless of scores.

Usage:
    rsem = RSEM()
    options = [
        {"action": "block_ip", "target": "185.220.101.42", "description": "Block attacker IP"},
        {"action": "isolate_endpoint", "target": "FIN-DC01", "description": "Isolate domain controller"},
    ]
    scored = rsem.score_options(options, severity="P2")
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Action factor templates
# ─────────────────────────────────────────────────────────────────

ACTION_FACTORS = {
    # action: (containment_effectiveness, business_impact, execution_risk, reversibility)
    #   0.0 = none/minimal, 1.0 = perfect/maximum
    "block_ip": {
        "containment_effectiveness": 0.90,
        "business_impact": 0.05,
        "execution_risk": 0.05,
        "reversibility": 0.95,
        "description": "Block external malicious IP at perimeter firewall",
    },
    "isolate_endpoint": {
        "containment_effectiveness": 0.95,
        "business_impact": 0.40,
        "execution_risk": 0.10,
        "reversibility": 0.80,
        "description": "Isolate endpoint via EDR network isolation",
    },
    "reset_password": {
        "containment_effectiveness": 0.60,
        "business_impact": 0.20,
        "execution_risk": 0.05,
        "reversibility": 0.90,
        "description": "Force password reset for compromised account",
    },
    "force_mfa_reset": {
        "containment_effectiveness": 0.70,
        "business_impact": 0.15,
        "execution_risk": 0.05,
        "reversibility": 0.95,
        "description": "Force MFA re-enrollment after potential compromise",
    },
    "block_domain": {
        "containment_effectiveness": 0.80,
        "business_impact": 0.10,
        "execution_risk": 0.05,
        "reversibility": 0.90,
        "description": "Block malicious C2 domain via DNS sinkhole",
    },
    "kill_process": {
        "containment_effectiveness": 0.85,
        "business_impact": 0.15,
        "execution_risk": 0.08,
        "reversibility": 0.85,
        "description": "Kill malicious process on endpoint",
    },
    "quarantine_file": {
        "containment_effectiveness": 0.75,
        "business_impact": 0.05,
        "execution_risk": 0.03,
        "reversibility": 0.95,
        "description": "Quarantine malicious file via EDR",
    },
    "create_case": {
        "containment_effectiveness": 0.20,
        "business_impact": 0.0,
        "execution_risk": 0.0,
        "reversibility": 1.0,
        "description": "Create case management record for tracking",
    },
    "escalate_human": {
        "containment_effectiveness": 0.30,
        "business_impact": 0.0,
        "execution_risk": 0.0,
        "reversibility": 1.0,
        "description": "Escalate to senior analyst for review",
    },
    "no_action": {
        "containment_effectiveness": 0.0,
        "business_impact": 0.0,
        "execution_risk": 0.0,
        "reversibility": 1.0,
        "description": "No action — monitor and document only",
    },
}

# Severity multipliers
SEVERITY_MULTIPLIER = {
    "P1": 1.20,  # P1 alerts justify more aggressive response
    "P2": 1.10,
    "P3": 1.00,
    "P4": 0.90,
}

# Weights (sum to 1.0)
WEIGHTS = {
    "containment_effectiveness": 0.35,
    "business_impact": 0.30,
    "execution_risk": 0.20,
    "reversibility": 0.15,
}


# ─────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────

@dataclass
class ScoredOption:
    """A response option scored by RSEM."""
    action: str
    target: str
    description: str
    score: float          # 0-100
    tier: str            # P1/P2/P3/P4
    factors: dict        # {factor: value}
    weighted_score_breakdown: dict
    containment_score: float
    business_impact_score: float
    execution_risk_score: float
    reversibility_score: float
    blast_radius: str
    reasoning: str
    rank: int = 0
    is_auto_executable: bool = False  # True only if score >= 80 AND not P1/P2

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "score": round(self.score, 1),
            "tier": self.tier,
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "containment_score": round(self.containment_score, 1),
            "business_impact_score": round(self.business_impact_score, 1),
            "execution_risk_score": round(self.execution_risk_score, 1),
            "reversibility_score": round(self.reversibility_score, 1),
            "blast_radius": self.blast_radius,
            "reasoning": self.reasoning,
            "rank": self.rank,
            "is_auto_executable": self.is_auto_executable,
        }


@dataclass
class RSEMResult:
    """Overall RSEM assessment for an alert."""
    alert_id: str
    severity: str
    category: str
    options: list[ScoredOption]
    recommended_primary: ScoredOption
    recommended_secondary: Optional[ScoredOption]
    hitl_required: bool  # True if P1/P2 or recommended_primary score < 80
    auto_executable_count: int
    top_tier: str        # "P1", "P2", etc.

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity,
            "category": self.category,
            "recommended_primary": self.recommended_primary.to_dict(),
            "recommended_secondary": self.recommended_secondary.to_dict() if self.recommended_secondary else None,
            "hitl_required": self.hitl_required,
            "auto_executable_count": self.auto_executable_count,
            "options": [o.to_dict() for o in self.options],
            "top_tier": self.top_tier,
        }


# ─────────────────────────────────────────────────────────────────
# RSEM Engine
# ─────────────────────────────────────────────────────────────────

class RSEM:
    """
    Risk Scoring and Evaluation Module.

    Scores response options based on:
      - Containment effectiveness (35%)
      - Business impact (30%)
      - Execution risk (20%)
      - Reversibility (15%)

    For P1/P2 alerts, HITL is always required.
    For P3/P4, auto-execution is possible if RSEM score >= 80.
    """

    def __init__(self):
        logger.info("RSEM (Risk Scoring and Evaluation Module) initialized")

    def score_options(
        self,
        options: list[dict],
        severity: str = "P3",
        category: str = "unknown",
    ) -> list[dict]:
        """
        Score a list of response options.
        Returns list of scored option dicts sorted by score descending.

        Args:
            options: [{"action": "...", "target": "...", "description": "..."}]
            severity: P1/P2/P3/P4
            category: alert category for contextual adjustments

        Returns:
            List of scored option dicts with RSEM scores, tiers, reasoning
        """
        if severity not in SEVERITY_MULTIPLIER:
            severity = "P3"

        multiplier = SEVERITY_MULTIPLIER[severity]

        scored = []
        for opt in options:
            action = opt.get("action", "unknown")
            target = opt.get("target", "unknown")

            # Get base factors
            factors = ACTION_FACTORS.get(action, {
                "containment_effectiveness": 0.50,
                "business_impact": 0.30,
                "execution_risk": 0.20,
                "reversibility": 0.50,
            })

            # Calculate raw RSEM score
            # Note: business_impact and execution_risk are scored as NEGATIVE
            # (higher = worse), so we invert them for the score
            ce = factors["containment_effectiveness"]
            bi = factors["business_impact"]
            er = factors["execution_risk"]
            rev = factors["reversibility"]

            raw_score = (
                ce * WEIGHTS["containment_effectiveness"]
                + (1 - bi) * WEIGHTS["business_impact"]  # invert: low BI = good
                + (1 - er) * WEIGHTS["execution_risk"]   # invert: low ER = good
                + rev * WEIGHTS["reversibility"]
            )

            # Apply severity multiplier
            final_score = min(100.0, max(0.0, round(raw_score * multiplier * 100, 1)))

            # Determine tier
            if final_score >= 80:
                tier = "P1"
            elif final_score >= 60:
                tier = "P2"
            elif final_score >= 40:
                tier = "P3"
            else:
                tier = "P4"

            # Blast radius description
            blast = self._blast_radius(action, target)

            # Reasoning
            reasoning = self._build_reasoning(action, factors, severity, final_score)

            # Containment/Business/Execution/Reversibility individual scores
            containment_score = round(ce * 100, 1)
            business_impact_score = round((1 - bi) * 100, 1)  # inverted
            execution_risk_score = round((1 - er) * 100, 1)   # inverted
            reversibility_score = round(rev * 100, 1)

            # Auto-executable? Only if score >= 80 AND not P1/P2
            is_auto = final_score >= 80 and tier not in ("P1", "P2")

            scored.append({
                "action": action,
                "target": target,
                "description": opt.get("description", ""),
                "score": final_score,
                "tier": tier,
                "factors": factors,
                "containment_score": containment_score,
                "business_impact_score": business_impact_score,
                "execution_risk_score": execution_risk_score,
                "reversibility_score": reversibility_score,
                "blast_radius": blast,
                "reasoning": reasoning,
                "is_auto_executable": is_auto,
            })

        # Sort by score descending and assign ranks
        scored.sort(key=lambda x: x["score"], reverse=True)
        for i, opt in enumerate(scored):
            opt["rank"] = i + 1

        return scored

    def score_options_full(
        self,
        options: list[dict],
        severity: str = "P3",
        category: str = "unknown",
    ) -> RSEMResult:
        """
        Full RSEM result with all options and recommendations.
        """
        scored_dicts = self.score_options(options, severity, category)

        # Convert to ScoredOption dataclasses
        scored = []
        for d in scored_dicts:
            scored.append(ScoredOption(
                action=d["action"],
                target=d["target"],
                description=d["description"],
                score=d["score"],
                tier=d["tier"],
                factors=d["factors"],
                weighted_score_breakdown={},
                containment_score=d["containment_score"],
                business_impact_score=d["business_impact_score"],
                execution_risk_score=d["execution_risk_score"],
                reversibility_score=d["reversibility_score"],
                blast_radius=d["blast_radius"],
                reasoning=d["reasoning"],
                rank=d["rank"],
                is_auto_executable=d["is_auto_executable"],
            ))

        primary = scored[0] if scored else None
        secondary = scored[1] if len(scored) > 1 else None
        auto_count = sum(1 for o in scored if o.is_auto_executable)

        # HITL required for P1/P2 OR if primary score < 80
        hitl_required = (severity in ("P1", "P2")) or (primary.score < 80 if primary else True)

        return RSEMResult(
            alert_id="",
            severity=severity,
            category=category,
            options=scored,
            recommended_primary=primary,
            recommended_secondary=secondary,
            hitl_required=hitl_required,
            auto_executable_count=auto_count,
            top_tier=primary.tier if primary else "P4",
        )

    def _blast_radius(self, action: str, target: str) -> str:
        """Generate blast radius description."""
        descriptions = {
            "block_ip": f"Blocks {target}. No blast radius if IP is attacker-only.",
            "isolate_endpoint": f"Affects users on {target}. Temporary network isolation.",
            "reset_password": "User inconvenience only. Re-authentication required.",
            "force_mfa_reset": "User must re-enroll MFA. Low operational impact.",
            "block_domain": f"Blocks {target}. May affect legitimate subdomain traffic.",
            "kill_process": "Terminates process. User may lose unsaved work.",
            "quarantine_file": "File quarantined. No user impact if not actively used.",
            "create_case": "No operational impact. Creates tracking record.",
            "no_action": "No impact — threat remains active.",
            "escalate_human": "No direct impact — routes to analyst queue.",
        }
        return descriptions.get(action, f"Action {action} on {target} — minimal impact expected.")

    def _build_reasoning(
        self,
        action: str,
        factors: dict,
        severity: str,
        final_score: float,
    ) -> str:
        """Generate human-readable reasoning for the score."""
        ce = factors["containment_effectiveness"]
        bi = factors["business_impact"]
        er = factors["execution_risk"]
        rev = factors["reversibility"]

        return (
            f"{action.replace('_', ' ').title()} at {severity} severity: "
            f"containment {ce:.0%}, business impact {(1-bi):.0%}, "
            f"execution risk {(1-er):.0%}, reversibility {rev:.0%}. "
            f"Final RSEM score: {final_score:.0f}/100."
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    rsem = RSEM()

    options = [
        {"action": "block_ip", "target": "185.220.101.42", "description": "Block TOR exit node at perimeter"},
        {"action": "isolate_endpoint", "target": "FIN-DC01", "description": "Isolate domain controller"},
        {"action": "reset_password", "target": "jsmith", "description": "Force password reset for user"},
        {"action": "create_case", "target": "ALR-2026-05-19-001", "description": "Create TheHive case"},
    ]

    print("\n" + "=" * 70)
    print("🍀 RSEM — Risk Scoring and Evaluation Module Demo")
    print("=" * 70)

    for severity in ["P1", "P2", "P3", "P4"]:
        result = rsem.score_options_full(options, severity=severity)
        print(f"\n📊 Severity: {severity} | HITL required: {result.hitl_required}")
        print(f"   Auto-executable: {result.auto_executable_count} options")
        print(f"   Top tier: {result.top_tier}")
        for o in result.options[:4]:
            auto_mark = " [AUTO]" if o.is_auto_executable else ""
            print(f"   [{o.rank}] {o.action}: {o.score:.0f}/100 ({o.tier}){auto_mark}")
            print(f"       CE={o.containment_score:.0f} | BI={o.business_impact_score:.0f} | ER={o.execution_risk_score:.0f} | R={o.reversibility_score:.0f}")
            print(f"       {o.blast_radius[:60]}...")

    print("\n" + "=" * 70)
    print("Key: CE=Containment Effectiveness, BI=Business Impact (inverted), ER=Execution Risk (inverted), R=Reversibility")
    print("      [AUTO] = auto-executable (RSEM>=80, not P1/P2)")
    print("=" * 70)