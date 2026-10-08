"""Sales Agent — CRM, productized pricing, proposals, pipeline forecasting.

Legacy CRM ops (backward-compatible names and result shapes):
    create_lead, qualify_lead, create_opportunity, generate_proposal,
    update_pipeline.

Profitability ops (deterministic, no external services required):
    price_book    — the service price book (single source, owner-tunable).
    quote         — build a quote: line items, MRR, one-time, year-1 total.
    pipeline_report — counts/totals/weighted pipeline + quote stats.
    forecast      — weighted pipeline grouped by close quarter.
    draft_outreach— personalized outreach email DRAFTS (touch 1-3 cadence).
    get_lead      — fetch one lead by id or email.

Persistence: when a real ``state_store`` is present, CRM state is loaded
lazily (first op after construction) and saved eagerly after every mutation
via ``save_agent_state``. Without a state store the agent is in-memory only
(mock state stores are tolerated and ignored). IDs are monotonic across
restarts: the sequence counter is rebuilt from the highest persisted id.

Draft-only rule: ``draft_outreach`` returns email drafts marked
``requires_owner_send`` — nothing is ever sent by this agent. SMTP or
CRM-suite credentials are deliberately out of scope.

Proposal numbers cite only measured fleet stats (PROOF_POINTS below) —
no invented marketing numbers.
"""

import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from agentic_ai.agents.base import BaseAgent, Permission

logger = logging.getLogger(__name__)


class LeadStatus:
    """Lead lifecycle status (string values kept stable for serialization)."""

    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    PROPOSAL = "proposal"
    NEGOTIATION = "negotiation"
    WON = "won"
    LOST = "lost"

    @classmethod
    def values(cls) -> List[str]:
        return [v for k, v in vars(cls).items() if k.isupper()]


# Opportunity pipeline stages and their default close probabilities.
STAGE_PROBABILITIES: Dict[str, float] = {
    "prospecting": 0.10,
    "qualified": 0.30,
    "proposal": 0.50,
    "negotiation": 0.75,
    "won": 1.00,
    "lost": 0.00,
}

# Legacy / alternate stage names normalized to the canonical set above.
STAGE_ALIASES: Dict[str, str] = {
    "qualification": "qualified",
    "pricing": "proposal",
    "closing": "negotiation",
    "close_won": "won",
    "close_lost": "lost",
}

VALID_STAGES = list(STAGE_PROBABILITIES.keys())

# Productized price book. Numbers are owner-tunable; structure is the contract.
# Anchors: recurring SOC/MDR pricing is per-endpoint with a platform base;
# compliance is sold productized (fixed prep + optional evidence watch);
# vCISO retainers tier by scope; the platform pilot is a fixed-fee engagement.
PRICING: Dict[str, Any] = {
    "soc_monitoring": {
        "label": "SOC monitoring (agentic, human-supervised)",
        "models": {"type": "tiered_per_endpoint"},
        "tiers": {
            "business_hours": {
                "label": "Business-hours SOC",
                "base_monthly": 1500.0,
                "per_endpoint_monthly": 12.0,
            },
            "24x7": {
                "label": "24x7 SOC",
                "base_monthly": 2800.0,
                "per_endpoint_monthly": 18.0,
            },
        },
    },
    "compliance": {
        "label": "Compliance productized packages",
        "models": {"type": "package"},
        "packages": {
            "soc2_prep": {
                "label": "SOC 2 prep program (evidence pipeline, audit-ready)",
                "one_time": 12000.0,
                "monthly": 0.0,
            },
            "stig_pipeline": {
                "label": "DISA STIG evidence pipeline (stig-baselines)",
                "one_time": 9500.0,
                "monthly": 2500.0,
            },
            "compliance_watch": {
                "label": "Continuous compliance evidence watch",
                "one_time": 0.0,
                "monthly": 1800.0,
            },
        },
    },
    "vciso": {
        "label": "vCISO retainer",
        "models": {"type": "tiered_flat"},
        "tiers": {
            "standard": {"label": "vCISO standard", "monthly": 3500.0,
                         "label_short": "vCISO standard"},
            "with_ir": {"label": "vCISO + incident-response retainer",
                        "monthly": 6500.0},
        },
    },
    "platform_pilot": {
        "label": "Agentic platform pilot",
        "models": {"type": "fixed_fee"},
        "tiers": {
            "six_week": {"label": "6-week supervised agentic pilot",
                         "one_time": 15000.0},
        },
    },
}

# Measured fleet proof points (published: capabilities page + Laya reports).
PROOF_POINTS: List[str] = [
    "Median alert decision 21s -> 1.2s after the deterministic gate + single local inference (measured over the live decision log)",
    "65% of decisions hitting a 90-second model ceiling -> 0",
    "74% less GPU energy per decision, 16x decision latency, 94.6% decision agreement over a 452-decision soak",
    "$0 per-alert model spend: the alert path runs on local hardware, bound to loopback",
    "Second-host replication (2026-09-28): the same 300-state eval on a "
    "second host - 1.6x faster, 100% identical answers, 20% less energy "
    "per decision",
]

CAPABILITIES_URL = "https://bedimsecurity.com/capabilities"
CONTACT_URL = "https://bedimsecurity.com/contact"

TIER_THRESHOLDS = (80.0, 60.0, 40.0)  # A, B, C; below C is D


@dataclass
class Lead:
    lead_id: str
    name: str
    company: str = ""
    email: str = ""
    status: str = LeadStatus.NEW
    score: float = 0.0
    value: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    notes: List[str] = field(default_factory=list)
    source: str = ""
    industry: str = ""
    endpoints: int = 0
    compliance_drivers: List[str] = field(default_factory=list)
    tier: str = ""
    touch_count: int = 0
    last_touched_at: Optional[datetime] = None


@dataclass
class Opportunity:
    opp_id: str
    title: str
    value: float = 0.0
    stage: str = "prospecting"
    probability: float = 0.10
    close_date: Optional[datetime] = None
    contact: str = ""
    lead_id: str = ""
    quote_id: str = ""
    quote_snapshot: Dict[str, Any] = field(default_factory=dict)
    updated_at: Optional[datetime] = None


class SalesAgent(BaseAgent):
    """Sales agent: CRM, BANT/ICP qualification, productized price book,
    quotes, proposals, pipeline forecasting, and draft-only outbound.
    Human-supervised; never sends anything unaided."""

    agent_type = "sales"
    permission = Permission.STANDARD

    def __init__(self, agent_id: Optional[str] = None, name: Optional[str] = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 crm_path: str = "/tmp/crm") -> None:
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.crm_path = crm_path  # kept for compatibility; persistence uses state_store
        self.leads: List[Lead] = []
        self.opportunities: List[Opportunity] = []
        self.quotes: List[Dict[str, Any]] = []
        self._seq: Dict[str, int] = {"lead": 0, "opp": 0, "quote": 0}
        self._loaded = False
        self._tools = {
            "create_lead": self.create_lead,
            "qualify_lead": self.qualify_lead,
            "create_opportunity": self.create_opportunity,
            "generate_proposal": self.generate_proposal,
            "update_pipeline": self.update_pipeline,
            "price_book": self.price_book,
            "quote": self.quote,
            "pipeline_report": self.pipeline_report,
            "forecast": self.forecast,
            "draft_outreach": self.draft_outreach,
            "get_lead": self.get_lead,
        }

    # ============================================
    # Persistence
    # ============================================

    def _ensure_loaded(self) -> None:
        """Load persisted CRM state once, if a real state store is attached."""
        if self._loaded or self.state_store is None:
            return
        self._loaded = True
        try:
            state = self.state_store.get_agent_state(self.agent_id)
        except Exception as exc:  # noqa: BLE001 - persistence must never break ops
            logger.warning("SalesAgent: load state failed, starting empty: %s", exc)
            return
        if not isinstance(state, dict) or "leads" not in state:
            return
        self._deserialize(state)

    def _persist(self) -> None:
        """Save CRM state; failures are logged and never fatal."""
        if self.state_store is None:
            return
        try:
            self.state_store.save_agent_state(self.agent_id, self.agent_type,
                                              self._serialize())
        except Exception as exc:  # noqa: BLE001
            logger.warning("SalesAgent: save state failed: %s", exc)

    def _serialize(self) -> Dict[str, Any]:
        return {
            "leads": [self._dump_lead(lead) for lead in self.leads],
            "opportunities": [self._dump_opp(opp) for opp in self.opportunities],
            "quotes": self.quotes,
            "seq": self._seq,
        }

    def _deserialize(self, state: Dict[str, Any]) -> None:
        seq = state.get("seq")
        self._seq = seq if isinstance(seq, dict) else {"lead": 0, "opp": 0, "quote": 0}
        self.leads = [self._load_lead(e) for e in state.get("leads", []) if isinstance(e, dict)]
        self.opportunities = [self._load_opp(e) for e in state.get("opportunities", []) if isinstance(e, dict)]
        self.quotes = [q for q in state.get("quotes", []) if isinstance(q, dict)]
        # Rebuild sequence counters from max persisted ids so ids stay unique
        # even if the stored seq disagrees with the records.
        for kind, prefix, records, attr in (
            ("lead", "LEAD-", self.leads, "lead_id"),
            ("opp", "OPP-", self.opportunities, "opp_id"),
            ("quote", "Q-", self.quotes, "quote_id"),
        ):
            max_seen = int(self._seq.get(kind, 0))
            for record in records:
                if isinstance(record, dict):
                    value = str(record.get(attr, ""))
                else:
                    value = str(getattr(record, attr, ""))
                if value.startswith(prefix):
                    try:
                        max_seen = max(max_seen, int(value[len(prefix):]))
                    except ValueError:
                        continue
            self._seq[kind] = max_seen

    @staticmethod
    def _dt(value: Any) -> Optional[datetime]:
        if value is None or isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            return None

    @classmethod
    def _dump_lead(cls, lead: Lead) -> Dict[str, Any]:
        data = asdict(lead)
        data["created_at"] = lead.created_at.isoformat()
        data["last_touched_at"] = lead.last_touched_at.isoformat() if lead.last_touched_at else None
        return data

    @classmethod
    def _load_lead(cls, data: Dict[str, Any]) -> Lead:
        return Lead(
            lead_id=data.get("lead_id", ""),
            name=data.get("name", ""),
            company=data.get("company", ""),
            email=data.get("email", ""),
            status=data.get("status", LeadStatus.NEW),
            score=float(data.get("score", 0.0) or 0.0),
            value=float(data.get("value", 0.0) or 0.0),
            created_at=cls._dt(data.get("created_at")) or datetime.now(),
            notes=list(data.get("notes", [])),
            source=data.get("source", ""),
            industry=data.get("industry", ""),
            endpoints=int(data.get("endpoints", 0) or 0),
            compliance_drivers=list(data.get("compliance_drivers", [])),
            tier=data.get("tier", ""),
            touch_count=int(data.get("touch_count", 0) or 0),
            last_touched_at=cls._dt(data.get("last_touched_at")),
        )

    @classmethod
    def _dump_opp(cls, opp: Opportunity) -> Dict[str, Any]:
        data = asdict(opp)
        data["close_date"] = opp.close_date.isoformat() if opp.close_date else None
        data["updated_at"] = opp.updated_at.isoformat() if opp.updated_at else None
        return data

    @classmethod
    def _load_opp(cls, data: Dict[str, Any]) -> Opportunity:
        stage = data.get("stage", "prospecting")
        if stage not in STAGE_PROBABILITIES:
            stage = STAGE_ALIASES.get(stage, "prospecting")
        return Opportunity(
            opp_id=data.get("opp_id", ""),
            title=data.get("title", ""),
            value=float(data.get("value", 0.0) or 0.0),
            stage=stage,
            probability=float(data.get("probability", STAGE_PROBABILITIES[stage]) or 0.0),
            close_date=cls._dt(data.get("close_date")),
            contact=data.get("contact", ""),
            lead_id=data.get("lead_id", ""),
            quote_id=data.get("quote_id", ""),
            quote_snapshot=data.get("quote_snapshot", {}) if isinstance(data.get("quote_snapshot", {}), dict) else {},
            updated_at=cls._dt(data.get("updated_at")),
        )

    def _next_id(self, prefix: str, kind: str) -> str:
        self._seq[kind] = int(self._seq.get(kind, 0)) + 1
        return f"{prefix}{self._seq[kind]:04d}"

    def _find_lead(self, lead_id: str = "", email: str = "") -> Optional[Lead]:
        for lead in self.leads:
            if lead_id and lead.lead_id == lead_id:
                return lead
            if email and lead.email and lead.email.lower() == email.lower():
                return lead
        return None

    def _find_opp(self, opp_id: str) -> Optional[Opportunity]:
        for opp in self.opportunities:
            if opp.opp_id == opp_id:
                return opp
        return None

    # ============================================
    # Legacy CRM tools (backward-compatible shapes)
    # ============================================

    def create_lead(self, lead_name: str = "", name: str = "", company: str = "",
                    email: str = "", value: float = 0.0, source: str = "",
                    industry: str = "", endpoints: int = 0,
                    compliance_drivers: Optional[List[str]] = None,
                    **legacy: Any) -> Dict[str, Any]:
        """Create a lead. Lead creation records only this agent's fields."""
        _ = legacy  # tolerate unknown kwargs from old callers instead of failing
        self._ensure_loaded()
        name = lead_name or name
        if email:
            existing = self._find_lead(email=email)
            if existing is not None:
                return {
                    "status": "exists",
                    "lead_id": existing.lead_id,
                    "lead": self.lead_summary(existing),
                    "message": f"A lead with this email already exists: {existing.lead_id}",
                }
        lead_id = self._next_id("LEAD-", "lead")
        lead = Lead(
            lead_id=lead_id, name=name, company=company, email=email,
            value=value, source=source, industry=industry,
            endpoints=max(int(endpoints or 0), 0),
            compliance_drivers=list(compliance_drivers or []),
        )
        self.leads.append(lead)
        self._persist()
        return {"status": "created", "lead_id": lead_id,
                "lead": self.lead_summary(lead)}

    def lead_summary(self, lead: Lead) -> Dict[str, Any]:
        """Flat dict view of a lead for results and reports."""
        return {
            "lead_id": lead.lead_id,
            "name": lead.name,
            "company": lead.company,
            "email": lead.email,
            "status": lead.status,
            "score": lead.score,
            "value": lead.value,
            "tier": lead.tier,
            "industry": lead.industry,
            "endpoints": lead.endpoints,
            "compliance_drivers": list(lead.compliance_drivers),
            "touch_count": lead.touch_count,
        }

    # ---------- qualification ----------

    @staticmethod
    def _budget_score(budget: str) -> float:
        text = (budget or "").strip().lower()
        if not text:
            return 0.0
        if re.search(r"\b(no|none|not_yet|none_yet)\b", text) or text.startswith("no"):
            return 2.0
        money = re.search(r"(\d+(?:\.\d+)?)\s*([kKmM]?)", text)
        if money and ("$" in text or "usd" in text or text[-1:] in ("k", "K", "m", "M")
                      or any(ch.isdigit() for ch in text)):
            amount = float(money.group(1))
            unit = money.group(2).lower()
            amount *= {"k": 1_000, "m": 1_000_000}.get(unit, 1.0)
            if amount >= 50_000:
                return 25.0
            if amount >= 20_000:
                return 18.0
            if amount > 0:
                return 10.0
        if "yes" in text:
            return 18.0
        if re.search(r"partial|maybe|unsure|unclear", text):
            return 12.0
        return 10.0

    @staticmethod
    def _authority_score(authority: str) -> float:
        text = (authority or "").strip().lower()
        if not text:
            return 0.0
        if re.search(r"\b(ceo|cfo|cto|ciso|coo|owner|president)\b", text):
            return 25.0
        if text in ("yes", "budget owner", "decision maker", "decision-maker"):
            return 20.0
        if re.search(r"\b(vp|vice president|director|head of)\b", text):
            return 18.0
        if text in ("no", "none", "unknown"):
            return 5.0
        return 15.0  # named a person or gave a role

    @staticmethod
    def _need_score(need: str) -> float:
        text = (need or "").strip().lower()
        if not text:
            return 0.0
        if re.search(r"security|compliance|audit|incident|soc\b|stig|soc 2|soc2|fedramp|circia", text):
            return 25.0
        if text in ("yes", "true"):
            return 18.0
        return 15.0

    @staticmethod
    def _timeline_score(timeline: str) -> float:
        text = (timeline or "").strip().lower()
        if not text:
            return 0.0
        if re.search(r"\b(now|immediate|asap|today|urgent)\b", text):
            return 25.0
        if re.search(r"\bq[1-4]\b", text):
            return 18.0
        days = re.search(r"(\d+)\s*day", text)
        if days:
            n = int(days.group(1))
            return 25.0 if n <= 90 else 18.0 if n <= 180 else 10.0
        months = re.search(r"(\d+)\s*month", text)
        if months:
            n = int(months.group(1))
            return 25.0 if n <= 3 else 18.0 if n <= 6 else 10.0
        if "year" in text:
            return 8.0
        if text in ("yes", "true"):
            return 15.0
        return 12.0

    def _icp_bonus(self, lead: Lead) -> float:
        bonus = 0.0
        bonus += min(len(lead.compliance_drivers) * 5.0, 10.0)
        if lead.industry.lower() in ("finance", "financial_services", "financial",
                                     "healthcare", "saas", "fintech", "defense",
                                     "manufacturing"):
            bonus += 5.0
        if lead.endpoints >= 500:
            bonus += 5.0
        elif lead.endpoints >= 100:
            bonus += 3.0
        return min(bonus, 20.0)

    def _tier_for_score(self, score: float) -> str:
        for tier, threshold in zip(("A", "B", "C"), TIER_THRESHOLDS):
            if score >= threshold:
                return tier
        return "D"

    def qualify_lead(self, lead_id: str = "", score: float = 0.0, name: str = "",
                     budget: str = "", authority: str = "", need: str = "",
                     timeline: str = "", **kwargs: Any) -> Dict[str, Any]:
        """Qualify a lead: BANT scoring (0-25 per pillar) + ICP bonus."""
        _ = kwargs
        self._ensure_loaded()
        lead = self._find_lead(lead_id=lead_id, email="") if lead_id else \
            next((l for l in self.leads if l.name == name), None)
        if lead is None:
            return {"error": f"Lead {lead_id or name} not found"}
        bant = {
            "budget": round(self._budget_score(budget), 1),
            "authority": round(self._authority_score(authority), 1),
            "need": round(self._need_score(need), 1),
            "timeline": round(self._timeline_score(timeline), 1),
        }
        computed = sum(bant.values()) + self._icp_bonus(lead)
        final_score = round(max(float(score), computed), 1)
        lead.status = LeadStatus.QUALIFIED
        lead.score = min(final_score, 100.0)
        lead.tier = self._tier_for_score(lead.score)
        self._persist()
        return {"status": "qualified", "lead_id": lead.lead_id,
                "score": lead.score, "tier": lead.tier, "name": lead.name,
                "budget": budget, "authority": authority, "need": need,
                "timeline": timeline, "qualified": True,
                "breakdown": {**bant, "icp_bonus": round(self._icp_bonus(lead), 1)}}

    # ---------- opportunities ----------

    def create_opportunity(self, title: str = "", value: float = 0.0,
                           contact: str = "", lead_id: str = "",
                           opportunity_name: str = "", stage: str = "prospecting",
                           probability: Optional[float] = None,
                           close_date=None, **kwargs: Any) -> Dict[str, Any]:
        """Create an opportunity linked to a lead, with a valid pipeline stage."""
        _ = kwargs
        self._ensure_loaded()
        title = title or opportunity_name
        stage = self._normalize_stage(stage)
        if close_date is not None and not isinstance(close_date, datetime):
            close_date = self._dt(close_date)
        if probability is not None:
            probability = float(probability)
            if probability > 1.0:  # compat: percent form (e.g. 20 -> 0.20)
                probability = round(probability / 100.0, 4)
        else:
            probability = STAGE_PROBABILITIES.get(stage, 0.10)
        if not contact and lead_id:
            lead = self._find_lead(lead_id=lead_id)
            if lead is not None:
                contact = lead.company or lead.name
        opp_id = self._next_id("OPP-", "opp")
        opp = Opportunity(opp_id=opp_id, title=title, value=value, stage=stage,
                          probability=probability, close_date=close_date,
                          contact=contact, lead_id=lead_id,
                          updated_at=datetime.now())
        self.opportunities.append(opp)
        self._persist()
        return {"status": "created", "opp_id": opp_id, "title": title,
                "value": value, "lead_id": lead_id,
                "opportunity": {"opp_id": opp_id, "title": title, "value": value,
                                "stage": stage, "probability": probability}}

    def _normalize_stage(self, stage: str) -> str:
        text = (stage or "prospecting").strip().lower()
        if text in STAGE_PROBABILITIES:
            return text
        if text in STAGE_ALIASES:
            return STAGE_ALIASES[text]
        raise ValueError(f"Unknown stage '{stage}'; valid stages: {', '.join(VALID_STAGES)}")

    def update_pipeline(self, opp_id: str = "", stage: str = "") -> Dict[str, Any]:
        """Move an opportunity to a validated stage; probability follows the table."""
        self._ensure_loaded()
        opp = self._find_opp(opp_id)
        if opp is None:
            return {"error": f"Opportunity {opp_id} not found"}
        try:
            stage = self._normalize_stage(stage)
        except ValueError as exc:
            return {"error": str(exc), "valid_stages": VALID_STAGES}
        opp.stage = stage
        opp.probability = STAGE_PROBABILITIES[stage]
        opp.updated_at = datetime.now()
        self._persist()
        return {"status": "updated", "opp_id": opp_id, "stage": stage,
                "probability": opp.probability}

    # ---------- quotes + pricing ----------

    def price_book(self) -> Dict[str, Any]:
        """Return the productized price book (single source, owner-tunable)."""
        self._ensure_loaded()
        return {"status": "ok", "pricing": PRICING,
                "note": ("Numbers are owner-tunable constants; per-endpoint and "
                         "package anchors follow 2026 MSP/MDR productized pricing "
                         "and outcome-based AI pricing research.")}

    def quote(self, service: str = "", tier: str = "", package: str = "",
              endpoints: int = 1, months: int = 12,
              discount_pct: float = 0.0, opp_id: str = "", lead_id: str = "",
              **kwargs: Any) -> Dict[str, Any]:
        """Build a quote from the price book: line items + MRR + year-1 total."""
        _ = kwargs
        self._ensure_loaded()
        entry = PRICING.get(service)
        if entry is None:
            return {"error": f"Unknown service '{service}'",
                    "valid_services": sorted(PRICING.keys())}
        months = int(max(1, min(int(months), 36)))
        discount_pct = max(0.0, min(float(discount_pct), 50.0))
        lines: List[Dict[str, Any]] = []
        monthly = 0.0
        one_time = 0.0

        if entry["models"]["type"] == "tiered_per_endpoint":
            tiers = entry["tiers"]
            tier_key = (tier or "business_hours").strip().lower()
            spec = tiers.get(tier_key) if tier_key else None
            if spec is None:
                return {"error": f"Unknown tier '{tier}' for service '{service}'",
                        "valid_tiers": sorted(tiers.keys())}
            n = max(int(endpoints or 0), 0)
            base_extended = spec["base_monthly"] * months
            per_ep = spec["per_endpoint_monthly"] * n * months
            monthly = spec["base_monthly"] + spec["per_endpoint_monthly"] * n
            lines.append({"item": f"{spec['label']} - platform base ({tier_key})",
                          "unit_price": spec["base_monthly"], "qty": months,
                          "extended": base_extended})
            lines.append({"item": f"endpoint coverage @ {tier_key}",
                          "unit_price": spec["per_endpoint_monthly"], "qty": n,
                          "extended": per_ep})
        elif entry["models"]["type"] == "package":
            packages = entry["packages"]
            package_key = (package or "").strip().lower()
            spec = packages.get(package_key) if package_key else None
            if spec is None:
                return {"error": f"Unknown package '{package}' for service '{service}'",
                        "valid_packages": sorted(packages.keys())}
            one_time += spec["one_time"]
            monthly += spec.get("monthly", 0.0)
            if spec["one_time"]:
                lines.append({"item": f"{spec['label']} - implementation",
                              "unit_price": spec["one_time"], "qty": 1,
                              "extended": spec["one_time"]})
            if spec.get("monthly"):
                extended = spec["monthly"] * months
                monthly += 0.0
                lines.append({"item": f"{spec['label']} - evidence watch ({months} mo)",
                              "unit_price": spec["monthly"], "qty": months,
                              "extended": extended})
        elif entry["models"]["type"] == "tiered_flat":
            tiers = entry["tiers"]
            tier_key = (tier or "standard").strip().lower()
            spec = tiers.get(tier_key) if tier_key else None
            if spec is None:
                return {"error": f"Unknown tier '{tier}' for service '{service}'",
                        "valid_tiers": sorted(tiers.keys())}
            monthly += spec["monthly"]
            lines.append({"item": spec.get("label", tier_key),
                          "unit_price": spec["monthly"], "qty": months,
                          "extended": spec["monthly"] * months})
        elif entry["models"]["type"] == "fixed_fee":
            tiers = entry["tiers"]
            tier_key = (tier or next(iter(tiers), "")).strip().lower()
            spec = tiers.get(tier_key) if tier_key else None
            if spec is None:
                return {"error": f"Unknown tier '{tier}' for service '{service}'",
                        "valid_tiers": sorted(tiers.keys())}
            one_time += spec["one_time"]
            lines.append({"item": spec.get("label", tier_key),
                          "unit_price": spec["one_time"], "qty": 1,
                          "extended": spec["one_time"]})
        else:
            return {"error": f"Unsupported pricing model for service '{service}'"}

        gross_recurring = monthly * months
        gross_total = gross_recurring + one_time
        discount_amount = round(gross_total * discount_pct / 100.0, 2)
        net_total = round(gross_total - discount_amount, 2)
        monthly = round(monthly, 2)
        quote_id = self._next_id("Q-", "quote")
        quote_out = {
            "status": "quoted",
            "quote_id": quote_id,
            "service": service,
            "tier": tier,
            "package": package,
            "endpoints": int(endpoints or 0),
            "months": months,
            "lines": lines,
            "monthly_recurring": monthly,
            "one_time": round(one_time, 2),
            "gross_total": round(gross_total, 2),
            "discount_pct": discount_pct,
            "discount_amount": discount_amount,
            "year1_total": round(monthly * 12 + (one_time * (months >= 1)), 2),
            "net_total_term": net_total,
            "lead_id": lead_id,
            "created_at": datetime.now().isoformat(),
        }
        self.quotes.append(quote_out)
        if opp_id:
            opp = self._find_opp(opp_id)
            if opp is None:
                return {"error": f"Opportunity {opp_id} not found"}
            opp.quote_id = quote_id
            opp.quote_snapshot = {"monthly_recurring": monthly,
                                  "one_time": quote_out["one_time"],
                                  "gross_total": quote_out["gross_total"],
                                  "discount_pct": discount_pct}
            opp.updated_at = datetime.now()
        self._persist()
        return quote_out

    # ---------- proposals ----------

    def generate_proposal(self, opp_id: str = "", template: str = "standard",
                          customer_name: str = "", opportunity_id: str = "",
                          **kwargs: Any) -> Dict[str, Any]:
        """Generate a full markdown proposal for an opportunity.

        Investment totals come from a bound quote when one exists; otherwise
        from the opportunity's own value. Proof points cite measured fleet
        stats only.
        """
        _ = kwargs
        opp_id = opp_id or opportunity_id
        self._ensure_loaded()
        opp = self._find_opp(opp_id)
        if opp is None:
            return {"error": f"Opportunity {opp_id} not found"}
        lead = self._find_lead(lead_id=opp.lead_id) if opp.lead_id else None
        customer = customer_name or (lead.company if lead else "") or opp.contact \
            or opp.title or "the customer"
        snapshot = opp.quote_snapshot or {}
        if snapshot:
            mrr = float(snapshot.get("monthly_recurring", 0.0) or 0.0)
            one_time = float(snapshot.get("one_time", 0.0) or 0.0)
            investment = (
                f"- Monthly recurring: ${mrr:,.0f}\n"
                f"- One-time implementation: ${one_time:,.0f}\n"
                f"- Year-1 total: ${mrr * 12 + one_time:,.0f}\n"
            )
        else:
            one_time = opp.value
            investment = (f"- Estimated engagement value: ${opp.value:,.0f}\n"
                          "  (attach a quote via the quote tool for detailed pricing)\n")

        md = [
            f"# Proposal — {customer}",
            f"Reference: {opp.opp_id} | Prepared: {datetime.now().strftime('%Y-%m-%d')}"
            f"{f' | Close target: {opp.close_date.date().isoformat()}' if opp.close_date else ''}",
            "",
            "## Executive summary",
            f"{customer} is evaluating security operations support. Bedim Security proposes a "
            "human-supervised, agentic SOC + compliance program: a Wazuh sensor fabric with an "
            "agentic analyst that decides every alert in-house, and a machine-speed DISA STIG "
            "compliance pipeline. All open source, all self-hosted, all verified.",
            "",
            "## Scope",
            f"- Opportunity: {opp.title or opp.opp_id}",
            f"- Stage: {opp.stage} (probability {opp.probability:.0%})",
            "- Delivery: deterministic alert gate + local inference; standing cloud access held in reserve",
            "- Human supervision: policy, exceptions, and accepted risk stay with a human supervisor",
            "",
            "## Measured proof points (published, not invented)",
            *[f"- {point}" for point in PROOF_POINTS],
            "",
            "## Investment",
            investment.rstrip("\n"),
            "",
            "## Honest scope note",
            "Our tooling is agentic automation for security operations — measurable, deterministic, "
            "and logged. It is not 'super intelligence'; every deployment is supervised by a human "
            "and every decision lands in an append-only audit log.",
            "",
            "## Next steps",
            "1. Review scope and pricing above.",
            f"2. Book a 30-minute briefing via {CONTACT_URL}.",
            "3. Pilot proposal within one week of approval.",
        ]
        proposal_md = "\n".join(md)
        return {"status": "generated", "opp_id": opp.opp_id, "title": opp.title,
                "value": opp.value, "template": template,
                "proposal": {
                    "markdown": proposal_md,
                    "customer": customer,
                    "sections": ["Executive summary", "Scope", "Measured proof points",
                                 "Investment", "Honest scope note", "Next steps"],
                    "quote_id": opp.quote_id,
                    "totals": {"monthly_recurring": snapshot.get("monthly_recurring"),
                               "one_time": one_time,
                               "year1_total": (snapshot.get("monthly_recurring") or 0.0) * 12 + one_time},
                }}

    # ---------- pipeline + forecast + outreach ----------

    def pipeline_report(self) -> Dict[str, Any]:
        """Owner-facing pipeline snapshot: stages, weighted totals, quotes, leads."""
        self._ensure_loaded()
        stage_counts: Dict[str, int] = {s: 0 for s in VALID_STAGES}
        stage_values: Dict[str, float] = {s: 0.0 for s in VALID_STAGES}
        weighted = 0.0
        open_value = 0.0
        won_value = 0.0
        lost_count = 0
        ranked: List[tuple] = []
        for opp in self.opportunities:
            stage_counts[opp.stage] = stage_counts.get(opp.stage, 0) + 1
            stage_values[opp.stage] = stage_values.get(opp.stage, 0.0) + opp.value
            w = opp.value * opp.probability
            weighted += w
            if opp.stage == "won":
                won_value += opp.value
            elif opp.stage == "lost":
                lost_count += 1
            else:
                open_value += opp.value
                ranked.append((w, opp.opp_id, opp.title, opp.value, opp.probability))
        ranked.sort(reverse=True)
        qualified = [l for l in self.leads if l.status == LeadStatus.QUALIFIED]
        quotes_mrr = sum(float(q.get("monthly_recurring", 0.0) or 0.0) for q in self.quotes)
        quotes_y1 = sum(float(q.get("year1_total", 0.0) or 0.0) for q in self.quotes)
        return {
            "status": "ok",
            "opportunities": len(self.opportunities),
            "stage_counts": stage_counts,
            "stage_values": stage_values,
            "total_pipeline": round(sum(stage_values.values()), 2),
            "open_pipeline": round(open_value, 2),
            "weighted_pipeline": round(weighted, 2),
            "won_value": round(won_value, 2),
            "lost_count": lost_count,
            "top_open": [{"opp_id": i, "title": t, "value": v,
                          "probability": p, "weighted": round(w, 2)}
                         for w, i, t, v, p in ranked[:5]],
            "leads": {"total": len(self.leads),
                      "qualified": len(qualified),
                      "qualified_pct": round(100.0 * len(qualified) / len(self.leads), 1)
                      if self.leads else 0.0},
            "quotes": {"count": len(self.quotes),
                       "total_mrr": round(quotes_mrr, 2),
                       "total_year1": round(quotes_y1, 2)},
        }

    def forecast(self, quarters: int = 2) -> Dict[str, Any]:
        """Weighted pipeline grouped by close quarter (undated ops bucketed separately)."""
        self._ensure_loaded()
        quarters = int(max(1, min(int(quarters), 8)))
        buckets: Dict[str, Dict[str, float]] = {}
        weighted_total = 0.0
        won_total = 0.0
        for opp in self.opportunities:
            w = opp.value * opp.probability
            weighted_total += w
            if opp.stage == "won":
                won_total += opp.value
                continue
            label = "unscheduled"
            if opp.close_date is not None:
                try:
                    label = (f"{opp.close_date.isocalendar()[0]}"
                             f"Q{(opp.close_date.month - 1) // 3 + 1}")
                except Exception:  # noqa: BLE001 - defensive fallback
                    label = "unscheduled"
            bucket = buckets.setdefault(label, {"weighted": 0.0, "count": 0})
            bucket["weighted"] += w
            bucket["count"] += 1
        ordered = sorted(buckets.items(), key=lambda kv: (kv[0] == "unscheduled", kv[0]))
        by_quarter = [{"quarter": q, "weighted": round(v["weighted"], 2),
                       "count": int(v["count"])} for q, v in ordered[:quarters]]
        return {"status": "ok", "horizon_quarters": quarters,
                "by_period": by_quarter,
                "weighted_total": round(weighted_total - won_total, 2),
                "won_total": round(won_total, 2),
                "note": "Weights come from STAGE_PROBABILITIES; explicit probabilities win."}

    def draft_outreach(self, lead_id: str = "", touch: int = 1,
                       channel: str = "email", angle: str = "") -> Dict[str, Any]:
        """Draft (never send) a personalized outreach email for a lead.

        Touch 1 introduces the productized SOC + compliance program; touch 2
        leads with measured proof; touch 3 proposes a briefing. Returns a
        draft flagged requires_owner_send — this agent has no SMTP path.
        """
        self._ensure_loaded()
        touch = int(max(1, min(int(touch), 3)))
        lead = self._find_lead(lead_id=lead_id)
        if lead is None:
            return {"error": f"Lead {lead_id} not found"}
        company = lead.company or lead.name
        drivers = " and ".join(sorted(set(lead.compliance_drivers))) if lead.compliance_drivers else ""
        angle = angle.strip()
        if touch == 1:
            subject = f"Security operations option for {company}"
            body = (
                f"Hi {lead.name or 'there'},\n\n"
                f"We run a human-supervised agentic SOC: every alert decided in-house on local "
                f"hardware — median decision 1.2s, measured on the live decision log — plus a "
                f"machine-speed DISA STIG compliance pipeline (stig-baselines, 14 platforms).\n"
                + (f"\nGiven your interest in {drivers} compliance, the compliance package line "
                   "is probably the right starting point.\n" if drivers else "\n")
                + (f"\nAngle from our side: {angle}\n" if angle else "")
                + f"\nCapability overview with measured numbers: {CAPABILITIES_URL}\n\n"
                  "Would a 30-minute briefing help?\n\n— Bedim Security (draft prepared by the sales agent)"
            )
        elif touch == 2:
            subject = f"Measured numbers behind our SOC proposal ({company})"
            body = (
                f"Hi {lead.name or 'there'},\n\n"
                "Published proof points, all measured:\n"
                + "\n".join(f"- {p}" for p in PROOF_POINTS)
                + f"\n\nFull capability pages: {CAPABILITIES_URL}\n\n"
                  "Happy to scope a fixed-fee pilot.\n\n— Bedim Security (draft prepared by the sales agent)"
            )
        else:
            subject = f"Next step: 30-minute briefing?"
            body = (
                f"Hi {lead.name or 'there'},\n\nClosing the loop on our earlier notes. The fastest "
                "path: a 30-minute briefing — we whiteboard your topology, you see the live SOC, "
                f"and we leave with a quote. {CONTACT_URL}\n\n"
                "If timing is wrong, say the word and I'll stop the sequence.\n\n"
                "— Bedim Security (draft prepared by the sales agent)"
            )
        lead.touch_count += 1
        lead.last_touched_at = datetime.now()
        lead.status = lead.status if lead.status != LeadStatus.NEW else LeadStatus.CONTACTED
        self._persist()
        return {"status": "drafted", "lead_id": lead.lead_id, "touch": touch,
                "channel": channel, "subject": subject, "body": body,
                "requires_owner_send": True,
                "note": "Draft only — this agent never sends anything."}

    # ============================================
    # Task dispatch
    # ============================================

    async def perform_task(self, task_type: str = "",
                           payload: Optional[Dict[str, Any]] = None,
                           *args, **kwargs) -> Dict[str, Any]:
        """Dispatch a task by type; payload is merged into kwargs."""
        merged: Dict[str, Any] = {**(payload or {}), **kwargs}
        handler = self._tools.get(task_type if task_type else "")
        if handler is None:
            return {"error": f"Unknown task type: {task_type}"}
        try:
            result = handler(**merged)
        except TypeError as exc:
            return {"error": f"Bad arguments for '{task_type}': {exc}"}
        except ValueError as exc:  # stage validation and friends
            return {"error": str(exc)}
        return dict(result) if isinstance(result, dict) else {"result": result}

    def get_lead(self, lead_id: str = "", email: str = "") -> Dict[str, Any]:
        """Fetch one lead's summary by id or email."""
        self._ensure_loaded()
        lead = self._find_lead(lead_id=lead_id, email=email)
        if lead is None:
            return {"error": f"Lead {lead_id or email} not found"}
        return {"status": "ok", "lead": self.lead_summary(lead)}
