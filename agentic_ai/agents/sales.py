"""
Sales Agent — CRM and sales pipeline management.

Handles lead creation, qualification, opportunity management,
proposal generation, and pipeline tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
import logging

from agentic_ai.agents.base import BaseAgent, Permission

logger = logging.getLogger(__name__)


from enum import Enum

class LeadStatus(Enum):
    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    PROPOSAL = "proposal"
    NEGOTIATION = "negotiation"
    WON = "won"
    LOST = "lost"


@dataclass
class Lead:
    lead_id: str
    name: str
    company: str = ""
    email: str = ""
    status: LeadStatus = LeadStatus.NEW
    score: float = 0.0
    value: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    notes: List[str] = field(default_factory=list)


@dataclass
class Opportunity:
    opp_id: str
    title: str
    value: float = 0.0
    stage: str = "prospecting"
    probability: float = 0.0
    close_date: Optional[datetime] = None
    contact: str = ""


class SalesAgent(BaseAgent):
    """Sales agent for CRM and pipeline management."""

    agent_type = "sales"
    permission = Permission.STANDARD

    def __init__(self, agent_id: str = None, name: str = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 crm_path: str = "/tmp/crm"):
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.crm_path = crm_path
        self.leads: List[Lead] = []
        self.opportunities: List[Opportunity] = []
        self._tools = {
            "create_lead": self.create_lead,
            "qualify_lead": self.qualify_lead,
            "create_opportunity": self.create_opportunity,
            "generate_proposal": self.generate_proposal,
            "update_pipeline": self.update_pipeline,
        }

    def create_lead(self, name: str = "", company: str = "",
                    email: str = "", value: float = 0.0) -> Dict[str, Any]:
        lead_id = f"LEAD-{len(self.leads)+1:04d}"
        lead = Lead(lead_id=lead_id, name=name, company=company, email=email, value=value)
        self.leads.append(lead)
        return {"status": "created", "lead_id": lead_id, "name": name, "company": company}

    def qualify_lead(self, lead_id: str = "", score: float = 0.0) -> Dict[str, Any]:
        for lead in self.leads:
            if lead.lead_id == lead_id:
                lead.status = LeadStatus.QUALIFIED
                lead.score = max(score, 50.0)
                return {"status": "qualified", "lead_id": lead_id, "score": lead.score}
        return {"error": f"Lead {lead_id} not found"}

    def create_opportunity(self, title: str = "", value: float = 0.0,
                           contact: str = "") -> Dict[str, Any]:
        opp_id = f"OPP-{len(self.opportunities)+1:04d}"
        opp = Opportunity(opp_id=opp_id, title=title, value=value, contact=contact, probability=min(value/100000, 0.5))
        self.opportunities.append(opp)
        return {"status": "created", "opp_id": opp_id, "title": title, "value": value}

    def generate_proposal(self, opp_id: str = "", template: str = "standard") -> Dict[str, Any]:
        for opp in self.opportunities:
            if opp.opp_id == opp_id:
                return {"status": "generated", "opp_id": opp_id, "title": opp.title, "value": opp.value, "template": template}
        return {"error": f"Opportunity {opp_id} not found"}

    def update_pipeline(self, opp_id: str = "", stage: str = "") -> Dict[str, Any]:
        for opp in self.opportunities:
            if opp.opp_id == opp_id:
                opp.stage = stage
                return {"status": "updated", "opp_id": opp_id, "stage": stage}
        return {"error": f"Opportunity {opp_id} not found"}