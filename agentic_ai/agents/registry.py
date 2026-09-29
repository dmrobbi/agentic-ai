"""Agent registry: the single source of truth for every agent in agentic_ai.

Maps a short agent id to (module, class_name, category, description). Class
docs previously listed agents that did not exist (a hardcoded "product"
entry with no class) and omitted real ones (biblical_scholar, the cyber V2
variants); this registry is authoritative and lazily imported - no agent
module is loaded until requested, so `agenticai agent list` stays cheap.
"""

from importlib import import_module
from typing import Any, Dict, Optional, Tuple

# agent_id -> (module path, class name, category, description)
AGENT_REGISTRY: Dict[str, Tuple[str, str, str, str]] = {
    # Core
    "base": ("agentic_ai.agents.base", "BaseAgent", "Core",
             "Base agent functionality and shared protocol"),
    "developer": ("agentic_ai.agents.developer", "DeveloperAgent", "Core",
                  "Code implementation and review"),
    "qa": ("agentic_ai.agents.qa", "QAAgent", "Core",
           "Testing and quality assurance"),
    "sysadmin": ("agentic_ai.agents.sysadmin", "SysAdminAgent", "Core",
                 "System administration"),
    "lead": ("agentic_ai.agents.lead", "LeadAgent", "Core",
             "Orchestration and coordination"),
    # Business
    "sales": ("agentic_ai.agents.sales", "SalesAgent", "Business",
              "Sales and lead management"),
    "finance": ("agentic_ai.agents.finance", "FinanceAgent", "Business",
                "Financial operations"),
    "hr": ("agentic_ai.agents.hr", "HRAgent", "Business", "Human resources"),
    "marketing": ("agentic_ai.agents.marketing", "MarketingAgent", "Business",
                  "Marketing campaigns"),
    # Data
    "research": ("agentic_ai.agents.research", "ResearchAgent", "Data",
                 "Research and analysis"),
    "data_analyst": ("agentic_ai.agents.data_analyst", "DataAnalystAgent", "Data",
                     "Data analysis"),
    "data_governance": ("agentic_ai.agents.data_governance", "DataGovernanceAgent",
                        "Data", "Data governance"),
    # Operations
    "devops": ("agentic_ai.agents.devops", "DevOpsAgent", "Operations",
               "DevOps and infrastructure"),
    "support": ("agentic_ai.agents.support", "SupportAgent", "Operations",
                "Customer support"),
    "integration": ("agentic_ai.agents.integration", "IntegrationAgent", "Operations",
                    "System integrations"),
    "communications": ("agentic_ai.agents.communications", "CommunicationsAgent",
                       "Operations", "Communications"),
    # Governance
    "legal": ("agentic_ai.agents.legal", "LegalAgent", "Governance",
              "Legal operations"),
    "compliance": ("agentic_ai.agents.compliance", "ComplianceAgent", "Governance",
                   "Compliance management"),
    "privacy": ("agentic_ai.agents.privacy", "PrivacyAgent", "Governance",
                "Privacy compliance"),
    "risk": ("agentic_ai.agents.risk", "RiskAgent", "Governance",
             "Risk management"),
    "ethics": ("agentic_ai.agents.ethics", "EthicsAgent", "Governance",
               "Ethics and AI safety"),
    "biblical_scholar": ("agentic_ai.agents.biblical_scholar", "BiblicalScholarAgent",
                         "Specialized", "Biblical scholarship research"),
    # Cyber
    "security": ("agentic_ai.agents.security", "SecurityAgent", "Cyber",
                 "Security operations"),
    "soc": ("agentic_ai.agents.cyber.soc", "SecurityOperationsAgent", "Cyber",
            "Security operations center"),
    "vulnman": ("agentic_ai.agents.cyber.vulnman", "VulnerabilityManagementAgent",
                "Cyber", "Vulnerability management"),
    "redteam": ("agentic_ai.agents.cyber.redteam", "RedTeamAgent", "Cyber",
                "Red team operations"),
    "redteam_v2": ("agentic_ai.agents.cyber.redteam_v2", "RedTeamAgentV2", "Cyber",
                   "Red team operations (v2, standalone class)"),
    "malware": ("agentic_ai.agents.cyber.malware", "MalwareAnalysisAgent", "Cyber",
                "Malware analysis"),
    "kali": ("agentic_ai.agents.cyber.kali", "KaliAgent", "Cyber",
             "Kali Linux tooling agent (v1 interface; see also the kali-agent skill)"),
    "kali_v2": ("agentic_ai.agents.cyber.kali_v2", "KaliAgentV2", "Cyber",
                "Kali tooling v2 (standalone class)"),
    # Infrastructure & audit
    "cloud_security": ("agentic_ai.agents.cloud_security", "CloudSecurityAgent",
                       "Operations", "Cloud security posture"),
    "ml_ops": ("agentic_ai.agents.ml_ops", "MLOpsAgent", "Data",
               "ML operations"),
    "supply_chain": ("agentic_ai.agents.supply_chain", "SupplyChainAgent", "Governance",
                     "Software supply chain"),
    "audit": ("agentic_ai.agents.audit", "AuditAgent", "Governance",
              "Internal audit"),
    "vendor_risk": ("agentic_ai.agents.vendor_risk", "VendorRiskAgent", "Governance",
                    "Vendor risk management"),
    "chaos_monkey": ("agentic_ai.agents.chaos_monkey", "ChaosMonkeyAgent", "Operations",
                     "Chaos engineering"),
}


def resolve_agent_class(agent_id: str) -> type:
    """Import and return the agent class for an id (lazy, cached by Python)."""
    if agent_id not in AGENT_REGISTRY:
        raise KeyError(
            f"Unknown agent id: {agent_id!r}. "
            f"Known ids: {', '.join(sorted(AGENT_REGISTRY))}")
    module_path, class_name, _, _ = AGENT_REGISTRY[agent_id]
    return getattr(import_module(module_path), class_name)  # type: ignore[no-any-return]


def create_agent(agent_id: str, **params: Any) -> Any:
    """Instantiate an agent by id with optional constructor params."""
    cls = resolve_agent_class(agent_id)
    return cls(**params)


def list_agents() -> Dict[str, Dict[str, str]]:
    """Registry as {id: {class, module, category, description}} for display."""
    return {
        agent_id: {"class": class_name, "module": module_path,
                   "category": category, "description": description}
        for agent_id, (module_path, class_name, category, description)
        in sorted(AGENT_REGISTRY.items())
    }