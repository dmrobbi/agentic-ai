"""
Specialist Agents
=================

Specialist agent implementations for SOCConversation Milestone 2.

Each specialist agent:
- Consumes tasks from `soc.investigation.tasks` Kafka topic
- Performs its specialized work (enrichment, analysis, FP check)
- Produces results to `soc.alerts.enriched` or back to Kafka
- Reports findings back to the Lead Agent for RSEM + HITL
"""

from soc.agents.specialist_agents import (
    SOCDeveloperAgent,
    SOCSysAdminAgent,
    SOCQAAgent,
)

__all__ = [
    "SOCDeveloperAgent",
    "SOCSysAdminAgent",
    "SOCQAAgent",
]