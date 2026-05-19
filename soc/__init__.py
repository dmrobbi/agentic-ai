"""
SOCConversation — Agentic SOC Pipeline
======================================

SOC Phase 5: Security Operations Center agents built on agentic-ai.

Modules:
- agents/lead.py          : SOC Lead Agent (extends SecurityOperationsAgent)
- agents/soc_tools.py     : SOC-specific tools (triage, dispatch, enrich)
- engines/nce.py          : Narrative Counterfactual Engine
- engines/sse.py          : Structural Simulation Engine
- engines/rsem.py          : Risk Scoring and Evaluation Module
- kafka_client.py          : Kafka consumer/producer for SOC pipeline
- db_client.py             : PostgreSQL client for SOC schema
"""

__version__ = "1.0.0"
__phase__ = "SOC Phase 5"