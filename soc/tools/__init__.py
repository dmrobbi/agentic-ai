"""
SOC Tools
=========

SOC-specific tools for the Lead Agent:
- soc_triage: classify and deduplicate an incoming alert
- soc_dispatch: route alert to appropriate specialist agent
- soc_rsem_score: score response options using RSEM
- soc_hitl_present: format a HITL recommendation for the analyst
- threat_enrich: enrich an IOC with external threat intel
- mitre_lookup: look up MITRE ATT&CK technique info
- kafka_produce: produce a message to a Kafka topic
"""

from soc.tools.soc_tools import (
    soc_triage,
    soc_dispatch,
    soc_rsem_score,
    soc_hitl_present,
    threat_enrich,
    mitre_lookup,
    kafka_produce,
)

__all__ = [
    "soc_triage",
    "soc_dispatch",
    "soc_rsem_score",
    "soc_hitl_present",
    "threat_enrich",
    "mitre_lookup",
    "kafka_produce",
]