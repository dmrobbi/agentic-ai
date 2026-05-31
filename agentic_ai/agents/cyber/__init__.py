"""
Cyber Division - Offensive & Defensive Security Agents
========================================================

This package contains security-focused agents for both defensive (Blue Team)
and offensive (Red Team) operations.

Agents:
- SecurityOperationsAgent: SOC automation, incident response
- VulnerabilityManagementAgent: Scanning, patch management
- RedTeamAgent: Penetration testing, adversary emulation
- RedTeamAgentV2: Enhanced with MITRE ATT&CK v12, risk scoring
- MalwareAnalysisAgent: Reverse engineering, threat intel
- KaliAgent: Kali Linux tool orchestration (600+ tools)
- KaliAgentV2: Enhanced with CVE matching, modern tools, cloud security
- CloudSecurityAgent: Multi-cloud CSPM
- SecurityAgent: Threat detection, code scanning
"""

from agentic_ai.agents.cyber.soc import SecurityOperationsAgent  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.vulnman import VulnerabilityManagementAgent  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.redteam import RedTeamAgent  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.redteam_v2 import RedTeamAgentV2  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.malware import MalwareAnalysisAgent  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.kali import KaliAgent  # type: ignore[attr-defined]
from agentic_ai.agents.cyber.kali_v2 import KaliAgentV2  # type: ignore[attr-defined]

__all__ = [
    # Blue Team
    'SecurityOperationsAgent',
    'VulnerabilityManagementAgent',

    # Red Team
    'RedTeamAgent',
    'RedTeamAgentV2',
    'MalwareAnalysisAgent',
    'KaliAgent',
    'KaliAgentV2',
]
