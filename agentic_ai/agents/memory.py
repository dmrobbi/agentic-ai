"""Tiered memory system for agents following the MemGPT pattern.

Three tiers:
- CORE: Always in context (role, permissions, active task)
- WORKING: Recent conversation turns (sliding window)
- ARCHIVAL: Compressed/summarized history (searchable, loaded on demand)
"""
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional
import logging
import re

logger = logging.getLogger(__name__)


class MemoryTier(Enum):
    CORE = "core"        # Always in context
    WORKING = "working"  # Recent conversation turns
    ARCHIVAL = "archival"  # Compressed history


@dataclass
class MemoryEntry:
    """A single memory entry."""
    role: str
    content: str
    tier: MemoryTier = MemoryTier.WORKING
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tier": self.tier.value,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryEntry":
        tier = data.pop("tier", MemoryTier.WORKING.value)
        if isinstance(tier, str):
            tier = MemoryTier(tier)
        return cls(tier=tier, **data)


class TieredMemory:
    """Three-tier memory system for agents.
    
    Core: Always included in prompts (identity, role, permissions).
    Working: Recent conversation turns (sliding window, default 50).
    Archival: Compressed/summarized history (searchable, loaded on demand).
    """
    
    def __init__(self, max_working: int = 50, max_core: int = 20):
        self.max_working = max_working
        self.max_core = max_core
        self._core: List[Dict[str, Any]] = []
        self._working: deque = deque(maxlen=max_working)
        self._archival: List[Dict[str, Any]] = []
    
    def add(self, role: str, content: str, tier: MemoryTier = MemoryTier.WORKING,
            metadata: Dict[str, Any] = None) -> None:
        """Add a memory entry to the specified tier."""
        entry = MemoryEntry(
            role=role, content=content, tier=tier,
            metadata=metadata or {},
        )
        if tier == MemoryTier.CORE:
            if len(self._core) >= self.max_core:
                # Promote oldest core to archival
                self._archival.append(self._core.pop(0))
            self._core.append(entry.to_dict())
        elif tier == MemoryTier.WORKING:
            self._working.append(entry.to_dict())
        elif tier == MemoryTier.ARCHIVAL:
            self._archival.append(entry.to_dict())
    
    def add_core(self, role: str, content: str, metadata: Dict[str, Any] = None) -> None:
        """Add to core memory (always in context)."""
        self.add(role, content, MemoryTier.CORE, metadata)
    
    def add_working(self, role: str, content: str, metadata: Dict[str, Any] = None) -> None:
        """Add to working memory (recent conversation)."""
        self.add(role, content, MemoryTier.WORKING, metadata)
    
    def add_archival(self, role: str, content: str, metadata: Dict[str, Any] = None) -> None:
        """Add to archival memory (compressed history)."""
        self.add(role, content, MemoryTier.ARCHIVAL, metadata)
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search archival memory for relevant entries.
        
        Simple keyword-based search. Future: replace with vector similarity.
        """
        query_lower = query.lower()
        query_words = set(re.findall(r'\w+', query_lower))
        
        scored = []
        for entry in self._archival:
            content_lower = entry.get("content", "").lower()
            entry_words = set(re.findall(r'\w+', content_lower))
            overlap = len(query_words & entry_words)
            if overlap > 0:
                scored.append((overlap, entry))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]
    
    def summarize_working(self) -> str:
        """Summarize working memory and move to archival.
        
        Simple truncation-based summarization. Future: use LLM for compression.
        """
        if not self._working:
            return ""
        
        entries = list(self._working)
        summary_parts = [f"{e.get('role', 'unknown')}: {e.get('content', '')[:100]}" for e in entries]
        summary = " | ".join(summary_parts)
        
        # Move to archival
        self._archival.append({
            "role": "system",
            "content": f"Working memory summary: {summary}",
            "tier": MemoryTier.ARCHIVAL.value,
            "metadata": {"summarized_entries": len(entries)},
        })
        
        # Clear working memory
        self._working.clear()
        return summary
    
    def to_messages(self) -> List[Dict[str, Any]]:
        """Build prompt messages from core + working memory.
        
        This is what gets sent to the LLM.
        """
        messages = []
        # Core memory is always included
        messages.extend(self._core)
        # Working memory is included
        messages.extend(self._working)
        return messages
    
    @property
    def core(self) -> List[Dict[str, Any]]:
        return list(self._core)
    
    @property
    def working(self) -> List[Dict[str, Any]]:
        return list(self._working)
    
    @property
    def archival(self) -> List[Dict[str, Any]]:
        return list(self._archival)
    
    def clear_working(self) -> None:
        """Clear working memory."""
        self._working.clear()
    
    def clear_archival(self) -> None:
        """Clear archival memory."""
        self._archival.clear()
    
    def __len__(self) -> int:
        return len(self._core) + len(self._working) + len(self._archival)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize all memory tiers."""
        return {
            "core": self._core,
            "working": list(self._working),
            "archival": self._archival,
            "max_working": self.max_working,
            "max_core": self.max_core,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TieredMemory":
        """Deserialize from dict."""
        mem = cls(
            max_working=data.get("max_working", 50),
            max_core=data.get("max_core", 20),
        )
        mem._core = data.get("core", [])
        mem._archival = data.get("archival", [])
        for entry in data.get("working", []):
            mem._working.append(entry)
        return mem