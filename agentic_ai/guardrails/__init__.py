"""Guardrails for agent input/output safety."""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class GuardrailResult:
    """Result of a guardrail check."""
    def __init__(self, is_safe: bool, sanitized: str = "", reason: str = ""):
        self.is_safe = is_safe
        self.sanitized = sanitized
        self.reason = reason


class PIIFilter:
    """Redact personally identifiable information from text."""
    
    # Regex patterns for common PII
    PATTERNS = {
        "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "phone": re.compile(r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "credit_card": re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
        "ip_address": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    }
    
    REDACTION = {
        "ssn": "[REDACTED_SSN]",
        "email": "[REDACTED_EMAIL]",
        "phone": "[REDACTED_PHONE]",
        "credit_card": "[REDACTED_CC]",
        "ip_address": "[REDACTED_IP]",
    }
    
    def __init__(self, enabled_patterns: Optional[List[str]] = None):
        self.enabled = enabled_patterns or list(self.PATTERNS.keys())
    
    def check(self, text: str) -> GuardrailResult:
        """Check and redact PII from text."""
        sanitized = text
        found = False
        for pattern_name in self.enabled:
            if pattern_name in self.PATTERNS:
                matches = self.PATTERNS[pattern_name].findall(sanitized)
                if matches:
                    found = True
                    sanitized = self.PATTERNS[pattern_name].sub(
                        self.REDACTION[pattern_name], sanitized
                    )
        reason = "PII detected and redacted" if found else ""
        return GuardrailResult(is_safe=True, sanitized=sanitized, reason=reason)


class ContentPolicyFilter:
    """Block harmful content patterns."""
    
    BLOCKED_PATTERNS = [
        re.compile(r'\b(?:bomb|explosive|terrorism|terrorist)\b', re.IGNORECASE),
        re.compile(r'\b(?:child\s*abuse|csam)\b', re.IGNORECASE),
        re.compile(r'\b(?:how\s+to\s+kill|how\s+to\s+murder)\b', re.IGNORECASE),
        re.compile(r'\b(?:synthesize\s+?(?:fentanyl|anthrax|sarin))\b', re.IGNORECASE),
    ]
    
    def check(self, text: str) -> GuardrailResult:
        """Check text against content policy."""
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.search(text):
                return GuardrailResult(
                    is_safe=False,
                    sanitized=text,
                    reason=f"Content policy violation detected"
                )
        return GuardrailResult(is_safe=True, sanitized=text, reason="")


class ToolAllowlist:
    """Only permit tools on the agent's registered list."""
    
    def __init__(self, allowed_tools: Optional[List[str]] = None):
        self.allowed = set(allowed_tools) if allowed_tools else set()
    
    def check(self, tool_name: str, kwargs: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Check if tool call is permitted."""
        if not self.allowed:
            return GuardrailResult(is_safe=True, reason="No allowlist configured")
        if tool_name in self.allowed:
            return GuardrailResult(is_safe=True, reason="Tool on allowlist")
        return GuardrailResult(
            is_safe=False,
            reason=f"Tool '{tool_name}' not on allowlist: {self.allowed}"
        )


class MaxLengthGuardrail:
    """Truncate overlong inputs/outputs."""
    
    def __init__(self, max_length: int = 10000):
        self.max_length = max_length
    
    def check(self, text: str) -> GuardrailResult:
        """Check and truncate if needed."""
        if len(text) <= self.max_length:
            return GuardrailResult(is_safe=True, sanitized=text, reason="")
        truncated = text[:self.max_length] + f"\n[...truncated at {self.max_length} chars]"
        return GuardrailResult(is_safe=True, sanitized=truncated, reason=f"Truncated from {len(text)} chars")