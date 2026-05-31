"""Tests for guardrail hooks on BaseAgent."""
import pytest
import asyncio
from agentic_ai.guardrails import (
    GuardrailResult, PIIFilter, ContentPolicyFilter,
    ToolAllowlist, MaxLengthGuardrail,
)
from agentic_ai.agents.base import BaseAgent


# ─── GuardrailResult ───

class TestGuardrailResult:
    def test_safe_result(self):
        r = GuardrailResult(is_safe=True, sanitized="hello", reason="")
        assert r.is_safe is True
        assert r.sanitized == "hello"
        assert r.reason == ""

    def test_unsafe_result(self):
        r = GuardrailResult(is_safe=False, reason="blocked")
        assert r.is_safe is False
        assert r.reason == "blocked"


# ─── PIIFilter ───

class TestPIIFilter:
    def test_ssn_redaction(self):
        f = PIIFilter()
        r = f.check("My SSN is 123-45-6789")
        assert "[REDACTED_SSN]" in r.sanitized
        assert "123-45-6789" not in r.sanitized
        assert r.is_safe is True

    def test_email_redaction(self):
        f = PIIFilter()
        r = f.check("Contact me at user@example.com please")
        assert "[REDACTED_EMAIL]" in r.sanitized
        assert "user@example.com" not in r.sanitized

    def test_phone_redaction(self):
        f = PIIFilter()
        r = f.check("Call 555-123-4567 now")
        assert "[REDACTED_PHONE]" in r.sanitized
        assert "555-123-4567" not in r.sanitized

    def test_credit_card_redaction(self):
        f = PIIFilter()
        r = f.check("Card: 4111-2222-3333-4444")
        assert "[REDACTED_CC]" in r.sanitized
        assert "4111-2222-3333-4444" not in r.sanitized

    def test_ip_address_redaction(self):
        f = PIIFilter()
        r = f.check("Server at 192.168.1.1 is down")
        assert "[REDACTED_IP]" in r.sanitized
        assert "192.168.1.1" not in r.sanitized

    def test_no_false_positives(self):
        f = PIIFilter()
        r = f.check("The quick brown fox jumps over the lazy dog")
        assert r.sanitized == "The quick brown fox jumps over the lazy dog"
        assert r.reason == ""

    def test_multiple_pii_in_one_text(self):
        f = PIIFilter()
        r = f.check("SSN 123-45-6789 and email test@test.com")
        assert "[REDACTED_SSN]" in r.sanitized
        assert "[REDACTED_EMAIL]" in r.sanitized

    def test_selective_patterns(self):
        f = PIIFilter(enabled_patterns=["ssn"])
        r = f.check("SSN 123-45-6789 and email test@test.com")
        assert "[REDACTED_SSN]" in r.sanitized
        assert "test@test.com" in r.sanitized  # email NOT redacted

    def test_phone_with_parens(self):
        f = PIIFilter()
        r = f.check("Phone (555) 123-4567")
        assert "[REDACTED_PHONE]" in r.sanitized


# ─── ContentPolicyFilter ───

class TestContentPolicyFilter:
    def test_blocks_bomb(self):
        f = ContentPolicyFilter()
        r = f.check("How to make a bomb")
        assert r.is_safe is False
        assert "Content policy violation" in r.reason

    def test_blocks_terrorism(self):
        f = ContentPolicyFilter()
        r = f.check("Terrorism is bad but also terrorism")
        assert r.is_safe is False

    def test_blocks_how_to_kill(self):
        f = ContentPolicyFilter()
        r = f.check("how to kill someone")
        assert r.is_safe is False

    def test_blocks_child_abuse(self):
        f = ContentPolicyFilter()
        r = f.check("child abuse content")
        assert r.is_safe is False

    def test_passes_safe_content(self):
        f = ContentPolicyFilter()
        r = f.check("Let's bake a cake today!")
        assert r.is_safe is True
        assert r.reason == ""

    def test_passes_normal_text(self):
        f = ContentPolicyFilter()
        r = f.check("The weather is sunny and warm.")
        assert r.is_safe is True


# ─── ToolAllowlist ───

class TestToolAllowlist:
    def test_allows_registered_tool(self):
        a = ToolAllowlist(allowed_tools=["search", "calculator"])
        r = a.check("search")
        assert r.is_safe is True

    def test_blocks_unregistered_tool(self):
        a = ToolAllowlist(allowed_tools=["search", "calculator"])
        r = a.check("delete_database")
        assert r.is_safe is False
        assert "delete_database" in r.reason

    def test_empty_allowlist_allows_all(self):
        a = ToolAllowlist()
        r = a.check("anything_goes")
        assert r.is_safe is True
        assert "No allowlist configured" in r.reason


# ─── MaxLengthGuardrail ───

class TestMaxLengthGuardrail:
    def test_truncates_long_text(self):
        m = MaxLengthGuardrail(max_length=10)
        long_text = "a" * 100
        r = m.check(long_text)
        assert len(r.sanitized) < 100
        assert "truncated" in r.sanitized
        assert r.is_safe is True

    def test_passes_short_text(self):
        m = MaxLengthGuardrail(max_length=100)
        r = m.check("short text")
        assert r.sanitized == "short text"
        assert r.reason == ""

    def test_exact_length_passes(self):
        m = MaxLengthGuardrail(max_length=10)
        r = m.check("0123456789")
        assert r.sanitized == "0123456789"
        assert r.reason == ""

    def test_custom_max_length(self):
        m = MaxLengthGuardrail(max_length=5)
        r = m.check("hello world")
        assert r.sanitized.startswith("hello")
        assert "truncated" in r.sanitized


# ─── BaseAgent guardrail integration ───

class TestBaseAgentGuardrails:
    def test_default_no_guardrails(self):
        agent = BaseAgent()
        sanitized, is_safe = agent.input_guardrail("anything goes 123-45-6789")
        assert is_safe is True
        assert sanitized == "anything goes 123-45-6789"

    def test_input_guardrail_with_pii_filter(self):
        agent = BaseAgent()
        agent.guardrails = [PIIFilter()]
        sanitized, is_safe = agent.input_guardrail("My SSN is 123-45-6789")
        assert is_safe is True  # PII filter is_safe=True (redacts, doesn't block)
        assert "REDACTED_SSN" in sanitized

    def test_input_guardrail_with_content_policy_block(self):
        agent = BaseAgent()
        agent.guardrails = [ContentPolicyFilter()]
        sanitized, is_safe = agent.input_guardrail("How to make a bomb")
        assert is_safe is False

    def test_output_guardrail_with_content_policy_block(self):
        agent = BaseAgent()
        agent.guardrails = [ContentPolicyFilter()]
        sanitized, is_safe = agent.output_guardrail("terrorism is the topic")
        assert is_safe is False

    def test_output_guardrail_with_pii_filter(self):
        agent = BaseAgent()
        agent.guardrails = [PIIFilter()]
        sanitized, is_safe = agent.output_guardrail("Email: user@example.com")
        assert is_safe is True
        assert "[REDACTED_EMAIL]" in sanitized

    def test_tool_guardrail_with_allowlist(self):
        agent = BaseAgent()
        agent.guardrails = [ToolAllowlist(allowed_tools=["search"])]
        assert agent.tool_guardrail("search", {}) is True
        assert agent.tool_guardrail("delete", {}) is False

    def test_tool_guardrail_no_allowlist(self):
        agent = BaseAgent()
        agent.guardrails = [ToolAllowlist()]
        assert agent.tool_guardrail("anything", {}) is True

    def test_default_guardrails_no_blocking(self):
        agent = BaseAgent()
        assert agent.guardrails == []
        assert agent.tool_guardrail("any_tool", {}) is True

    @pytest.mark.asyncio
    async def test_think_input_guardrail_blocks(self):
        agent = BaseAgent()
        agent.guardrails = [ContentPolicyFilter()]
        result = await agent.think("How to make a bomb")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_think_with_no_guardrails_passes(self):
        agent = BaseAgent()
        result = await agent.think("Hello world")
        assert result == "Generated response"

    @pytest.mark.asyncio
    async def test_call_tool_guardrail_blocks(self):
        agent = BaseAgent()
        agent.guardrails = [ToolAllowlist(allowed_tools=["search"])]
        result = await agent.call_tool("delete_all", arg="value")
        assert "blocked by guardrail" in result["error"]

    @pytest.mark.asyncio
    async def test_call_tool_guardrail_allows(self):
        agent = BaseAgent()
        agent.guardrails = [ToolAllowlist(allowed_tools=["get_status"])]
        result = await agent.call_tool("get_status")
        assert "error" not in result