"""Tests for the TieredMemory system (MemGPT pattern)."""
import pytest
from agentic_ai.agents.memory import TieredMemory, MemoryTier, MemoryEntry
from agentic_ai.agents.base import AgentMemory


class TestMemoryTier:
    """Tests for the MemoryTier enum."""

    def test_tier_values(self):
        assert MemoryTier.CORE.value == "core"
        assert MemoryTier.WORKING.value == "working"
        assert MemoryTier.ARCHIVAL.value == "archival"

    def test_tier_from_string(self):
        assert MemoryTier("core") == MemoryTier.CORE
        assert MemoryTier("working") == MemoryTier.WORKING
        assert MemoryTier("archival") == MemoryTier.ARCHIVAL

    def test_tier_members(self):
        assert len(MemoryTier) == 3


class TestMemoryEntry:
    """Tests for the MemoryEntry dataclass."""

    def test_entry_creation_defaults(self):
        entry = MemoryEntry(role="user", content="hello")
        assert entry.role == "user"
        assert entry.content == "hello"
        assert entry.tier == MemoryTier.WORKING
        assert entry.timestamp == ""
        assert entry.metadata == {}

    def test_entry_creation_with_tier(self):
        entry = MemoryEntry(role="system", content="you are an agent", tier=MemoryTier.CORE)
        assert entry.tier == MemoryTier.CORE

    def test_entry_creation_with_metadata(self):
        entry = MemoryEntry(
            role="user", content="hello",
            metadata={"source": "test", "priority": 1}
        )
        assert entry.metadata["source"] == "test"
        assert entry.metadata["priority"] == 1

    def test_entry_to_dict(self):
        entry = MemoryEntry(
            role="user", content="hello",
            tier=MemoryTier.WORKING,
            timestamp="2024-01-01",
            metadata={"key": "val"}
        )
        d = entry.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "hello"
        assert d["tier"] == "working"
        assert d["timestamp"] == "2024-01-01"
        assert d["metadata"] == {"key": "val"}

    def test_entry_from_dict(self):
        data = {
            "role": "assistant",
            "content": "hi",
            "tier": "archival",
            "timestamp": "2024-01-01",
            "metadata": {"summarized": True}
        }
        entry = MemoryEntry.from_dict(data)
        assert entry.role == "assistant"
        assert entry.content == "hi"
        assert entry.tier == MemoryTier.ARCHIVAL
        assert entry.timestamp == "2024-01-01"
        assert entry.metadata == {"summarized": True}

    def test_entry_from_dict_default_tier(self):
        data = {"role": "user", "content": "hello"}
        entry = MemoryEntry.from_dict(data)
        assert entry.tier == MemoryTier.WORKING

    def test_entry_roundtrip(self):
        original = MemoryEntry(
            role="system", content="test",
            tier=MemoryTier.CORE,
            timestamp="2024-06-01",
            metadata={"x": 1}
        )
        d = original.to_dict()
        restored = MemoryEntry.from_dict(d)
        assert restored.role == original.role
        assert restored.content == original.content
        assert restored.tier == original.tier
        assert restored.timestamp == original.timestamp
        assert restored.metadata == original.metadata


class TestTieredMemoryCreation:
    """Tests for TieredMemory creation."""

    def test_default_creation(self):
        m = TieredMemory()
        assert len(m) == 0
        assert m.max_working == 50
        assert m.max_core == 20

    def test_custom_limits(self):
        m = TieredMemory(max_working=10, max_core=5)
        assert m.max_working == 10
        assert m.max_core == 5

    def test_empty_properties(self):
        m = TieredMemory()
        assert m.core == []
        assert m.working == []
        assert m.archival == []


class TestTieredMemoryAddCore:
    """Tests for adding to core tier."""

    def test_add_core(self):
        m = TieredMemory()
        m.add("system", "You are a helpful assistant", MemoryTier.CORE)
        assert len(m.core) == 1
        assert m.core[0]["role"] == "system"
        assert m.core[0]["tier"] == "core"

    def test_add_core_convenience(self):
        m = TieredMemory()
        m.add_core("system", "Role definition")
        assert len(m.core) == 1
        assert m.core[0]["content"] == "Role definition"

    def test_core_overflow_promotes_to_archival(self):
        m = TieredMemory(max_core=2)
        m.add_core("system", "entry1")
        m.add_core("system", "entry2")
        assert len(m.core) == 2
        assert len(m.archival) == 0
        # Adding a third should push entry1 to archival
        m.add_core("system", "entry3")
        assert len(m.core) == 2
        assert len(m.archival) == 1
        assert m.archival[0]["content"] == "entry1"

    def test_core_overflow_preserves_order(self):
        m = TieredMemory(max_core=2)
        m.add_core("system", "first")
        m.add_core("system", "second")
        m.add_core("system", "third")
        # core should have second and third
        assert m.core[0]["content"] == "second"
        assert m.core[1]["content"] == "third"
        # archival should have first
        assert m.archival[0]["content"] == "first"


class TestTieredMemoryAddWorking:
    """Tests for adding to working tier."""

    def test_add_working(self):
        m = TieredMemory()
        m.add("user", "hello")
        assert len(m.working) == 1
        assert m.working[0]["role"] == "user"

    def test_add_working_convenience(self):
        m = TieredMemory()
        m.add_working("user", "hi there")
        assert len(m.working) == 1
        assert m.working[0]["content"] == "hi there"

    def test_working_maxlen(self):
        m = TieredMemory(max_working=3)
        m.add_working("user", "msg1")
        m.add_working("assistant", "msg2")
        m.add_working("user", "msg3")
        m.add_working("assistant", "msg4")
        assert len(m.working) == 3
        # Oldest should be evicted
        assert m.working[0]["content"] == "msg2"

    def test_working_maxlen_preserves_latest(self):
        m = TieredMemory(max_working=2)
        m.add_working("user", "a")
        m.add_working("user", "b")
        m.add_working("user", "c")
        assert m.working[0]["content"] == "b"
        assert m.working[1]["content"] == "c"


class TestTieredMemoryAddArchival:
    """Tests for adding to archival tier."""

    def test_add_archival(self):
        m = TieredMemory()
        m.add("system", "old summary", MemoryTier.ARCHIVAL)
        assert len(m.archival) == 1
        assert m.archival[0]["role"] == "system"

    def test_add_archival_convenience(self):
        m = TieredMemory()
        m.add_archival("system", "compressed history")
        assert len(m.archival) == 1
        assert m.archival[0]["content"] == "compressed history"

    def test_archival_unlimited(self):
        m = TieredMemory()
        for i in range(100):
            m.add_archival("system", f"entry {i}")
        assert len(m.archival) == 100


class TestTieredMemorySearch:
    """Tests for archival search."""

    def test_search_basic(self):
        m = TieredMemory()
        m.add_archival("system", "The agent discussed machine learning algorithms")
        m.add_archival("system", "The user asked about weather patterns")
        m.add_archival("system", "Discussion about Python programming")
        
        results = m.search("machine learning")
        assert len(results) >= 1
        assert any("machine learning" in r["content"] for r in results)

    def test_search_no_results(self):
        m = TieredMemory()
        m.add_archival("system", "Some content here")
        results = m.search("quantum physics")
        assert len(results) == 0

    def test_search_top_k(self):
        m = TieredMemory()
        m.add_archival("system", "Python Python Python")
        m.add_archival("system", "Python Python")
        m.add_archival("system", "Python")
        m.add_archival("system", "No match here")
        m.add_archival("system", "Also Python related")
        
        results = m.search("Python", top_k=2)
        assert len(results) <= 2

    def test_search_empty_archival(self):
        m = TieredMemory()
        results = m.search("anything")
        assert len(results) == 0

    def test_search_keyword_matching(self):
        m = TieredMemory()
        m.add_archival("system", "The quick brown fox jumps over the lazy dog")
        m.add_archival("system", "A slow green turtle walks through the garden")
        
        results = m.search("brown fox")
        assert len(results) == 1
        assert "brown fox" in results[0]["content"]

    def test_search_ranking_by_overlap(self):
        m = TieredMemory()
        m.add_archival("system", "cat dog bird")
        m.add_archival("system", "cat dog")
        m.add_archival("system", "bird fish whale")
        
        results = m.search("cat dog", top_k=5)
        # The entry with more word overlap should rank higher
        assert len(results) >= 2
        assert results[0]["content"] == "cat dog bird"


class TestTieredMemorySummarize:
    """Tests for summarize_working()."""

    def test_summarize_empty(self):
        m = TieredMemory()
        result = m.summarize_working()
        assert result == ""

    def test_summarize_creates_summary(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_working("assistant", "hi there")
        
        summary = m.summarize_working()
        assert "user" in summary
        assert "hello" in summary

    def test_summarize_clears_working(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_working("assistant", "hi")
        
        m.summarize_working()
        assert len(m.working) == 0

    def test_summarize_adds_to_archival(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_working("assistant", "hi")
        
        m.summarize_working()
        assert len(m.archival) == 1
        assert m.archival[0]["role"] == "system"
        assert "Working memory summary" in m.archival[0]["content"]

    def test_summarize_preserves_metadata(self):
        m = TieredMemory()
        m.add_working("user", "msg1")
        m.add_working("assistant", "msg2")
        m.add_working("user", "msg3")
        
        m.summarize_working()
        assert m.archival[0]["metadata"]["summarized_entries"] == 3


class TestTieredMemoryToMessages:
    """Tests for to_messages()."""

    def test_empty_messages(self):
        m = TieredMemory()
        assert m.to_messages() == []

    def test_working_only_messages(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_working("assistant", "hi")
        messages = m.to_messages()
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"

    def test_core_always_in_messages(self):
        m = TieredMemory()
        m.add_core("system", "You are helpful")
        m.add_working("user", "hello")
        messages = m.to_messages()
        assert len(messages) == 2
        assert messages[0]["content"] == "You are helpful"

    def test_archival_not_in_messages(self):
        m = TieredMemory()
        m.add_core("system", "role")
        m.add_working("user", "hi")
        m.add_archival("system", "old summary")
        messages = m.to_messages()
        # Archival should NOT appear in messages
        assert len(messages) == 2
        assert all(m.get("tier") != "archival" for m in messages)

    def test_messages_order_core_then_working(self):
        m = TieredMemory()
        m.add_working("user", "question")
        m.add_core("system", "role")
        messages = m.to_messages()
        # Core comes first regardless of add order
        assert messages[0]["content"] == "role"


class TestTieredMemorySerialization:
    """Tests for to_dict / from_dict."""

    def test_to_dict_empty(self):
        m = TieredMemory()
        d = m.to_dict()
        assert d == {"core": [], "working": [], "archival": [], "max_working": 50, "max_core": 20}

    def test_to_dict_with_data(self):
        m = TieredMemory()
        m.add_core("system", "role")
        m.add_working("user", "hello")
        m.add_archival("system", "old summary")
        d = m.to_dict()
        assert len(d["core"]) == 1
        assert len(d["working"]) == 1
        assert len(d["archival"]) == 1

    def test_from_dict_roundtrip(self):
        m = TieredMemory()
        m.add_core("system", "You are an assistant")
        m.add_working("user", "hello")
        m.add_working("assistant", "hi there")
        m.add_archival("system", "previous context")

        d = m.to_dict()
        restored = TieredMemory.from_dict(d)

        assert len(restored.core) == 1
        assert len(restored.working) == 2
        assert len(restored.archival) == 1
        assert restored.max_working == 50
        assert restored.max_core == 20

    def test_from_dict_custom_limits(self):
        d = {"core": [], "working": [], "archival": [], "max_working": 10, "max_core": 5}
        m = TieredMemory.from_dict(d)
        assert m.max_working == 10
        assert m.max_core == 5

    def test_from_dict_preserves_content(self):
        m = TieredMemory()
        m.add_core("system", "role def")
        m.add_working("user", "query")
        
        restored = TieredMemory.from_dict(m.to_dict())
        assert restored.core[0]["content"] == "role def"
        assert restored.working[0]["content"] == "query"


class TestTieredMemoryClear:
    """Tests for clear operations."""

    def test_clear_working(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_working("assistant", "hi")
        m.clear_working()
        assert len(m.working) == 0
        # Core and archival unaffected
        assert len(m.core) == 0  # nothing added to core

    def test_clear_archival(self):
        m = TieredMemory()
        m.add_archival("system", "summary")
        m.clear_archival()
        assert len(m.archival) == 0

    def test_len_total(self):
        m = TieredMemory()
        m.add_core("system", "role")
        m.add_working("user", "hello")
        m.add_archival("system", "old")
        assert len(m) == 3

    def test_len_decreases_on_clear(self):
        m = TieredMemory()
        m.add_working("user", "hello")
        m.add_core("system", "role")
        assert len(m) == 2
        m.clear_working()
        assert len(m) == 1


class TestAgentMemoryBackwardCompat:
    """Tests for AgentMemory backward-compatible wrapper."""

    def test_agent_memory_add(self):
        m = AgentMemory()
        m.add("user", "Hello")
        assert len(m.entries) == 1

    def test_agent_memory_get_recent(self):
        m = AgentMemory()
        m.add("user", "Hello")
        m.add("assistant", "Hi there!")
        recent = m.get_recent(1)
        assert len(recent) == 1
        assert recent[0]["role"] == "assistant"

    def test_agent_memory_to_messages(self):
        m = AgentMemory()
        m.add("user", "Hello")
        m.add("assistant", "Hi there!")
        messages = m.to_messages()
        assert len(messages) >= 2
        assert messages[0]["role"] == "user"

    def test_agent_memory_clear(self):
        m = AgentMemory()
        m.add("user", "Hello")
        m.clear()
        assert len(m.entries) == 0

    def test_agent_memory_store_retrieve(self):
        m = AgentMemory()
        m.store("key1", "value1")
        assert m.retrieve("key1") == "value1"
        assert m.retrieve("nonexistent") is None

    def test_agent_memory_max_entries(self):
        m = AgentMemory(max_entries=3)
        m.store("a", 1)
        m.store("b", 2)
        m.store("c", 3)
        m.store("d", 4)  # Should evict "a"
        assert "a" not in m.keys()
        assert len(m.entries) == 3

    def test_agent_memory_forget(self):
        m = AgentMemory()
        m.store("key1", "val1")
        result = m.forget("key1")
        assert result is True
        assert m.retrieve("key1") is None
        result = m.forget("nonexistent")
        assert result is False

    def test_agent_memory_delegates_to_tiered(self):
        m = AgentMemory()
        assert hasattr(m, '_tiered')
        assert isinstance(m._tiered, TieredMemory)


class TestLargeArchivalSearch:
    """Tests for searching large archival memory."""

    def test_search_large_archival(self):
        m = TieredMemory()
        for i in range(200):
            m.add_archival("system", f"Entry number {i} about topic {i % 5}")
        
        results = m.search("topic 0", top_k=5)
        assert len(results) <= 5
        assert all("topic" in r["content"] for r in results)

    def test_search_returns_relevant(self):
        m = TieredMemory()
        m.add_archival("system", "The cat sat on the mat")
        m.add_archival("system", "The dog ran in the park")
        m.add_archival("system", "Birds fly in the sky")
        m.add_archival("system", "The cat chased the mouse")
        m.add_archival("system", "Fish swim in the ocean")
        
        results = m.search("cat", top_k=3)
        assert len(results) >= 1
        # At least one result should mention cat
        assert any("cat" in r["content"] for r in results)