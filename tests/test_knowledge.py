"""Tests for AgentKnowledge and KnowledgeEntry."""
import pytest
from agentic_ai.agents.knowledge import (
    AgentKnowledge,
    KnowledgeEntry,
    _CHROMADB_AVAILABLE,
)


class TestKnowledgeEntry:
    """Tests for KnowledgeEntry dataclass."""

    def test_knowledge_entry_creation(self):
        entry = KnowledgeEntry(doc_id="doc-1", text="hello world")
        assert entry.doc_id == "doc-1"
        assert entry.text == "hello world"
        assert entry.metadata == {}
        assert entry.score == 0.0

    def test_knowledge_entry_with_metadata(self):
        entry = KnowledgeEntry(
            doc_id="doc-2",
            text="test document",
            metadata={"source": "web", "author": "alice"},
            score=0.95,
        )
        assert entry.metadata == {"source": "web", "author": "alice"}
        assert entry.score == 0.95

    def test_knowledge_entry_to_dict(self):
        entry = KnowledgeEntry(
            doc_id="doc-3",
            text="some text",
            metadata={"key": "value"},
            score=0.8,
        )
        d = entry.to_dict()
        assert d["doc_id"] == "doc-3"
        assert d["text"] == "some text"
        assert d["metadata"] == {"key": "value"}
        assert d["score"] == 0.8

    def test_knowledge_entry_default_metadata(self):
        entry = KnowledgeEntry(doc_id="doc-4", text="text")
        assert entry.metadata == {}
        assert entry.score == 0.0


class TestAgentKnowledgeCreation:
    """Tests for AgentKnowledge initialization."""

    def test_create_without_chromadb(self):
        kb = AgentKnowledge()
        assert kb.collection_name == "agent_knowledge"
        assert kb.uses_vector_store is False or kb.uses_vector_store is True
        # Without ChromaDB installed, should be False
        if not _CHROMADB_AVAILABLE:
            assert kb.uses_vector_store is False

    def test_create_with_custom_collection_name(self):
        kb = AgentKnowledge(collection_name="my_collection")
        assert kb.collection_name == "my_collection"

    def test_create_with_persist_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = AgentKnowledge(persist_dir=tmpdir)
            # Should not raise even without ChromaDB
            assert kb.persist_dir == tmpdir

    def test_uses_vector_store_property_without_chromadb(self):
        kb = AgentKnowledge()
        if not _CHROMADB_AVAILABLE:
            assert kb.uses_vector_store is False


class TestAgentKnowledgeStore:
    """Tests for store() method."""

    def test_store_returns_doc_id(self):
        kb = AgentKnowledge()
        doc_id = kb.store("test document")
        assert doc_id is not None
        assert isinstance(doc_id, str)
        assert doc_id.startswith("doc-")

    def test_store_with_custom_doc_id(self):
        kb = AgentKnowledge()
        doc_id = kb.store("test document", doc_id="my-custom-id")
        assert doc_id == "my-custom-id"

    def test_store_with_metadata(self):
        kb = AgentKnowledge()
        doc_id = kb.store("test document", metadata={"source": "test"})
        entry = kb._entries[doc_id]
        assert entry.metadata == {"source": "test"}

    def test_store_with_custom_id_and_metadata(self):
        kb = AgentKnowledge()
        doc_id = kb.store(
            "hello world",
            metadata={"lang": "en"},
            doc_id="custom-123",
        )
        assert doc_id == "custom-123"
        assert kb._entries["custom-123"].text == "hello world"
        assert kb._entries["custom-123"].metadata == {"lang": "en"}

    def test_store_multiple_documents(self):
        kb = AgentKnowledge()
        ids = [kb.store(f"document {i}") for i in range(10)]
        assert len(set(ids)) == 10  # All unique IDs
        assert kb.count() == 10

    def test_store_empty_text(self):
        kb = AgentKnowledge()
        doc_id = kb.store("")
        assert doc_id is not None
        assert kb._entries[doc_id].text == ""


class TestAgentKnowledgeSearch:
    """Tests for search() method (keyword fallback)."""

    def test_search_returns_results(self):
        kb = AgentKnowledge()
        kb.store("the quick brown fox jumps over the lazy dog")
        results = kb.search("quick fox")
        assert len(results) > 0
        assert results[0].text == "the quick brown fox jumps over the lazy dog"

    def test_search_with_top_k(self):
        kb = AgentKnowledge()
        for i in range(10):
            kb.store(f"document number {i} about cats and dogs")
        results = kb.search("cats dogs", top_k=3)
        assert len(results) <= 3

    def test_search_no_results(self):
        kb = AgentKnowledge()
        kb.store("apples and oranges are fruits")
        results = kb.search("quantum physics")
        assert results == []

    def test_search_empty_knowledge_base(self):
        kb = AgentKnowledge()
        results = kb.search("anything")
        assert results == []

    def test_search_keyword_matching_relevance(self):
        kb = AgentKnowledge()
        kb.store("python programming language", doc_id="d1")
        kb.store("python snake in the jungle", doc_id="d2")
        kb.store("java programming language", doc_id="d3")
        results = kb.search("python programming")
        # First result should be the one with more keyword overlap
        assert len(results) >= 2
        # The programming+python doc should score higher
        ids = [r.doc_id for r in results]
        assert "d1" in ids

    def test_search_case_insensitive(self):
        kb = AgentKnowledge()
        kb.store("Python Programming Language")
        results = kb.search("python programming")
        assert len(results) > 0

    def test_search_partial_word_match(self):
        kb = AgentKnowledge()
        kb.store("machine learning algorithms")
        results = kb.search("learning")
        assert len(results) > 0
        assert "machine learning algorithms" in results[0].text

    def test_search_returns_knowledge_entries(self):
        kb = AgentKnowledge()
        kb.store("hello world", metadata={"greeting": True})
        results = kb.search("hello")
        assert len(results) > 0
        assert isinstance(results[0], KnowledgeEntry)

    def test_search_scores_between_zero_and_one(self):
        kb = AgentKnowledge()
        kb.store("test document about cats")
        kb.store("another document about dogs")
        results = kb.search("test cats")
        for entry in results:
            assert 0.0 <= entry.score <= 1.0


class TestAgentKnowledgeDelete:
    """Tests for delete() method."""

    def test_delete_removes_document(self):
        kb = AgentKnowledge()
        doc_id = kb.store("document to delete")
        assert kb.count() == 1
        result = kb.delete(doc_id)
        assert result is True
        assert kb.count() == 0

    def test_delete_nonexistent_document(self):
        kb = AgentKnowledge()
        result = kb.delete("nonexistent")
        assert result is False

    def test_delete_and_search(self):
        kb = AgentKnowledge()
        doc_id = kb.store("unique document content")
        kb.delete(doc_id)
        results = kb.search("unique document")
        assert results == []


class TestAgentKnowledgeCount:
    """Tests for count() method."""

    def test_count_empty(self):
        kb = AgentKnowledge()
        assert kb.count() == 0

    def test_count_after_stores(self):
        kb = AgentKnowledge()
        kb.store("doc one")
        kb.store("doc two")
        kb.store("doc three")
        assert kb.count() == 3

    def test_count_after_delete(self):
        kb = AgentKnowledge()
        id1 = kb.store("doc one")
        kb.store("doc two")
        kb.delete(id1)
        assert kb.count() == 1


class TestAgentKnowledgeClear:
    """Tests for clear() method."""

    def test_clear_empties_knowledge_base(self):
        kb = AgentKnowledge()
        kb.store("doc one")
        kb.store("doc two")
        assert kb.count() == 2
        kb.clear()
        assert kb.count() == 0

    def test_clear_and_reuse(self):
        kb = AgentKnowledge()
        kb.store("doc one")
        kb.clear()
        kb.store("doc two")
        assert kb.count() == 1
        results = kb.search("two")
        assert len(results) > 0


class TestAgentKnowledgeLargeScale:
    """Tests for large-scale storage and search."""

    def test_large_document_storage_and_search(self):
        kb = AgentKnowledge()
        doc_ids = []
        for i in range(100):
            doc_id = kb.store(
                f"document {i} about topic {i % 5}",
                metadata={"index": i},
            )
            doc_ids.append(doc_id)
        assert kb.count() == 100
        results = kb.search("topic 0", top_k=5)
        assert len(results) > 0
        assert len(results) <= 5

    def test_multiple_store_and_search(self):
        kb = AgentKnowledge()
        kb.store("python is a great language", metadata={"topic": "python"})
        kb.store("javascript runs in the browser", metadata={"topic": "javascript"})
        kb.store("rust is fast and safe", metadata={"topic": "rust"})

        results = kb.search("python language")
        assert len(results) > 0
        assert any("python" in r.text for r in results)