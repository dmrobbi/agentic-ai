"""Agent knowledge base with optional vector store integration.

Uses ChromaDB for semantic search when available, falls back to
keyword-based search when not installed.
"""
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Try to import chromadb, but don't fail if not installed
_CHROMADB_AVAILABLE = False
try:
    import chromadb
    _CHROMADB_AVAILABLE = True
except ImportError:
    logger.info("ChromaDB not installed. AgentKnowledge will use keyword search fallback.")


@dataclass
class KnowledgeEntry:
    """A single knowledge entry."""
    doc_id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "text": self.text,
            "metadata": self.metadata,
            "score": self.score,
        }


class AgentKnowledge:
    """Knowledge base with optional vector store for semantic search.

    When ChromaDB is installed, uses vector similarity search.
    When not installed, falls back to keyword-based search.
    """

    def __init__(self, collection_name: str = "agent_knowledge",
                 persist_dir: Optional[str] = None):
        self.collection_name = collection_name
        self.persist_dir = persist_dir
        self._entries: Dict[str, KnowledgeEntry] = {}
        self._chroma_client = None
        self._collection = None

        if _CHROMADB_AVAILABLE:
            try:
                if persist_dir:
                    self._chroma_client = chromadb.PersistentClient(path=persist_dir)
                else:
                    self._chroma_client = chromadb.Client()
                self._collection = self._chroma_client.get_or_create_collection(  # type: ignore[union-attr]
                    name=collection_name,
                    metadata={"hnsw:space": "cosine"}
                )
                logger.info(f"ChromaDB knowledge base initialized: {collection_name}")
            except Exception as e:
                logger.warning(f"ChromaDB initialization failed: {e}. Using fallback.")
                self._chroma_client = None
                self._collection = None

    @property
    def uses_vector_store(self) -> bool:
        """Whether vector store (ChromaDB) is available."""
        return self._collection is not None

    def store(self, text: str, metadata: Optional[Dict[str, Any]] = None,
              doc_id: Optional[str] = None) -> str:
        """Store a document in the knowledge base.

        Args:
            text: Document text
            metadata: Optional metadata dict
            doc_id: Optional document ID (auto-generated if not provided)

        Returns:
            Document ID
        """
        import uuid
        doc_id = doc_id or f"doc-{uuid.uuid4().hex[:8]}"
        metadata = metadata or {}

        # Store in local dict
        self._entries[doc_id] = KnowledgeEntry(
            doc_id=doc_id, text=text, metadata=metadata
        )

        # Store in ChromaDB if available
        if self._collection is not None:
            try:
                self._collection.add(  # type: ignore[union-attr]
                    documents=[text],
                    metadatas=[metadata],
                    ids=[doc_id],
                )
            except Exception as e:
                logger.warning(f"ChromaDB store failed: {e}")

        return doc_id

    def search(self, query: str, top_k: int = 5) -> List[KnowledgeEntry]:
        """Search for relevant documents.

        Uses vector similarity if ChromaDB available, keyword matching otherwise.
        """
        if self._collection is not None:
            return self._vector_search(query, top_k)
        else:
            return self._keyword_search(query, top_k)

    def _vector_search(self, query: str, top_k: int) -> List[KnowledgeEntry]:
        """Search using ChromaDB vector similarity."""
        try:
            results = self._collection.query(  # type: ignore[union-attr]
                query_texts=[query],
                n_results=min(top_k, len(self._entries) or 1),
            )
            entries = []
            if results and results.get("documents"):
                for i, doc in enumerate(results["documents"][0]):
                    doc_id = results["ids"][0][i] if results.get("ids") else f"result-{i}"
                    metadata = results["metadatas"][0][i] if results.get("metadatas") and results["metadatas"][0] else {}
                    distance = results["distances"][0][i] if results.get("distances") else 0.0
                    entries.append(KnowledgeEntry(
                        doc_id=doc_id,
                        text=doc,
                        metadata=metadata,
                        score=1.0 - distance,  # Convert distance to similarity
                    ))
            return entries
        except Exception as e:
            logger.warning(f"Vector search failed: {e}. Falling back to keyword search.")
            return self._keyword_search(query, top_k)

    def _keyword_search(self, query: str, top_k: int) -> List[KnowledgeEntry]:
        """Fallback keyword-based search."""
        query_words = set(re.findall(r'\w+', query.lower()))
        scored = []
        for entry in self._entries.values():
            doc_words = set(re.findall(r'\w+', entry.text.lower()))
            overlap = len(query_words & doc_words)
            if overlap > 0:
                scored.append(KnowledgeEntry(
                    doc_id=entry.doc_id,
                    text=entry.text,
                    metadata=entry.metadata,
                    score=overlap / max(len(query_words), 1),
                ))
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored[:top_k]

    def delete(self, doc_id: str) -> bool:
        """Delete a document from the knowledge base."""
        existed = doc_id in self._entries
        if doc_id in self._entries:
            del self._entries[doc_id]
        if self._collection is not None:
            try:
                self._collection.delete(ids=[doc_id])  # type: ignore[union-attr]
            except Exception as e:
                logger.warning(f"ChromaDB delete failed: {e}")
        return existed

    def count(self) -> int:
        """Return number of documents in the knowledge base."""
        if self._collection is not None:
            try:
                return int(self._collection.count())  # type: ignore[union-attr]
            except Exception:
                pass
        return len(self._entries)

    def clear(self) -> None:
        """Clear all documents from the knowledge base."""
        self._entries.clear()
        if self._collection is not None:
            try:
                self._chroma_client.delete_collection(self.collection_name)  # type: ignore[union-attr]
                self._collection = self._chroma_client.get_or_create_collection(  # type: ignore[union-attr]
                    name=self.collection_name,
                    metadata={"hnsw:space": "cosine"}
                )
            except Exception as e:
                logger.warning(f"ChromaDB clear failed: {e}")